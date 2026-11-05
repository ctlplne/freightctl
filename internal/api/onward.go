package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

type onwardRunAction struct {
	Start      workflow.OnwardStart `json:"start"`
	ReceiptKey string               `json:"receipt_key"`
	RunID      string               `json:"run_id"`
}

// Both ordinary HTTPS and MCP must prove the same original typed receipt before
// inspecting or working a run. The receipt lookup never stages or wakes work.
func (s *Server) onwardRun(ctx context.Context, scope store.Scope, action onwardRunAction, work bool, key string) (map[string]any, error) {
	if !store.ValidID(action.RunID) {
		return nil, workflow.ErrInput
	}
	service := &workflow.Service{Custody: s.Service}
	accepted, err := service.OnwardReceipt(ctx, scope, workflow.OnwardLookup{Start: action.Start, ReceiptKey: action.ReceiptKey})
	if err != nil {
		return nil, err
	}
	var bound store.WorkflowRun
	if json.Unmarshal(accepted.Resource, &bound) != nil || bound.ID != action.RunID {
		return nil, store.ErrRevision
	}
	if !work {
		view, err := service.Status(ctx, scope, action.RunID)
		if err != nil {
			return nil, err
		}
		return mcpOnwardStatus(view)
	}
	result, err := service.Work(ctx, scope, action.RunID, key)
	if err != nil {
		return nil, err
	}
	summary, err := mcpOnwardStatus(result.Status)
	if err != nil {
		return nil, err
	}
	summary["replayed"] = result.Replayed
	summary["selected_delivery_id"] = result.Dispatch.DeliveryID
	return summary, nil
}

func (s *Server) onward(w http.ResponseWriter, r *http.Request) {
	identity, err := scope(r)
	if err != nil {
		failure(w, err)
		return
	}
	service := &workflow.Service{Custody: s.Service}
	var result any
	if r.Pattern == "POST /v1/tenants/{tenant}/partners/{partner}/onward/previews" {
		var request workflow.OnwardRequest
		if err = workflowInput(w, r, &request); err == nil {
			result, err = service.PrepareOnward(r.Context(), identity, request)
		}
	} else if r.Pattern == "POST /v1/tenants/{tenant}/partners/{partner}/onward/receipts" {
		var request workflow.OnwardLookup
		if err = workflowInput(w, r, &request); err == nil {
			result, err = service.OnwardReceipt(r.Context(), identity, request)
		}
	} else if r.Pattern == "POST /v1/tenants/{tenant}/partners/{partner}/onward/status" || r.Pattern == "POST /v1/tenants/{tenant}/partners/{partner}/onward/work" {
		var request onwardRunAction
		if err = workflowInput(w, r, &request); err == nil {
			result, err = s.onwardRun(r.Context(), identity, request, r.Pattern == "POST /v1/tenants/{tenant}/partners/{partner}/onward/work", r.Header.Get("Idempotency-Key"))
		}
	} else {
		var request workflow.OnwardStart
		if err = workflowInput(w, r, &request); err == nil {
			result, err = service.StartOnward(r.Context(), identity, r.Header.Get("Idempotency-Key"), request)
		}
	}
	if errors.Is(err, workflow.ErrInput) {
		fail(w, 400, "invalid_onward_contract")
		return
	}
	if err != nil {
		failure(w, err)
		return
	}
	respond(w, 200, result)
}
