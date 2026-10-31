package api

import (
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/ctlplne/freightctl/internal/workflow"
)

func workflowInput(w http.ResponseWriter, r *http.Request, target any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	data, err := io.ReadAll(r.Body)
	if err != nil {
		return workflow.ErrInput
	}
	return workflow.Decode(data, target)
}
func workflowVersion(r *http.Request) (int, error) {
	v, err := strconv.Atoi(r.PathValue("version"))
	if err != nil || v < 1 {
		return 0, workflow.ErrInput
	}
	return v, nil
}
func (s *Server) workflow(w http.ResponseWriter, r *http.Request) {
	identity, err := scope(r)
	if err != nil {
		failure(w, err)
		return
	}
	service := &workflow.Service{Custody: s.Service}
	var result any
	switch r.Pattern {
	case "POST /v1/tenants/{tenant}/partners/{partner}/workflows/validate":
		var request workflow.PreviewRequest
		if err = workflowInput(w, r, &request); err == nil {
			result, err = service.Validate(r.Context(), identity, request)
		}
	case "POST /v1/tenants/{tenant}/partners/{partner}/workflows/drafts":
		var request workflow.DraftRequest
		if err = workflowInput(w, r, &request); err == nil {
			result, err = service.Draft(r.Context(), identity, r.Header.Get("Idempotency-Key"), request)
		}
	case "POST /v1/tenants/{tenant}/partners/{partner}/workflow-runs":
		var request workflow.RunRequest
		if err = workflowInput(w, r, &request); err == nil {
			result, err = service.Run(r.Context(), identity, r.Header.Get("Idempotency-Key"), request)
		}
	case "GET /v1/tenants/{tenant}/partners/{partner}/workflow-runs/{run}":
		result, err = service.Status(r.Context(), identity, r.PathValue("run"))
	case "POST /v1/tenants/{tenant}/partners/{partner}/workflow-runs/{run}/cancel":
		var decision workflow.Decision
		if err = workflowInput(w, r, &decision); err == nil {
			result, err = service.Cancel(r.Context(), identity, r.PathValue("run"), r.Header.Get("Idempotency-Key"), decision)
		}
	case "POST /v1/tenants/{tenant}/partners/{partner}/workflow-runs/{run}/refresh", "POST /v1/tenants/{tenant}/partners/{partner}/workflow-runs/{run}/work":
		r.Body = http.MaxBytesReader(w, r.Body, 1)
		var b []byte
		b, err = io.ReadAll(r.Body)
		if err == nil && len(b) == 0 {
			if r.Pattern == "POST /v1/tenants/{tenant}/partners/{partner}/workflow-runs/{run}/refresh" {
				result, err = service.RefreshRun(r.Context(), identity, r.PathValue("run"), r.Header.Get("Idempotency-Key"))
			} else {
				result, err = service.Work(r.Context(), identity, r.PathValue("run"), r.Header.Get("Idempotency-Key"))
			}
		} else {
			err = workflow.ErrInput
		}
	default:
		var version int
		if version, err = workflowVersion(r); err != nil {
			break
		}
		switch r.Pattern {
		case "GET /v1/tenants/{tenant}/partners/{partner}/connections/{connection}/{version}":
			result, err = service.Connection(r.Context(), identity, r.PathValue("connection"), version)
		case "GET /v1/tenants/{tenant}/partners/{partner}/workflows/{workflow}/{version}":
			result, err = service.Configuration(r.Context(), identity, r.PathValue("workflow"), version)
		case "GET /v1/tenants/{tenant}/partners/{partner}/workflows/{workflow}/{version}/diff":
			var against int
			against, err = strconv.Atoi(r.URL.Query().Get("against"))
			if err == nil && against > 0 {
				result, err = service.Diff(r.Context(), identity, r.PathValue("workflow"), against, version)
			} else {
				err = workflow.ErrInput
			}
		case "POST /v1/tenants/{tenant}/partners/{partner}/connections/{connection}/{version}/revoke":
			var decision workflow.Decision
			if err = workflowInput(w, r, &decision); err == nil {
				result, err = service.RevokeConnection(r.Context(), identity, r.PathValue("connection"), version, r.Header.Get("Idempotency-Key"), decision)
			}
		default:
			var decision workflow.Decision
			if err = workflowInput(w, r, &decision); err == nil {
				action := "approve"
				if r.Pattern == "POST /v1/tenants/{tenant}/partners/{partner}/workflows/{workflow}/{version}/revoke" {
					action = "revoke"
				}
				result, err = service.Decide(r.Context(), identity, r.PathValue("workflow"), version, r.Header.Get("Idempotency-Key"), action, decision)
			}
		}
	}
	if errors.Is(err, workflow.ErrInput) {
		fail(w, 400, "invalid_typed_workflow")
		return
	}
	if err != nil {
		failure(w, err)
		return
	}
	respond(w, 200, result)
}
