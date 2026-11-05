package api

import (
	"errors"
	"net/http"

	"github.com/ctlplne/freightctl/internal/workflow"
)

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
