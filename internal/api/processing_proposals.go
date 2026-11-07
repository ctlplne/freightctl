package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/ctlplne/freightctl/internal/workflow"
)

func (s *Server) processingProposals(w http.ResponseWriter, r *http.Request) {
	identity, err := scope(r)
	if err != nil {
		failure(w, err)
		return
	}
	service := &workflow.Service{Custody: s.Service, Processor: s.Checks}
	var value any
	switch r.Pattern {
	case "POST /v1/tenants/{tenant}/partners/{partner}/processing-proposals":
		var request workflow.ProcessingProposalRequest
		if err = workflowInput(w, r, &request); err == nil {
			value, err = service.ProposeProcessingWorkflow(r.Context(), identity, r.Header.Get("Idempotency-Key"), request)
		}
	case "GET /v1/tenants/{tenant}/partners/{partner}/processing-proposals":
		limit := 25
		if text := r.URL.Query().Get("limit"); text != "" {
			limit, err = strconv.Atoi(text)
		}
		if err != nil || limit < 1 || limit > 100 {
			err = workflow.ErrInput
		}
		if err == nil {
			value, err = service.ProcessingProposals(r.Context(), identity, r.URL.Query().Get("after"), limit)
		}
	case "GET /v1/tenants/{tenant}/partners/{partner}/processing-proposals/{proposal}":
		value, err = service.ProcessingProposal(r.Context(), identity, r.PathValue("proposal"))
	default:
		var decision workflow.Decision
		if err = workflowInput(w, r, &decision); err == nil {
			action := ""
			switch r.Pattern {
			case "POST /v1/tenants/{tenant}/partners/{partner}/processing-proposals/{proposal}/adopt":
				action = "adopt"
			case "POST /v1/tenants/{tenant}/partners/{partner}/processing-proposals/{proposal}/reject":
				action = "reject"
			case "POST /v1/tenants/{tenant}/partners/{partner}/processing-proposals/{proposal}/withdraw":
				action = "withdraw"
			}
			value, err = service.DecideProcessingProposal(r.Context(), identity, r.PathValue("proposal"), r.Header.Get("Idempotency-Key"), action, decision)
		}
	}
	if errors.Is(err, workflow.ErrInput) {
		fail(w, 400, "invalid_processing_proposal")
		return
	}
	if err != nil {
		failure(w, err)
		return
	}
	respond(w, 200, value)
}
