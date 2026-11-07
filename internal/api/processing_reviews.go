package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/ctlplne/freightctl/internal/workflow"
)

func (s *Server) processingReviews(w http.ResponseWriter, r *http.Request) {
	identity, err := scope(r)
	if err != nil {
		failure(w, err)
		return
	}
	service := &workflow.Service{Custody: s.Service, Processor: s.Checks}
	var result any
	switch r.Pattern {
	case "POST /v1/tenants/{tenant}/partners/{partner}/processing-reviews":
		var request workflow.ProcessingReviewRequest
		if err = workflowInput(w, r, &request); err == nil {
			result, err = service.RequestProcessingReview(r.Context(), identity, r.Header.Get("Idempotency-Key"), request)
		}
	case "GET /v1/tenants/{tenant}/partners/{partner}/processing-reviews", "GET /v1/tenants/{tenant}/partners/{partner}/processing-workflows":
		limit := 25
		if r.URL.Query().Get("limit") != "" {
			limit, err = strconv.Atoi(r.URL.Query().Get("limit"))
		}
		if err != nil || limit < 1 || limit > 100 {
			err = workflow.ErrInput
		}
		if err == nil {
			if r.Pattern == "GET /v1/tenants/{tenant}/partners/{partner}/processing-workflows" {
				result, err = service.ProcessingWorkflows(r.Context(), identity, r.URL.Query().Get("after"), limit)
			} else {
				result, err = service.ProcessingReviews(r.Context(), identity, r.URL.Query().Get("after"), limit)
			}
		}
	case "GET /v1/tenants/{tenant}/partners/{partner}/processing-reviews/{review}":
		result, err = service.ProcessingReview(r.Context(), identity, r.PathValue("review"))
	default:
		var decision workflow.Decision
		if err = workflowInput(w, r, &decision); err == nil {
			action := ""
			switch r.Pattern {
			case "POST /v1/tenants/{tenant}/partners/{partner}/processing-reviews/{review}/approve":
				action = "approve"
			case "POST /v1/tenants/{tenant}/partners/{partner}/processing-reviews/{review}/reject":
				action = "reject"
			case "POST /v1/tenants/{tenant}/partners/{partner}/processing-reviews/{review}/withdraw":
				action = "withdraw"
			case "POST /v1/tenants/{tenant}/partners/{partner}/processing-reviews/{review}/adopt":
				action = "adopt"
			}
			result, err = service.DecideProcessingReview(r.Context(), identity, r.PathValue("review"), r.Header.Get("Idempotency-Key"), action, decision)
		}
	}
	if errors.Is(err, workflow.ErrInput) {
		code := "invalid_processing_review"
		if r.Pattern == "GET /v1/tenants/{tenant}/partners/{partner}/processing-workflows" {
			code = "invalid_processing_catalog"
		}
		fail(w, 400, code)
		return
	}
	if err != nil {
		failure(w, err)
		return
	}
	respond(w, 200, result)
}
