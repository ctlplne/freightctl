package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/ctlplne/freightctl/internal/checks"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func (s *Server) outputPolicies(w http.ResponseWriter, r *http.Request) {
	identity, err := scope(r)
	if err != nil {
		failure(w, err)
		return
	}
	var result any
	switch r.Pattern {
	case "POST /v1/tenants/{tenant}/partners/{partner}/processing-output-policies":
		var request checks.OutputPolicyRequest
		if err = workflowInput(w, r, &request); err == nil {
			result, err = s.Checks.RegisterOutputPolicy(r.Context(), identity, r.Header.Get("Idempotency-Key"), request)
		}
	case "GET /v1/tenants/{tenant}/partners/{partner}/processing-output-policies":
		limit := 25
		if r.URL.Query().Get("limit") != "" {
			limit, err = strconv.Atoi(r.URL.Query().Get("limit"))
		}
		if err != nil || limit < 1 || limit > 100 {
			err = checks.ErrInput
		} else {
			result, err = s.Checks.OutputPolicies(r.Context(), identity, r.URL.Query().Get("after"), limit)
		}
	default:
		var version int
		version, err = workflowVersion(r)
		if err == nil {
			if r.Pattern == "GET /v1/tenants/{tenant}/partners/{partner}/processing-output-policies/{policy}/{version}" {
				result, err = s.Checks.OutputPolicy(r.Context(), identity, r.PathValue("policy"), version)
			} else {
				var decision checks.PolicyDecision
				if err = workflowInput(w, r, &decision); err == nil {
					result, err = s.Checks.RevokeOutputPolicy(r.Context(), identity, r.PathValue("policy"), version, r.Header.Get("Idempotency-Key"), decision)
				}
			}
		}
	}
	if errors.Is(err, checks.ErrInput) || errors.Is(err, workflow.ErrInput) {
		fail(w, 400, "invalid_processing_output_policy")
		return
	}
	if err != nil {
		failure(w, err)
		return
	}
	respond(w, 200, result)
}
