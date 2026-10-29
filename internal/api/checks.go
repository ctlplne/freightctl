package api

import (
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/ctlplne/freightctl/internal/checks"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func (s *Server) checks(w http.ResponseWriter, r *http.Request) {
	scope, err := scope(r)
	if err != nil {
		failure(w, err)
		return
	}
	key := r.Header.Get("Idempotency-Key")
	var result any
	switch r.Pattern {
	case "GET /v1/tenants/{tenant}/partners/{partner}/checks":
		limit := 50
		if value := r.URL.Query().Get("limit"); value != "" {
			limit, err = strconv.Atoi(value)
			if err != nil {
				err = checks.ErrInput
				break
			}
		}
		result, err = s.Checks.List(r.Context(), scope, r.URL.Query().Get("after"), limit)
	case "GET /v1/tenants/{tenant}/partners/{partner}/intake-policy":
		result, err = s.Checks.Policy(r.Context(), scope)
	case "POST /v1/tenants/{tenant}/partners/{partner}/intake-policy":
		var request checks.PolicyRequest
		if err = workflowInput(w, r, &request); err == nil {
			result, err = s.Checks.Register(r.Context(), scope, key, request)
		}
	case "POST /v1/tenants/{tenant}/partners/{partner}/intake-policy/revoke":
		var request checks.PolicyDecision
		if err = workflowInput(w, r, &request); err == nil {
			result, err = s.Checks.Revoke(r.Context(), scope, key, request)
		}
	case "GET /v1/tenants/{tenant}/partners/{partner}/checks/{file}":
		result, err = s.Checks.Get(r.Context(), scope, r.PathValue("file"))
	case "POST /v1/tenants/{tenant}/partners/{partner}/checks/{file}/run":
		r.Body = http.MaxBytesReader(w, r.Body, 1)
		data, readErr := io.ReadAll(r.Body)
		if readErr != nil || len(data) != 0 {
			err = checks.ErrInput
		} else {
			result, err = s.Checks.Run(r.Context(), scope, r.PathValue("file"), key)
		}
	default:
		var request checks.ReleaseDecision
		if err = workflowInput(w, r, &request); err == nil {
			result, err = s.Checks.Release(r.Context(), scope, r.PathValue("file"), key, request)
		}
	}
	if errors.Is(err, checks.ErrInput) || errors.Is(err, workflow.ErrInput) {
		fail(w, 400, "invalid_check_request")
	} else if err != nil {
		failure(w, err)
	} else {
		respond(w, 200, result)
	}
}
