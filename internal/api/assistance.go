package api

import (
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/ctlplne/freightctl/internal/assistance"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func (s *Server) assistance(w http.ResponseWriter, r *http.Request) {
	scope, err := scope(r)
	if err != nil {
		failure(w, err)
		return
	}
	key := r.Header.Get("Idempotency-Key")
	var result any
	switch r.Pattern {
	case "GET /v1/tenants/{tenant}/partners/{partner}/ai/profiles/{profile}/{version}":
		version, parseErr := strconv.Atoi(r.PathValue("version"))
		if parseErr != nil || version < 1 {
			err = assistance.ErrInput
			break
		}
		result, err = s.Assistance.Profile(r.Context(), scope, r.PathValue("profile"), version)
	case "POST /v1/tenants/{tenant}/partners/{partner}/ai/jobs":
		var request assistance.PrepareRequest
		if err = workflowInput(w, r, &request); err == nil {
			result, err = s.Assistance.Prepare(r.Context(), scope, key, request)
		}
	case "GET /v1/tenants/{tenant}/partners/{partner}/ai/jobs/{job}":
		result, err = s.Assistance.Get(r.Context(), scope, r.PathValue("job"))
	case "GET /v1/tenants/{tenant}/partners/{partner}/ai/jobs/{job}/evidence/{event}":
		result, err = s.Assistance.Evidence(r.Context(), scope, r.PathValue("job"), r.PathValue("event"))
	case "POST /v1/tenants/{tenant}/partners/{partner}/ai/jobs/{job}/generate":
		r.Body = http.MaxBytesReader(w, r.Body, 1)
		data, readErr := io.ReadAll(r.Body)
		if readErr != nil || len(data) != 0 {
			err = assistance.ErrInput
			break
		}
		result, err = s.Assistance.Generate(r.Context(), scope, r.PathValue("job"), key)
	default:
		var decision assistance.Decision
		if err = workflowInput(w, r, &decision); err == nil {
			if r.Pattern == "POST /v1/tenants/{tenant}/partners/{partner}/ai/jobs/{job}/approve" {
				result, err = s.Assistance.Approve(r.Context(), scope, r.PathValue("job"), key, decision)
			} else {
				result, err = s.Assistance.Adopt(r.Context(), scope, r.PathValue("job"), key, decision)
			}
		}
	}
	switch {
	case errors.Is(err, assistance.ErrInput), errors.Is(err, workflow.ErrInput):
		fail(w, 400, "invalid_assistance_request")
	case errors.Is(err, assistance.ErrDisabled):
		fail(w, 503, "inference_disabled")
	case errors.Is(err, assistance.ErrBackend):
		fail(w, 502, "model_endpoint_failed")
	case err != nil:
		failure(w, err)
	default:
		respond(w, 200, result)
	}
}
