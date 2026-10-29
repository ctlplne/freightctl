package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func (s *Server) onboardingProbe(w http.ResponseWriter, r *http.Request) {
	identity, err := scope(r)
	if err != nil {
		failure(w, err)
		return
	}
	service := &workflow.Service{Custody: s.Service}
	var result any
	if plan := r.PathValue("plan"); plan != "" {
		limit := 50
		if raw := r.URL.Query().Get("limit"); raw != "" {
			limit, err = strconv.Atoi(raw)
		}
		if err == nil {
			result, err = service.ListOnboardingProbes(r.Context(), identity, plan, r.URL.Query().Get("after"), limit)
		} else {
			err = workflow.ErrInput
		}
	} else if r.Method == http.MethodGet {
		result, err = service.OnboardingProbeStatus(r.Context(), identity, r.PathValue("probe"))
	} else if id := r.PathValue("probe"); id != "" {
		var request workflow.OnboardingProbeWorkRequest
		if err = workflowInput(w, r, &request); err == nil {
			result, err = service.WorkOnboardingProbe(r.Context(), identity, id, r.Header.Get("Idempotency-Key"), request)
		}
	} else {
		var request store.OnboardingProbeRequest
		if err = workflowInput(w, r, &request); err == nil {
			result, err = service.StartOnboardingProbe(r.Context(), identity, r.Header.Get("Idempotency-Key"), request)
		}
	}
	if errors.Is(err, workflow.ErrInput) {
		fail(w, 400, "invalid_onboarding_probe")
		return
	}
	if err != nil {
		failure(w, err)
		return
	}
	respond(w, http.StatusOK, result)
}
