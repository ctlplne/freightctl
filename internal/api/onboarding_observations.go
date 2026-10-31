package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/ctlplne/freightctl/internal/workflow"
)

func (s *Server) onboardingObservationAction(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.SetPathValue("observation_action", action)
		s.onboardingObservation(w, r)
	}
}
func (s *Server) onboardingObservation(w http.ResponseWriter, r *http.Request) {
	identity, err := scope(r)
	if err != nil {
		failure(w, err)
		return
	}
	service := &workflow.Service{Custody: s.Service}
	var result any
	switch action := r.PathValue("observation_action"); action {
	case "list":
		limit := 50
		if v := r.URL.Query().Get("limit"); v != "" {
			limit, err = strconv.Atoi(v)
		}
		if err == nil {
			result, err = service.ListOnboardingObservations(r.Context(), identity, r.PathValue("plan"), r.URL.Query().Get("after"), limit)
		} else {
			err = workflow.ErrInput
		}
	case "status":
		result, err = service.OnboardingObservationStatus(r.Context(), identity, r.PathValue("observation"))
	case "preview":
		var input workflow.OnboardingObservationSelection
		if err = workflowInput(w, r, &input); err == nil {
			result, err = service.PreviewOnboardingObservation(r.Context(), identity, input)
		}
	case "work":
		var input workflow.OnboardingProbeWorkRequest
		if err = workflowInput(w, r, &input); err == nil {
			result, err = service.WorkOnboardingObservation(r.Context(), identity, r.PathValue("observation"), r.Header.Get("Idempotency-Key"), input)
		}
	case "propose":
		var input workflow.OnboardingObservationProposal
		if err = workflowInput(w, r, &input); err == nil {
			result, err = service.ProposeOnboardingObservation(r.Context(), identity, r.Header.Get("Idempotency-Key"), input)
		}
	default:
		var input workflow.Decision
		if err = workflowInput(w, r, &input); err == nil {
			result, err = service.DecideOnboardingObservation(r.Context(), identity, r.PathValue("observation"), action, r.Header.Get("Idempotency-Key"), input)
		}
	}
	if errors.Is(err, workflow.ErrInput) {
		fail(w, 400, "invalid_onboarding_observation")
		return
	}
	if err != nil {
		failure(w, err)
		return
	}
	respond(w, 200, result)
}
