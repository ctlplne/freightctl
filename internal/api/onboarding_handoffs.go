package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/ctlplne/freightctl/internal/workflow"
)

func (s *Server) onboardingHandoffAction(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.SetPathValue("handoff_action", action)
		s.onboardingHandoff(w, r)
	}
}
func (s *Server) onboardingHandoff(w http.ResponseWriter, r *http.Request) {
	identity, err := scope(r)
	if err != nil {
		failure(w, err)
		return
	}
	service := &workflow.Service{Custody: s.Service}
	var result any
	switch action := r.PathValue("handoff_action"); action {
	case "list":
		limit := 50
		if v := r.URL.Query().Get("limit"); v != "" {
			limit, err = strconv.Atoi(v)
		}
		if err == nil {
			result, err = service.ListOnboardingHandoffs(r.Context(), identity, r.PathValue("plan"), r.URL.Query().Get("after"), limit)
		} else {
			err = workflow.ErrInput
		}
	case "status":
		result, err = service.OnboardingHandoffStatus(r.Context(), identity, r.PathValue("handoff"))
	case "preview":
		var input workflow.OnboardingHandoffSelection
		if err = workflowInput(w, r, &input); err == nil {
			result, err = service.PreviewOnboardingHandoff(r.Context(), identity, input)
		}
	case "propose":
		var input workflow.OnboardingHandoffProposal
		if err = workflowInput(w, r, &input); err == nil {
			result, err = service.ProposeOnboardingHandoff(r.Context(), identity, r.Header.Get("Idempotency-Key"), input)
		}
	default:
		var input workflow.Decision
		if err = workflowInput(w, r, &input); err == nil {
			result, err = service.DecideOnboardingHandoff(r.Context(), identity, r.PathValue("handoff"), action, r.Header.Get("Idempotency-Key"), input)
		}
	}
	if errors.Is(err, workflow.ErrInput) {
		fail(w, 400, "invalid_onboarding_handoff")
		return
	}
	if err != nil {
		failure(w, err)
		return
	}
	respond(w, 200, result)
}
