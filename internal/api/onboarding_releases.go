package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/ctlplne/freightctl/internal/workflow"
)

func (s *Server) onboardingReleaseAction(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.SetPathValue("release_action", action)
		s.onboardingRelease(w, r)
	}
}
func (s *Server) onboardingRelease(w http.ResponseWriter, r *http.Request) {
	identity, err := scope(r)
	if err != nil {
		failure(w, err)
		return
	}
	service := &workflow.Service{Custody: s.Service}
	var result any
	switch action := r.PathValue("release_action"); action {
	case "list":
		limit := 50
		if value := r.URL.Query().Get("limit"); value != "" {
			limit, err = strconv.Atoi(value)
		}
		if err == nil {
			result, err = service.ListOnboardingReleases(r.Context(), identity, r.PathValue("plan"), r.URL.Query().Get("after"), limit)
		} else {
			err = workflow.ErrInput
		}
	case "production-status":
		result, err = service.OnboardingProductionStatus(r.Context(), identity, r.PathValue("production"))
	case "production-list":
		limit := 50
		if value := r.URL.Query().Get("limit"); value != "" {
			limit, err = strconv.Atoi(value)
		}
		if err == nil {
			result, err = service.ListOnboardingProduction(r.Context(), identity, r.PathValue("release"), r.URL.Query().Get("after"), limit)
		} else {
			err = workflow.ErrInput
		}
	case "status":
		result, err = service.OnboardingReleaseStatus(r.Context(), identity, r.PathValue("release"))
	case "preview":
		var input workflow.OnboardingReleaseSelection
		if err = workflowInput(w, r, &input); err == nil {
			result, err = service.PreviewOnboardingRelease(r.Context(), identity, input)
		}
	case "propose":
		var input workflow.OnboardingReleaseProposal
		if err = workflowInput(w, r, &input); err == nil {
			result, err = service.ProposeOnboardingRelease(r.Context(), identity, r.Header.Get("Idempotency-Key"), input)
		}
	case "production-preview":
		var input workflow.OnboardingProductionSelection
		if err = workflowInput(w, r, &input); err == nil {
			result, err = service.PreviewOnboardingProduction(r.Context(), identity, r.PathValue("release"), input)
		}
	case "production-start":
		var input workflow.OnboardingProductionStart
		if err = workflowInput(w, r, &input); err == nil {
			result, err = service.StartOnboardingProduction(r.Context(), identity, r.Header.Get("Idempotency-Key"), input)
		}
	default:
		var input workflow.Decision
		if err = workflowInput(w, r, &input); err == nil {
			result, err = service.DecideOnboardingRelease(r.Context(), identity, r.PathValue("release"), action, r.Header.Get("Idempotency-Key"), input)
		}
	}
	if errors.Is(err, workflow.ErrInput) {
		fail(w, 400, "invalid_onboarding_release")
		return
	}
	if err != nil {
		failure(w, err)
		return
	}
	respond(w, 200, result)
}
