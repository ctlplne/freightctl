package api

import (
	"errors"
	"net/http"

	"github.com/ctlplne/freightctl/internal/workflow"
)

func (s *Server) onboardingExchangeReview(w http.ResponseWriter, r *http.Request) {
	identity, err := scope(r)
	if err != nil {
		failure(w, err)
		return
	}
	var input workflow.OnboardingExchangeRequest
	if err = workflowInput(w, r, &input); err != nil {
		fail(w, 400, "invalid_onboarding_exchange_review")
		return
	}
	result, err := (&workflow.Service{Custody: s.Service}).ReviewOnboardingExchange(r.Context(), identity, input)
	if errors.Is(err, workflow.ErrInput) {
		fail(w, 400, "invalid_onboarding_exchange_review")
		return
	}
	if err != nil {
		failure(w, err)
		return
	}
	respond(w, http.StatusOK, result)
}
