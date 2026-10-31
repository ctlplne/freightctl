package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/ctlplne/freightctl/internal/workflow"
)

func (s *Server) onboardingTests(w http.ResponseWriter, r *http.Request) {
	identity, err := scope(r)
	if err != nil {
		failure(w, err)
		return
	}
	service := &workflow.Service{Custody: s.Service}
	var result any
	if plan := r.PathValue("plan"); plan != "" {
		limit := 50
		if value := r.URL.Query().Get("limit"); value != "" {
			limit, err = strconv.Atoi(value)
		}
		if err == nil {
			result, err = service.ListOnboardingTests(r.Context(), identity, plan, r.URL.Query().Get("after"), limit)
		} else {
			err = workflow.ErrInput
		}
	} else if id := r.PathValue("test"); id != "" {
		if r.PathValue("action") == "review" {
			result, err = service.ReviewOnboardingTest(r.Context(), identity, id)
		} else {
			result, err = service.OnboardingTestStatus(r.Context(), identity, id)
		}
	} else if r.PathValue("action") == "preview" {
		var input workflow.OnboardingTestPreviewRequest
		if err = workflowInput(w, r, &input); err == nil {
			result, err = service.PreviewOnboardingTest(r.Context(), identity, input)
		}
	} else {
		var input workflow.OnboardingTestStartRequest
		if err = workflowInput(w, r, &input); err == nil {
			result, err = service.StartOnboardingTest(r.Context(), identity, r.Header.Get("Idempotency-Key"), input)
		}
	}
	if errors.Is(err, workflow.ErrInput) {
		fail(w, 400, "invalid_onboarding_test")
		return
	}
	if err != nil {
		failure(w, err)
		return
	}
	respond(w, 200, result)
}

func (s *Server) onboardingTestPreview(w http.ResponseWriter, r *http.Request) {
	r.SetPathValue("action", "preview")
	s.onboardingTests(w, r)
}
func (s *Server) onboardingTestReview(w http.ResponseWriter, r *http.Request) {
	r.SetPathValue("action", "review")
	s.onboardingTests(w, r)
}
