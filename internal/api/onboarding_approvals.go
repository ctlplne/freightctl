package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/ctlplne/freightctl/internal/workflow"
)

func (s *Server) onboardingApproval(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scope, err := scope(r)
		if err != nil {
			failure(w, err)
			return
		}
		service := &workflow.Service{Custody: s.Service}
		var out any
		switch action {
		case "policy":
			out, err = service.OnboardingApprovalPolicy(r.Context(), scope)
		case "policy-change":
			var x workflow.OnboardingApprovalPolicyChange
			if err = workflowInput(w, r, &x); err == nil {
				out, err = service.ChangeOnboardingApprovalPolicy(r.Context(), scope, r.Header.Get("Idempotency-Key"), x)
			}
		case "preview":
			var x workflow.OnboardingApprovalSelection
			if err = workflowInput(w, r, &x); err == nil {
				out, err = service.PreviewOnboardingApproval(r.Context(), scope, x)
			}
		case "propose":
			var x workflow.OnboardingApprovalProposal
			if err = workflowInput(w, r, &x); err == nil {
				out, err = service.ProposeOnboardingApproval(r.Context(), scope, r.Header.Get("Idempotency-Key"), x)
			}
		case "status":
			out, err = service.OnboardingApprovalStatus(r.Context(), scope, r.PathValue("review"))
		case "list":
			limit := 50
			if r.URL.Query().Get("limit") != "" {
				limit, err = strconv.Atoi(r.URL.Query().Get("limit"))
			}
			if err == nil {
				out, err = service.ListOnboardingApprovals(r.Context(), scope, r.URL.Query().Get("after"), limit)
			} else {
				err = workflow.ErrInput
			}
		default:
			var x workflow.Decision
			if err = workflowInput(w, r, &x); err == nil {
				out, err = service.DecideOnboardingApproval(r.Context(), scope, r.PathValue("review"), action, r.Header.Get("Idempotency-Key"), x)
			}
		}
		if errors.Is(err, workflow.ErrInput) {
			fail(w, 400, "invalid_onboarding_approval")
			return
		}
		if err != nil {
			failure(w, err)
			return
		}
		respond(w, 200, out)
	}
}
