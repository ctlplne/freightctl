package api

import (
	"net/http"
	"strconv"

	"github.com/ctlplne/freightctl/internal/store"
)

func (s *Server) onboarding(w http.ResponseWriter, r *http.Request) {
	scope, err := scope(r)
	if err != nil {
		failure(w, err)
		return
	}
	var result any
	if r.Method == http.MethodPost {
		var request store.OnboardingCommand
		if workflowInput(w, r, &request) != nil {
			err = store.ErrOnboardingInput
		} else {
			result, err = s.Service.DB.SaveOnboarding(r.Context(), scope, r.Header.Get("Idempotency-Key"), request)
		}
	} else if id := r.PathValue("plan"); id != "" {
		version := 0
		if value := r.URL.Query().Get("version"); value != "" {
			version, err = strconv.Atoi(value)
		}
		if err != nil {
			err = store.ErrOnboardingInput
		} else {
			result, err = s.Service.DB.Onboarding(r.Context(), scope, id, version)
		}
	} else {
		limit := 50
		if value := r.URL.Query().Get("limit"); value != "" {
			limit, err = strconv.Atoi(value)
		}
		if err != nil {
			err = store.ErrOnboardingInput
		} else {
			result, err = s.Service.DB.OnboardingPlans(r.Context(), scope, r.URL.Query().Get("after"), limit)
		}
	}
	if err != nil {
		failure(w, err)
		return
	}
	respond(w, http.StatusOK, result)
}
