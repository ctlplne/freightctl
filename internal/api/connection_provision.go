package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/ctlplne/freightctl/internal/workflow"
)

func (s *Server) connectionProvisionChoices(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		identity, err := scope(r)
		if err != nil {
			failure(w, err)
			return
		}
		limit := 20
		if raw := r.URL.Query().Get("limit"); raw != "" {
			limit, err = strconv.Atoi(raw)
			if err != nil {
				fail(w, 400, "invalid_connection_provision")
				return
			}
		}
		service := &workflow.Service{Custody: s.Service}
		page, err := service.ConnectionProvisionChoices(r.Context(), identity, kind, r.URL.Query().Get("after"), limit)
		if errors.Is(err, workflow.ErrInput) {
			fail(w, 400, "invalid_connection_provision")
			return
		}
		if err != nil {
			failure(w, err)
			return
		}
		respond(w, 200, page)
	}
}

func (s *Server) connectionProvisionCommand(w http.ResponseWriter, r *http.Request) {
	identity, err := scope(r)
	if err != nil {
		failure(w, err)
		return
	}
	var command workflow.ConnectionProvisionCommand
	if err = boundedControlInput(w, r, 4<<10, &command); err != nil {
		fail(w, 400, "invalid_connection_provision")
		return
	}
	service := &workflow.Service{Custody: s.Service}
	result, err := service.ProvisionConnection(r.Context(), identity, r.Header.Get("Idempotency-Key"), command)
	if errors.Is(err, workflow.ErrInput) {
		fail(w, 400, "invalid_connection_provision")
		return
	}
	if err != nil {
		failure(w, err)
		return
	}
	respond(w, 200, result)
}
