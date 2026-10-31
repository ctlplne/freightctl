package api

import (
	"errors"
	"net/http"

	"github.com/ctlplne/freightctl/internal/workflow"
)

func (s *Server) scheduleArrival(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		identity, err := scope(r)
		if err != nil {
			failure(w, err)
			return
		}
		service := &workflow.Service{Custody: s.Service}
		id, key := r.PathValue("occurrence"), r.Header.Get("Idempotency-Key")
		var out any
		switch action {
		case "status":
			out, err = service.ScheduleArrivalStatus(r.Context(), identity, id)
		case "probe":
			var x workflow.CollectionWorkRequest
			if err = workflowInput(w, r, &x); err == nil {
				out, err = service.ProbeScheduleArrival(r.Context(), identity, id, key, x)
			}
		case "admit", "cancel":
			var x workflow.Decision
			if err = workflowInput(w, r, &x); err == nil {
				if action == "admit" {
					out, err = service.AdmitScheduleArrival(r.Context(), identity, id, key, x)
				} else {
					out, err = service.CancelScheduleArrival(r.Context(), identity, id, key, x)
				}
			}
		default:
			err = workflow.ErrInput
		}
		if errors.Is(err, workflow.ErrInput) {
			fail(w, 400, "invalid_schedule_arrival")
			return
		}
		if err != nil {
			failure(w, err)
			return
		}
		respond(w, 200, out)
	}
}
