package api

import (
	"errors"
	"github.com/ctlplne/freightctl/internal/workflow"
	"net/http"
	"strconv"
)

func (s *Server) schedule(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		identity, e := scope(r)
		if e != nil {
			failure(w, e)
			return
		}
		service := &workflow.Service{Custody: s.Service, Processor: s.Checks}
		var out any
		version := 1
		if text := r.PathValue("version"); text != "" {
			version, e = strconv.Atoi(text)
			if e != nil || version < 1 {
				fail(w, 400, "invalid_workflow_schedule")
				return
			}
		}
		limit := 20
		if text := r.URL.Query().Get("limit"); text != "" {
			limit, e = strconv.Atoi(text)
			if e != nil {
				fail(w, 400, "invalid_workflow_schedule")
				return
			}
		}
		switch action {
		case "preview":
			var x workflow.ScheduleSelection
			if e = workflowInput(w, r, &x); e == nil {
				out, e = service.PreviewSchedule(r.Context(), identity, x)
			}
		case "draft":
			var x workflow.ScheduleDraftRequest
			if e = workflowInput(w, r, &x); e == nil {
				out, e = service.DraftSchedule(r.Context(), identity, r.Header.Get("Idempotency-Key"), x)
			}
		case "workflows":
			out, e = service.SchedulableWorkflows(r.Context(), identity, r.URL.Query().Get("after"), limit)
		case "list":
			out, e = service.Schedules(r.Context(), identity, r.URL.Query().Get("after"), limit)
		case "status":
			out, e = service.ScheduleStatus(r.Context(), identity, r.PathValue("schedule"), version)
		case "history":
			out, e = service.ScheduleHistory(r.Context(), identity, r.PathValue("schedule"), r.URL.Query().Get("after"), limit)
		case "occurrence":
			out, e = service.ScheduleOccurrence(r.Context(), identity, r.PathValue("occurrence"))
		case "tick":
			var x workflow.ScheduleTickRequest
			if e = workflowInput(w, r, &x); e == nil {
				out, e = service.TickSchedule(r.Context(), identity, r.PathValue("schedule"), version, r.Header.Get("Idempotency-Key"), x)
			}
		default:
			var x workflow.Decision
			if e = workflowInput(w, r, &x); e == nil {
				out, e = service.ControlSchedule(r.Context(), identity, r.PathValue("schedule"), version, action, r.Header.Get("Idempotency-Key"), x)
			}
		}
		if errors.Is(e, workflow.ErrInput) {
			fail(w, 400, "invalid_workflow_schedule")
			return
		}
		if e != nil {
			failure(w, e)
			return
		}
		respond(w, 200, out)
	}
}
