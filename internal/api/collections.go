package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/ctlplne/freightctl/internal/workflow"
)

func (s *Server) collection(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		identity, e := scope(r)
		if e != nil {
			failure(w, e)
			return
		}
		service := &workflow.Service{Custody: s.Service}
		var out any
		limit := 20
		if text := r.URL.Query().Get("limit"); text != "" {
			limit, e = strconv.Atoi(text)
			if e != nil {
				fail(w, 400, "invalid_workflow_collection")
				return
			}
		}
		switch action {
		case "preview":
			var x workflow.CollectionSelection
			if e = workflowInput(w, r, &x); e == nil {
				out, e = service.PreviewCollection(r.Context(), identity, x)
			}
		case "start":
			var x workflow.CollectionStartRequest
			if e = workflowInput(w, r, &x); e == nil {
				out, e = service.StartCollection(r.Context(), identity, r.Header.Get("Idempotency-Key"), x)
			}
		case "status":
			out, e = service.CollectionStatus(r.Context(), identity, r.PathValue("collection"))
		case "list":
			out, e = service.Collections(r.Context(), identity, r.URL.Query().Get("after"), limit)
		case "work":
			var x workflow.CollectionWorkRequest
			if e = workflowInput(w, r, &x); e == nil {
				out, e = service.WorkCollection(r.Context(), identity, r.PathValue("collection"), r.Header.Get("Idempotency-Key"), x)
			}
		case "connections":
			out, e = service.CollectionConnections(r.Context(), identity, r.URL.Query().Get("after"), limit)
		case "workflows":
			out, e = service.CollectionWorkflows(r.Context(), identity, r.URL.Query().Get("after"), limit)
		default:
			var x workflow.Decision
			if e = workflowInput(w, r, &x); e == nil {
				if action == "cancel" {
					out, e = service.CancelCollection(r.Context(), identity, r.PathValue("collection"), r.Header.Get("Idempotency-Key"), x)
				} else {
					out, e = service.RefreshCollection(r.Context(), identity, r.PathValue("collection"), r.Header.Get("Idempotency-Key"), x)
				}
			}
		}
		if errors.Is(e, workflow.ErrInput) {
			fail(w, 400, "invalid_workflow_collection")
			return
		}
		if e != nil {
			failure(w, e)
			return
		}
		respond(w, 200, out)
	}
}
