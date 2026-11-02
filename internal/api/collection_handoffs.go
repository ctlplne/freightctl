package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/ctlplne/freightctl/internal/workflow"
)

func (s *Server) collectionHandoff(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		identity, err := scope(r)
		if err != nil {
			failure(w, err)
			return
		}
		service := &workflow.Service{Custody: s.Service}
		job, id := r.PathValue("collection"), r.PathValue("handoff")
		var out any
		switch action {
		case "receipt":
			out, err = service.CollectionHandoffReceipt(r.Context(), identity, job, r.PathValue("receipt"))
		case "history":
			limit := 20
			if raw := r.URL.Query().Get("limit"); raw != "" {
				limit, err = strconv.Atoi(raw)
				if err != nil {
					err = workflow.ErrInput
				}
			}
			if err == nil {
				out, err = service.CollectionHandoffHistory(r.Context(), identity, job, r.URL.Query().Get("after"), limit)
			}
		case "preview":
			var x workflow.CollectionHandoffSelection
			if err = workflowInput(w, r, &x); err == nil {
				out, err = service.PreviewCollectionHandoff(r.Context(), identity, job, x)
			}
		case "propose":
			var x workflow.CollectionHandoffProposal
			if err = workflowInput(w, r, &x); err == nil {
				out, err = service.ProposeCollectionHandoff(r.Context(), identity, job, r.Header.Get("Idempotency-Key"), x)
			}
		case "status":
			out, err = service.CollectionHandoffStatus(r.Context(), identity, job, id)
		default:
			var x workflow.Decision
			if err = workflowInput(w, r, &x); err == nil {
				out, err = service.DecideCollectionHandoff(r.Context(), identity, job, id, r.Header.Get("Idempotency-Key"), action, x)
			}
		}
		if errors.Is(err, workflow.ErrInput) {
			fail(w, http.StatusBadRequest, "invalid_collection_handoff")
			return
		}
		if err != nil {
			failure(w, err)
			return
		}
		respond(w, 200, out)
	}
}
