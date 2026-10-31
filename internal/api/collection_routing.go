package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/ctlplne/freightctl/internal/workflow"
)

func (s *Server) collectionRouting(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		identity, err := scope(r)
		if err != nil {
			failure(w, err)
			return
		}
		service := &workflow.Service{Custody: s.Service}
		job := r.PathValue("collection")
		var out any
		switch action {
		case "preview", "input-preview":
			var x workflow.CollectionRoutingSelection
			if err = workflowInput(w, r, &x); err == nil {
				if action == "input-preview" {
					out, err = service.PreviewCollectionRoutingInput(r.Context(), identity, job, r.PathValue("input"), x)
				} else {
					out, err = service.PreviewCollectionRouting(r.Context(), identity, job, x)
				}
			}
		case "propose":
			var x workflow.CollectionRoutingProposal
			if err = workflowInput(w, r, &x); err == nil {
				out, err = service.ProposeCollectionRouting(r.Context(), identity, job, r.Header.Get("Idempotency-Key"), x)
			}
		case "status":
			out, err = service.CollectionRoutingStatus(r.Context(), identity, job, r.PathValue("routing"))
		case "current":
			out, err = service.CurrentCollectionRouting(r.Context(), identity, job)
		case "details":
			out, err = service.CollectionRoutingDetails(r.Context(), identity, job, r.PathValue("routing"))
		case "receipt":
			out, err = service.CollectionRoutingReceipt(r.Context(), identity, job, r.PathValue("receipt"))
		case "history":
			after, limit := 0, 20
			if raw := r.URL.Query().Get("after"); raw != "" {
				after, err = strconv.Atoi(raw)
			}
			if raw := r.URL.Query().Get("limit"); raw != "" && err == nil {
				limit, err = strconv.Atoi(raw)
			}
			if err != nil || after < 0 || after > 2147483647 || limit < 1 || limit > 100 {
				err = workflow.ErrInput
			} else {
				out, err = service.CollectionRoutingHistory(r.Context(), identity, job, after, limit)
			}
		case "approve", "revoke", "withdraw":
			var x workflow.Decision
			if err = workflowInput(w, r, &x); err == nil {
				out, err = service.DecideCollectionRouting(r.Context(), identity, job, r.PathValue("routing"), r.Header.Get("Idempotency-Key"), action, x)
			}
		default:
			err = workflow.ErrInput
		}
		if errors.Is(err, workflow.ErrInput) {
			fail(w, 400, "invalid_collection_routing")
			return
		}
		if err != nil {
			failure(w, err)
			return
		}
		respond(w, 200, out)
	}
}
