package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/ctlplne/freightctl/internal/delivery"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func (s *Server) outboundApproval(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		identity, err := scope(r)
		if err != nil {
			failure(w, err)
			return
		}
		service := &delivery.Service{Custody: s.Service}
		var out any
		switch action {
		case "policy":
			out, err = service.DispatchPolicy(r.Context(), identity)
		case "policy-change":
			var x delivery.DispatchPolicyChange
			if err = workflowInput(w, r, &x); err == nil {
				out, err = service.ChangeDispatchPolicy(r.Context(), identity, r.Header.Get("Idempotency-Key"), x)
			}
		case "delivery":
			out, err = service.DispatchDelivery(r.Context(), identity, r.PathValue("delivery"))
		case "preview":
			var x delivery.DispatchSelection
			if err = workflowInput(w, r, &x); err == nil {
				out, err = service.PreviewDispatchReview(r.Context(), identity, x)
			}
		case "propose":
			var x delivery.DispatchProposal
			if err = workflowInput(w, r, &x); err == nil {
				out, err = service.ProposeDispatchReview(r.Context(), identity, r.Header.Get("Idempotency-Key"), x)
			}
		case "status":
			out, err = service.DispatchReview(r.Context(), identity, r.PathValue("review"))
		case "list":
			limit := 50
			if text := r.URL.Query().Get("limit"); text != "" {
				limit, err = strconv.Atoi(text)
			}
			if err == nil {
				out, err = service.DispatchReviews(r.Context(), identity, r.URL.Query().Get("after"), limit)
			} else {
				err = delivery.ErrInput
			}
		default:
			var x delivery.DispatchDecision
			if err = workflowInput(w, r, &x); err == nil {
				out, err = service.DecideDispatchReview(r.Context(), identity, r.PathValue("review"), action, r.Header.Get("Idempotency-Key"), x)
			}
		}
		if errors.Is(err, delivery.ErrInput) || errors.Is(err, workflow.ErrInput) {
			fail(w, 400, "invalid_outbound_dispatch_approval")
			return
		}
		if err != nil {
			failure(w, err)
			return
		}
		respond(w, 200, out)
	}
}
