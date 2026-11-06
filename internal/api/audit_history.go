package api

import (
	"net/http"

	"github.com/ctlplne/freightctl/internal/store"
)

func (s *Server) searchAuditHistory(w http.ResponseWriter, r *http.Request) {
	identity, err := scope(r)
	if err != nil {
		failure(w, err)
		return
	}
	wire, err := exchangeBody(w, r, 8<<10)
	if err != nil {
		fail(w, 400, "invalid_audit_history")
		return
	}
	input, err := store.DecodeAuditHistory(wire)
	if err != nil {
		fail(w, 400, "invalid_audit_history")
		return
	}
	select {
	case s.auditSlots <- struct{}{}:
		defer func() { <-s.auditSlots }()
	default:
		fail(w, 503, "audit_capacity_busy")
		return
	}
	result, err := s.Service.DB.SearchAuditHistory(r.Context(), identity, *input)
	if err != nil {
		failure(w, err)
		return
	}
	respond(w, 200, result)
}
