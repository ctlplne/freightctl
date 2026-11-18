package api

import (
	"net/http"
	"net/url"

	"github.com/ctlplne/freightctl/internal/store"
)

func (s *Server) recordExchangeIntegrityReport(w http.ResponseWriter, r *http.Request) {
	identity, err := scope(r)
	if err != nil {
		failure(w, err)
		return
	}
	raw, err := exchangeBody(w, r, 4096)
	if err != nil {
		failure(w, err)
		return
	}
	command, err := store.DecodeExchangeIntegrityCommand(raw)
	if err != nil || command.ExchangeID != r.PathValue("exchange") {
		failure(w, store.ErrExchangeInput)
		return
	}
	limits, _, err := s.Service.ExchangeLimits()
	if err != nil {
		failure(w, err)
		return
	}
	result, replayed, err := s.Service.DB.RecordExchangeIntegrityReport(r.Context(), identity, r.Header.Get("Idempotency-Key"), command, limits)
	if err != nil {
		failure(w, err)
		return
	}
	status := http.StatusCreated
	if replayed {
		status = http.StatusOK
	}
	respond(w, status, result)
}

func (s *Server) inspectExchangeIntegrityReport(w http.ResponseWriter, r *http.Request) {
	identity, err := scope(r)
	if err != nil {
		failure(w, err)
		return
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(query) != 1 || len(query["direction"]) != 1 {
		failure(w, store.ErrExchangeInput)
		return
	}
	limits, _, err := s.Service.ExchangeLimits()
	if err != nil {
		failure(w, err)
		return
	}
	result, err := s.Service.DB.InspectExchangeIntegrityReport(r.Context(), identity, store.ExchangeIntegritySelection{ID: r.PathValue("exchange"), Direction: query.Get("direction")}, limits)
	if err != nil {
		failure(w, err)
		return
	}
	respond(w, http.StatusOK, result)
}
