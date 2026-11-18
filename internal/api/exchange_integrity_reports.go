package api

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/ctlplne/freightctl/internal/store"
)

const exchangeReadCookie = "__Secure-freightctl-integrity-read"

func (s *Server) downloadExchangeForIntegrityReport(w http.ResponseWriter, r *http.Request) {
	proof, ok := r.Context().Value(browserContextKey{}).(browserProof)
	if !ok {
		requestFailure(w, r, store.ErrUnauthorized)
		return
	}
	exchange, read := r.PathValue("exchange"), r.PathValue("read")
	if !store.ValidID(exchange) || !store.ValidID(read) {
		requestFailure(w, r, store.ErrNotFound)
		return
	}
	// This marker links the browser's native download to its later JSON
	// request. Current session and database authority still govern both.
	marker := &http.Cookie{
		Name: exchangeReadCookie, Value: proof.Session.ID + "." + read + ".",
		Path:    "/v1/tenants/" + proof.Scope.Tenant + "/partners/" + proof.Scope.Partner + "/exchanges/" + exchange + "/integrity-read/" + read + "/selection",
		Expires: proof.Session.ExpiresAt, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	}
	s.serveExchangeDownload(w, r, proof.Scope, marker)
}

func (s *Server) selectExchangeIntegrityRead(w http.ResponseWriter, r *http.Request) {
	proof, ok := r.Context().Value(browserContextKey{}).(browserProof)
	if !ok {
		failure(w, store.ErrUnauthorized)
		return
	}
	exchange, read := r.PathValue("exchange"), r.PathValue("read")
	cookies := r.CookiesNamed(exchangeReadCookie)
	if !store.ValidID(exchange) || !store.ValidID(read) || len(cookies) != 1 {
		failure(w, store.ErrNotFound)
		return
	}
	event, bound := strings.CutPrefix(cookies[0].Value, proof.Session.ID+"."+read+".")
	if !bound || !store.ValidID(event) {
		failure(w, store.ErrNotFound)
		return
	}
	limits, _, err := s.Service.ExchangeLimits()
	if err != nil {
		failure(w, err)
		return
	}
	result, err := s.Service.DB.SelectExchangeIntegrityRead(r.Context(), proof.Scope, exchange, event, limits)
	if err != nil {
		failure(w, err)
		return
	}
	respond(w, http.StatusOK, result)
}

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
