package api

import (
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/ctlplne/freightctl/internal/store"
)

func exchangeBody(w http.ResponseWriter, r *http.Request, maximum int64) ([]byte, error) {
	r.Body = http.MaxBytesReader(w, r.Body, maximum)
	data, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, store.ErrExchangeInput
	}
	return data, nil
}

func (s *Server) exchangeEndpointCommand(w http.ResponseWriter, r *http.Request) {
	identity, err := scope(r)
	if err != nil {
		failure(w, err)
		return
	}
	limits, _, err := s.Service.ExchangeLimits()
	if err != nil {
		failure(w, err)
		return
	}
	data, err := exchangeBody(w, r, 24<<10)
	if err != nil {
		failure(w, err)
		return
	}
	command, err := store.DecodeExchangeEndpointCommand(data, limits)
	if err != nil {
		failure(w, err)
		return
	}
	result, err := s.Service.DB.RegisterExchangeEndpoint(r.Context(), identity, r.Header.Get("Idempotency-Key"), *command, limits, s.Service.Exchanges.MaxEndpoints)
	if err != nil {
		failure(w, err)
		return
	}
	respond(w, 200, result)
}

func (s *Server) exchangeEndpoints(w http.ResponseWriter, r *http.Request) {
	identity, err := scope(r)
	if err != nil {
		failure(w, err)
		return
	}
	if _, _, err = s.Service.ExchangeLimits(); err != nil {
		failure(w, err)
		return
	}
	limit := 20
	if raw := r.URL.Query().Get("limit"); raw != "" {
		limit, err = strconv.Atoi(raw)
	}
	if err != nil {
		failure(w, store.ErrExchangeInput)
		return
	}
	result, err := s.Service.DB.ExchangeEndpoints(r.Context(), identity, r.URL.Query().Get("after"), limit)
	if err != nil {
		failure(w, err)
		return
	}
	respond(w, 200, result)
}

func (s *Server) exchangeEndpoint(w http.ResponseWriter, r *http.Request) {
	identity, err := scope(r)
	if err != nil {
		failure(w, err)
		return
	}
	if _, _, err = s.Service.ExchangeLimits(); err != nil {
		failure(w, err)
		return
	}
	result, err := s.Service.DB.ExchangeEndpoint(r.Context(), identity, r.PathValue("endpoint"))
	if err != nil {
		failure(w, err)
		return
	}
	respond(w, 200, result)
}

func (s *Server) offerExchange(w http.ResponseWriter, r *http.Request) {
	identity, err := scope(r)
	if err != nil {
		failure(w, err)
		return
	}
	limits, _, err := s.Service.ExchangeLimits()
	if err != nil {
		failure(w, err)
		return
	}
	data, err := exchangeBody(w, r, 16<<10)
	if err != nil {
		failure(w, err)
		return
	}
	request, _, _, err := store.DecodeExchangeRequest(data, limits)
	if err != nil {
		failure(w, err)
		return
	}
	result, err := s.Service.OfferExchange(r.Context(), identity, r.Header.Get("Idempotency-Key"), *request)
	if err != nil {
		failure(w, err)
		return
	}
	code := 201
	if result.Replayed {
		code = 200
	}
	respond(w, code, result)
}

func (s *Server) incomingExchanges(w http.ResponseWriter, r *http.Request) {
	identity, err := scope(r)
	if err != nil {
		failure(w, err)
		return
	}
	limit := 20
	if value := r.URL.Query().Get("limit"); value != "" {
		limit, err = strconv.Atoi(value)
	}
	if err != nil {
		failure(w, store.ErrExchangeInput)
		return
	}
	limits, _, err := s.Service.ExchangeLimits()
	if err != nil {
		failure(w, err)
		return
	}
	page, err := s.Service.DB.IncomingExchanges(r.Context(), identity, r.PathValue("endpoint"), r.URL.Query().Get("after"), limit, limits)
	if err != nil {
		failure(w, err)
		return
	}
	respond(w, 200, page)
}

func (s *Server) inspectExchange(w http.ResponseWriter, r *http.Request) {
	identity, err := scope(r)
	if err != nil {
		failure(w, err)
		return
	}
	result, err := s.Service.InspectExchange(r.Context(), identity, r.PathValue("exchange"))
	if err != nil {
		failure(w, err)
		return
	}
	respond(w, 200, result)
}

func (s *Server) downloadExchange(w http.ResponseWriter, r *http.Request) {
	identity, err := scope(r)
	if err != nil {
		requestFailure(w, r, err)
		return
	}
	file, reader, err := s.Service.OpenExchangeReader(r.Context(), identity, r.PathValue("exchange"))
	if err != nil {
		requestFailure(w, r, err)
		return
	}
	defer reader.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="artifact"`)
	w.Header().Set("X-Content-SHA256", file.SHA256)
	w.Header().Set("X-File-Revision-ID", file.ID)
	w.Header().Set("X-Artifact-Exchange-ID", r.PathValue("exchange"))
	// No mutable filename or file path enters serving or content disposition.
	// Range reads use the same bounded, live-authorized revision reader.
	http.ServeContent(w, r, file.ID, time.Time{}, io.NewSectionReader(reader, 0, file.Size))
}
