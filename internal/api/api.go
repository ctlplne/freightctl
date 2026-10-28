// Package api exposes the same custody service to ordinary HTTPS clients.
package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
)

type Server struct {
	Service *custody.Service
	slots   chan struct{}
}

func New(service *custody.Service) http.Handler {
	s := &Server{Service: service, slots: make(chan struct{}, 8)}
	m := http.NewServeMux()
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"status":"process-running","transfer_readiness":"not-qualified"}`)
	})
	m.HandleFunc("POST /v1/tenants/{tenant}/partners/{partner}/files", s.upload)
	m.HandleFunc("GET /v1/tenants/{tenant}/partners/{partner}/files/{file}", s.download)
	m.HandleFunc("GET /v1/tenants/{tenant}/partners/{partner}/events", s.events)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		if r.TLS == nil {
			fail(w, http.StatusBadRequest, "tls_required")
			return
		}
		select {
		case s.slots <- struct{}{}:
			defer func() { <-s.slots }()
		default:
			fail(w, http.StatusServiceUnavailable, "capacity_busy")
			return
		}
		m.ServeHTTP(w, r)
	})
}
func scope(r *http.Request) (store.Scope, error) {
	h := r.Header.Get("Authorization")
	if len(h) != 71 || !strings.HasPrefix(h, "Bearer ") {
		return store.Scope{}, store.ErrUnauthorized
	}
	for _, c := range h[7:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return store.Scope{}, store.ErrUnauthorized
		}
	}
	b := []byte(h[7:])
	defer secure.Clear(b)
	return store.Scope{Tenant: r.PathValue("tenant"), Partner: r.PathValue("partner"), TokenHash: secure.Digest(b)}, nil
}
func respond(w http.ResponseWriter, code int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(value)
}
func fail(w http.ResponseWriter, code int, message string) {
	respond(w, code, map[string]string{"error": message})
}
func failure(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrUnauthorized):
		fail(w, 401, "unauthorized")
	case errors.Is(err, store.ErrNotFound):
		fail(w, 404, "not_found")
	case errors.Is(err, store.ErrConflict):
		fail(w, 409, "idempotency_conflict")
	case errors.Is(err, custody.ErrInput):
		fail(w, 400, "invalid_upload_contract")
	case errors.Is(err, custody.ErrIntegrity):
		fail(w, 422, "integrity_mismatch")
	case errors.Is(err, custody.ErrCapacity):
		fail(w, 507, "storage_quota_reached")
	default:
		fail(w, 503, "operation_unavailable")
	}
}
func (s *Server) upload(w http.ResponseWriter, r *http.Request) {
	identity, err := scope(r)
	if err != nil {
		failure(w, err)
		return
	}
	n, err := strconv.ParseInt(r.Header.Get("X-File-Size"), 10, 64)
	if err != nil {
		failure(w, custody.ErrInput)
		return
	}
	if r.ContentLength >= 0 && r.ContentLength != n {
		failure(w, custody.ErrInput)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, s.Service.MaxFile+1)
	f, replay, err := s.Service.Accept(r.Context(), identity, r.Header.Get("Idempotency-Key"), n, r.Header.Get("X-Content-SHA256"), r.Body)
	if err != nil {
		failure(w, err)
		return
	}
	status := http.StatusCreated
	if replay {
		status = http.StatusOK
	}
	respond(w, status, map[string]any{"file": f, "replayed": replay, "acceptance": "durable-local-integrity-only"})
}
func (s *Server) download(w http.ResponseWriter, r *http.Request) {
	identity, err := scope(r)
	if err != nil {
		failure(w, err)
		return
	}
	f, data, err := s.Service.Download(r.Context(), identity, r.PathValue("file"))
	if err != nil {
		failure(w, err)
		return
	}
	defer data.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+f.ID+`"`)
	w.Header().Set("X-Content-SHA256", f.SHA256)
	// ServeContent implements ranges using the same verified descriptor.
	http.ServeContent(w, r, f.ID, time.Time{}, data)
}
func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	identity, err := scope(r)
	if err != nil {
		failure(w, err)
		return
	}
	events, err := s.Service.DB.Events(r.Context(), identity)
	if err != nil {
		failure(w, err)
		return
	}
	respond(w, 200, map[string]any{"events": events, "limit": 100})
}
