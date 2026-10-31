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

	"github.com/ctlplne/freightctl/internal/assistance"
	"github.com/ctlplne/freightctl/internal/audit"
	"github.com/ctlplne/freightctl/internal/browser"
	"github.com/ctlplne/freightctl/internal/checks"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/vpath"
)

type Server struct {
	Service                *custody.Service
	slots                  chan struct{}
	Audit                  *audit.Service
	auditSlots             chan struct{}
	Assistance             *assistance.Service
	Checks                 *checks.Service
	BrowserSessionLifetime time.Duration
}

func New(service *custody.Service, audits *audit.Service, enableAssistance ...bool) http.Handler {
	enabled := len(enableAssistance) == 1 && enableAssistance[0]
	return NewWithBrowserLifetime(service, audits, enabled, 10*time.Minute)
}

// The lifetime is trusted deployment configuration, never a login body field.
func NewWithBrowserLifetime(service *custody.Service, audits *audit.Service, enabled bool, lifetime time.Duration) http.Handler {
	if lifetime < time.Second || lifetime > 10*time.Minute || lifetime%time.Second != 0 {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fail(w, 503, "browser_session_configuration_invalid") })
	}
	s := &Server{Service: service, Audit: audits, slots: make(chan struct{}, 8), auditSlots: make(chan struct{}, 1), BrowserSessionLifetime: lifetime}
	s.Assistance = &assistance.Service{DB: service.DB, Enabled: enabled}
	s.Checks = &checks.Service{Custody: service}
	m := http.NewServeMux()
	m.HandleFunc("GET /{$}", browser.Serve)
	m.HandleFunc("GET /assets/", browser.Serve)
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"status":"process-running","transfer_readiness":"not-qualified"}`)
	})
	m.HandleFunc("POST /v1/tenants/{tenant}/partners/{partner}/files", s.upload)
	m.HandleFunc("GET /v1/tenants/{tenant}/partners/{partner}/files/{file}", s.download)
	m.HandleFunc("GET /v1/tenants/{tenant}/partners/{partner}/events", s.events)
	m.HandleFunc("GET /v1/tenants/{tenant}/partners/{partner}/onboarding-plans", s.onboarding)
	m.HandleFunc("POST /v1/tenants/{tenant}/partners/{partner}/onboarding-plans", s.onboarding)
	m.HandleFunc("GET /v1/tenants/{tenant}/partners/{partner}/onboarding-plans/{plan}", s.onboarding)
	m.HandleFunc("GET /v1/tenants/{tenant}/partners/{partner}/onboarding-plans/{plan}/probes", s.onboardingProbe)
	m.HandleFunc("POST /v1/tenants/{tenant}/partners/{partner}/onboarding-probes", s.onboardingProbe)
	m.HandleFunc("POST /v1/tenants/{tenant}/partners/{partner}/onboarding-exchange-review", s.onboardingExchangeReview)
	m.HandleFunc("POST /v1/tenants/{tenant}/partners/{partner}/onboarding-tests/preview", s.onboardingTestPreview)
	m.HandleFunc("POST /v1/tenants/{tenant}/partners/{partner}/onboarding-tests", s.onboardingTests)
	m.HandleFunc("GET /v1/tenants/{tenant}/partners/{partner}/onboarding-tests/{test}", s.onboardingTests)
	m.HandleFunc("GET /v1/tenants/{tenant}/partners/{partner}/onboarding-tests/{test}/review", s.onboardingTestReview)
	m.HandleFunc("GET /v1/tenants/{tenant}/partners/{partner}/onboarding-plans/{plan}/tests", s.onboardingTests)
	m.HandleFunc("GET /v1/tenants/{tenant}/partners/{partner}/onboarding-probes/{probe}", s.onboardingProbe)
	m.HandleFunc("POST /v1/tenants/{tenant}/partners/{partner}/onboarding-probes/{probe}/work", s.onboardingProbe)
	m.HandleFunc("GET /v1/tenants/{tenant}/partners/{partner}/custody/reconcile", s.reconcile)
	m.HandleFunc("GET /v1/tenants/{tenant}/partners/{partner}/audit/export", s.exportAudit)
	m.HandleFunc("GET /v1/tenants/{tenant}/partners/{partner}/identity", s.identity)
	m.HandleFunc("GET /v1/tenants/{tenant}/partners/{partner}/accounts", s.accounts)
	m.HandleFunc("GET /v1/tenants/{tenant}/partners/{partner}/accounts/{account}", s.accounts)
	m.HandleFunc("POST /v1/tenants/{tenant}/partners/{partner}/accounts/commands", s.accounts)
	m.HandleFunc("GET /v1/tenants/{tenant}/partners/{partner}/partner-directory", s.partners)
	m.HandleFunc("POST /v1/tenants/{tenant}/partners/{partner}/partner-directory", s.partners)
	m.HandleFunc("POST /v1/tenants/{tenant}/partners/{partner}/browser-session", s.createBrowserSession)
	m.HandleFunc("GET /v1/browser/session", s.currentBrowserSession)
	m.HandleFunc("POST /v1/browser/logout", s.logoutBrowser)
	for _, pattern := range []string{
		"GET /v1/tenants/{tenant}/partners/{partner}/intake-policy",
		"POST /v1/tenants/{tenant}/partners/{partner}/intake-policy",
		"POST /v1/tenants/{tenant}/partners/{partner}/intake-policy/revoke",
		"GET /v1/tenants/{tenant}/partners/{partner}/checks/{file}",
		"GET /v1/tenants/{tenant}/partners/{partner}/checks",
		"GET /v1/tenants/{tenant}/partners/{partner}/scanners/{scanner}/{version}",
		"POST /v1/tenants/{tenant}/partners/{partner}/scanners/{scanner}/{version}/revoke",
		"POST /v1/tenants/{tenant}/partners/{partner}/pgp-keys",
		"GET /v1/tenants/{tenant}/partners/{partner}/pgp-keys/{key}/{version}",
		"POST /v1/tenants/{tenant}/partners/{partner}/pgp-keys/{key}/{version}/revoke",
		"PUT /v1/tenants/{tenant}/partners/{partner}/checks/{file}/signature",
		"GET /v1/tenants/{tenant}/partners/{partner}/checks/{file}/signature",
		"POST /v1/tenants/{tenant}/partners/{partner}/checks/{file}/run",
		"POST /v1/tenants/{tenant}/partners/{partner}/checks/{file}/recover",
		"POST /v1/tenants/{tenant}/partners/{partner}/checks/{file}/release",
		"POST /v1/tenants/{tenant}/partners/{partner}/checks/{file}/recheck-preview",
		"POST /v1/tenants/{tenant}/partners/{partner}/checks/{file}/rechecks",
		"GET /v1/tenants/{tenant}/partners/{partner}/checks/{file}/rechecks",
		"GET /v1/tenants/{tenant}/partners/{partner}/rechecks/{recheck}",
		"POST /v1/tenants/{tenant}/partners/{partner}/rechecks/{recheck}/decide",
		"POST /v1/tenants/{tenant}/partners/{partner}/rechecks/{recheck}/copy",
	} {
		m.HandleFunc(pattern, s.checks)
	}
	for _, pattern := range []string{
		"GET /v1/tenants/{tenant}/partners/{partner}/ai/profiles/{profile}/{version}",
		"POST /v1/tenants/{tenant}/partners/{partner}/ai/jobs",
		"GET /v1/tenants/{tenant}/partners/{partner}/ai/jobs/{job}",
		"POST /v1/tenants/{tenant}/partners/{partner}/ai/jobs/{job}/approve",
		"POST /v1/tenants/{tenant}/partners/{partner}/ai/jobs/{job}/generate",
		"POST /v1/tenants/{tenant}/partners/{partner}/ai/jobs/{job}/adopt",
		"GET /v1/tenants/{tenant}/partners/{partner}/ai/jobs/{job}/evidence/{event}",
	} {
		m.HandleFunc(pattern, s.assistance)
	}
	for _, pattern := range []string{
		"POST /v1/tenants/{tenant}/partners/{partner}/workflows/validate",
		"POST /v1/tenants/{tenant}/partners/{partner}/workflows/drafts",
		"GET /v1/tenants/{tenant}/partners/{partner}/workflows/{workflow}/{version}",
		"POST /v1/tenants/{tenant}/partners/{partner}/workflows/{workflow}/{version}/approve",
		"POST /v1/tenants/{tenant}/partners/{partner}/workflows/{workflow}/{version}/revoke",
		"GET /v1/tenants/{tenant}/partners/{partner}/workflows/{workflow}/{version}/diff",
		"GET /v1/tenants/{tenant}/partners/{partner}/connections/{connection}/{version}",
		"POST /v1/tenants/{tenant}/partners/{partner}/connections/{connection}/{version}/revoke",
		"POST /v1/tenants/{tenant}/partners/{partner}/workflow-runs",
		"GET /v1/tenants/{tenant}/partners/{partner}/workflow-runs/{run}",
		"POST /v1/tenants/{tenant}/partners/{partner}/workflow-runs/{run}/work",
		"POST /v1/tenants/{tenant}/partners/{partner}/workflow-runs/{run}/cancel",
	} {
		m.HandleFunc(pattern, s.workflow)
	}
	m.HandleFunc("POST /v1/tenants/{tenant}/partners/{partner}/namespace/commands", s.pathCommand)
	m.HandleFunc("GET /v1/tenants/{tenant}/partners/{partner}/namespace/stat", s.statPath)
	m.HandleFunc("GET /v1/tenants/{tenant}/partners/{partner}/namespace/entries", s.listPath)
	m.HandleFunc("GET /v1/tenants/{tenant}/partners/{partner}/namespace/file", s.downloadPath)
	m.HandleFunc("PUT /v1/tenants/{tenant}/partners/{partner}/namespace/file", s.uploadPath)
	m.HandleFunc("POST /v1/tenants/{tenant}/partners/{partner}/uploads", s.createUpload)
	m.HandleFunc("GET /v1/tenants/{tenant}/partners/{partner}/uploads", s.listUploads)
	m.HandleFunc("GET /v1/tenants/{tenant}/partners/{partner}/uploads/{upload}", s.uploadStatus)
	m.HandleFunc("PATCH /v1/tenants/{tenant}/partners/{partner}/uploads/{upload}", s.appendUpload)
	m.HandleFunc("POST /v1/tenants/{tenant}/partners/{partner}/uploads/{upload}/complete", s.completeUpload)
	m.HandleFunc("POST /v1/tenants/{tenant}/partners/{partner}/uploads/{upload}/abort", s.abortUpload)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
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
		request, ok := s.authenticateBrowser(w, r)
		if ok {
			m.ServeHTTP(w, request)
		}
	})
}
func (s *Server) exportAudit(w http.ResponseWriter, r *http.Request) {
	identity, err := scope(r)
	if err != nil {
		failure(w, err)
		return
	}
	select {
	case s.auditSlots <- struct{}{}:
		defer func() { <-s.auditSlots }()
	default:
		fail(w, 503, "audit_capacity_busy")
		return
	}
	if s.Audit == nil {
		failure(w, audit.ErrUnconfigured)
		return
	}
	envelope, err := s.Audit.Export(r.Context(), identity)
	if err != nil {
		failure(w, err)
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="audit-snapshot.json"`)
	respond(w, 200, envelope)
}
func (s *Server) reconcile(w http.ResponseWriter, r *http.Request) {
	identity, err := scope(r)
	if err != nil {
		failure(w, err)
		return
	}
	report, err := s.Service.Reconcile(r.Context(), identity)
	if err != nil {
		failure(w, err)
		return
	}
	respond(w, 200, report)
}
func scope(r *http.Request) (store.Scope, error) {
	h := r.Header.Get("Authorization")
	if h == "" {
		if proof, ok := r.Context().Value(browserContextKey{}).(browserProof); ok {
			return proof.Scope, nil
		}
	}
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
	code, message := errorStatus(err)
	fail(w, code, message)
}

// Native browser download navigation receives a readable refusal page. API
// callers retain the exact JSON status contract and no error becomes a file.
func requestFailure(w http.ResponseWriter, r *http.Request, err error) {
	if r.Method == http.MethodGet && strings.Contains(r.Header.Get("Accept"), "text/html") && (strings.HasSuffix(r.URL.Path, "/namespace/file") || strings.Contains(r.URL.Path, "/files/")) {
		code, message := errorStatus(err)
		browser.DownloadError(w, code, message)
		return
	}
	failure(w, err)
}

func errorStatus(err error) (int, string) {
	switch {
	case errors.Is(err, store.ErrOnboardingInput):
		return 400, "invalid_onboarding_command"
	case errors.Is(err, store.ErrPartnerInput):
		return 400, "invalid_partner_command"
	case errors.Is(err, store.ErrPartnerExists):
		return 409, "partner_exists"
	case errors.Is(err, store.ErrAccountInput):
		return 400, "invalid_account_command"
	case errors.Is(err, vpath.ErrPath):
		return 400, "invalid_virtual_path"
	case errors.Is(err, store.ErrForbidden):
		return 403, "permission_denied"
	case errors.Is(err, store.ErrRevision):
		return 409, "revision_conflict"
	case errors.Is(err, store.ErrExists):
		return 409, "path_exists"
	case errors.Is(err, store.ErrState):
		return 409, "operation_state_conflict"
	case errors.Is(err, store.ErrLimit):
		return 413, "evidence_bound_exceeded"
	case errors.Is(err, store.ErrIsolation):
		return 503, "database_isolation_unavailable"
	case errors.Is(err, audit.ErrUnconfigured):
		return 503, "audit_signing_unconfigured"
	case errors.Is(err, store.ErrUnauthorized):
		return 401, "unauthorized"
	case errors.Is(err, store.ErrNotFound):
		return 404, "not_found"
	case errors.Is(err, store.ErrConflict):
		return 409, "idempotency_conflict"
	case errors.Is(err, custody.ErrStorageIdentity):
		return 409, "storage_identity_mismatch"
	case errors.Is(err, custody.ErrInput):
		return 400, "invalid_upload_contract"
	case errors.Is(err, custody.ErrIntegrity):
		return 422, "integrity_mismatch"
	case errors.Is(err, custody.ErrCapacity):
		return 507, "storage_quota_reached"
	default:
		return 503, "operation_unavailable"
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
	respond(w, status, map[string]any{"file": f, "replayed": replay, "acceptance": custody.Acceptance(f)})
}
func (s *Server) download(w http.ResponseWriter, r *http.Request) {
	identity, err := scope(r)
	if err != nil {
		requestFailure(w, r, err)
		return
	}
	f, data, err := s.Service.OpenFileReader(r.Context(), identity, r.PathValue("file"))
	if err != nil {
		requestFailure(w, r, err)
		return
	}
	defer data.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+f.ID+`"`)
	w.Header().Set("X-Content-SHA256", f.SHA256)
	// Ranges use the same verified descriptor, with current authority and intake
	// release checks before each bounded read, including during a long response.
	http.ServeContent(w, r, f.ID, time.Time{}, io.NewSectionReader(data, 0, f.Size))
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
