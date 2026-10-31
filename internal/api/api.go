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
	"github.com/ctlplne/freightctl/internal/workflow"
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

	for _, action := range []string{"approve", "cancel", "work"} {
		m.HandleFunc("POST /v1/tenants/{tenant}/partners/{partner}/onboarding-observations/{observation}/"+action, s.onboardingObservationAction(action))
	}
	m.HandleFunc("POST /v1/tenants/{tenant}/partners/{partner}/onboarding-observations/preview", s.onboardingObservationAction("preview"))
	m.HandleFunc("POST /v1/tenants/{tenant}/partners/{partner}/onboarding-observations", s.onboardingObservationAction("propose"))
	m.HandleFunc("GET /v1/tenants/{tenant}/partners/{partner}/onboarding-observations/{observation}", s.onboardingObservationAction("status"))
	m.HandleFunc("GET /v1/tenants/{tenant}/partners/{partner}/onboarding-plans/{plan}/observations", s.onboardingObservationAction("list"))
	for _, action := range []string{"approve", "cancel", "execute"} {
		m.HandleFunc("POST /v1/tenants/{tenant}/partners/{partner}/onboarding-handoffs/{handoff}/"+action, s.onboardingHandoffAction(action))
	}
	m.HandleFunc("POST /v1/tenants/{tenant}/partners/{partner}/onboarding-handoffs/preview", s.onboardingHandoffAction("preview"))
	m.HandleFunc("POST /v1/tenants/{tenant}/partners/{partner}/onboarding-handoffs", s.onboardingHandoffAction("propose"))
	m.HandleFunc("GET /v1/tenants/{tenant}/partners/{partner}/onboarding-handoffs/{handoff}", s.onboardingHandoffAction("status"))
	m.HandleFunc("GET /v1/tenants/{tenant}/partners/{partner}/onboarding-plans/{plan}/handoffs", s.onboardingHandoffAction("list"))
	for _, action := range []string{"approve", "activate", "suspend", "revoke"} {
		m.HandleFunc("POST /v1/tenants/{tenant}/partners/{partner}/onboarding-releases/{release}/"+action, s.onboardingReleaseAction(action))
	}

	m.HandleFunc("GET /v1/tenants/{tenant}/partners/{partner}/workflow-schedule-workflows", s.schedule("workflows"))
	m.HandleFunc("GET /v1/tenants/{tenant}/partners/{partner}/workflow-collection-connections", s.collection("connections"))
	m.HandleFunc("GET /v1/tenants/{tenant}/partners/{partner}/workflow-collection-workflows", s.collection("workflows"))
	m.HandleFunc("POST /v1/tenants/{tenant}/partners/{partner}/workflow-collections/preview", s.collection("preview"))
	m.HandleFunc("POST /v1/tenants/{tenant}/partners/{partner}/workflow-collections", s.collection("start"))
	m.HandleFunc("GET /v1/tenants/{tenant}/partners/{partner}/workflow-collections", s.collection("list"))
	m.HandleFunc("GET /v1/tenants/{tenant}/partners/{partner}/workflow-collections/{collection}", s.collection("status"))
	m.HandleFunc("POST /v1/tenants/{tenant}/partners/{partner}/workflow-collections/{collection}/routing/preview", s.collectionRouting("preview"))
	m.HandleFunc("POST /v1/tenants/{tenant}/partners/{partner}/workflow-collections/{collection}/routing/inputs/{input}/preview", s.collectionRouting("input-preview"))
	m.HandleFunc("POST /v1/tenants/{tenant}/partners/{partner}/workflow-collections/{collection}/routing/proposals", s.collectionRouting("propose"))
	m.HandleFunc("GET /v1/tenants/{tenant}/partners/{partner}/workflow-collections/{collection}/routing", s.collectionRouting("history"))
	m.HandleFunc("GET /v1/tenants/{tenant}/partners/{partner}/workflow-collections/{collection}/routing/{routing}", s.collectionRouting("status"))
	for _, action := range []string{"approve", "revoke", "withdraw"} {
		m.HandleFunc("POST /v1/tenants/{tenant}/partners/{partner}/workflow-collections/{collection}/routing/{routing}/"+action, s.collectionRouting(action))
	}
	for _, action := range []string{"work", "refresh", "cancel"} {
		m.HandleFunc("POST /v1/tenants/{tenant}/partners/{partner}/workflow-collections/{collection}/"+action, s.collection(action))
	}
	m.HandleFunc("POST /v1/tenants/{tenant}/partners/{partner}/workflow-schedules/preview", s.schedule("preview"))
	m.HandleFunc("POST /v1/tenants/{tenant}/partners/{partner}/workflow-schedules/drafts", s.schedule("draft"))
	m.HandleFunc("GET /v1/tenants/{tenant}/partners/{partner}/workflow-schedules", s.schedule("list"))
	m.HandleFunc("GET /v1/tenants/{tenant}/partners/{partner}/workflow-schedules/{schedule}/{version}", s.schedule("status"))
	m.HandleFunc("GET /v1/tenants/{tenant}/partners/{partner}/workflow-schedules/{schedule}/history", s.schedule("history"))
	m.HandleFunc("GET /v1/tenants/{tenant}/partners/{partner}/workflow-schedule-occurrences/{occurrence}", s.schedule("occurrence"))
	m.HandleFunc("GET /v1/tenants/{tenant}/partners/{partner}/workflow-schedule-arrivals/{occurrence}", s.scheduleArrival("status"))
	for _, action := range []string{"probe", "admit", "cancel"} {
		m.HandleFunc("POST /v1/tenants/{tenant}/partners/{partner}/workflow-schedule-arrivals/{occurrence}/"+action, s.scheduleArrival(action))
	}
	m.HandleFunc("POST /v1/tenants/{tenant}/partners/{partner}/workflow-schedules/{schedule}/{version}/tick", s.schedule("tick"))
	for _, action := range []string{"activate", "suspend", "revoke"} {
		m.HandleFunc("POST /v1/tenants/{tenant}/partners/{partner}/workflow-schedules/{schedule}/{version}/"+action, s.schedule(action))
	}
	m.HandleFunc("GET /v1/tenants/{tenant}/partners/{partner}/outbound-dispatch-policy", s.outboundApproval("policy"))
	m.HandleFunc("POST /v1/tenants/{tenant}/partners/{partner}/outbound-dispatch-policy", s.outboundApproval("policy-change"))
	m.HandleFunc("GET /v1/tenants/{tenant}/partners/{partner}/outbound-deliveries/{delivery}", s.outboundApproval("delivery"))
	m.HandleFunc("POST /v1/tenants/{tenant}/partners/{partner}/outbound-dispatch-reviews/preview", s.outboundApproval("preview"))
	m.HandleFunc("GET /v1/tenants/{tenant}/partners/{partner}/outbound-dispatch-reviews", s.outboundApproval("list"))
	m.HandleFunc("POST /v1/tenants/{tenant}/partners/{partner}/outbound-dispatch-reviews", s.outboundApproval("propose"))
	m.HandleFunc("GET /v1/tenants/{tenant}/partners/{partner}/outbound-dispatch-reviews/{review}", s.outboundApproval("status"))
	for _, action := range []string{"approve", "reject", "withdraw"} {
		m.HandleFunc("POST /v1/tenants/{tenant}/partners/{partner}/outbound-dispatch-reviews/{review}/"+action, s.outboundApproval(action))
	}
	m.HandleFunc("GET /v1/tenants/{tenant}/partners/{partner}/onboarding-approval-policy", s.onboardingApproval("policy"))
	m.HandleFunc("POST /v1/tenants/{tenant}/partners/{partner}/onboarding-approval-policy", s.onboardingApproval("policy-change"))
	m.HandleFunc("POST /v1/tenants/{tenant}/partners/{partner}/onboarding-approval-reviews/preview", s.onboardingApproval("preview"))
	m.HandleFunc("POST /v1/tenants/{tenant}/partners/{partner}/onboarding-approval-reviews", s.onboardingApproval("propose"))
	m.HandleFunc("GET /v1/tenants/{tenant}/partners/{partner}/onboarding-approval-reviews", s.onboardingApproval("list"))
	m.HandleFunc("GET /v1/tenants/{tenant}/partners/{partner}/onboarding-approval-reviews/{review}", s.onboardingApproval("status"))
	for _, action := range []string{"approve", "reject", "withdraw"} {
		m.HandleFunc("POST /v1/tenants/{tenant}/partners/{partner}/onboarding-approval-reviews/{review}/"+action, s.onboardingApproval(action))
	}
	m.HandleFunc("POST /v1/tenants/{tenant}/partners/{partner}/onboarding-releases/preview", s.onboardingReleaseAction("preview"))
	m.HandleFunc("POST /v1/tenants/{tenant}/partners/{partner}/onboarding-releases", s.onboardingReleaseAction("propose"))
	m.HandleFunc("GET /v1/tenants/{tenant}/partners/{partner}/onboarding-releases/{release}", s.onboardingReleaseAction("status"))
	m.HandleFunc("GET /v1/tenants/{tenant}/partners/{partner}/onboarding-plans/{plan}/releases", s.onboardingReleaseAction("list"))
	m.HandleFunc("POST /v1/tenants/{tenant}/partners/{partner}/onboarding-releases/{release}/production-preview", s.onboardingReleaseAction("production-preview"))
	m.HandleFunc("POST /v1/tenants/{tenant}/partners/{partner}/onboarding-production", s.onboardingReleaseAction("production-start"))
	m.HandleFunc("GET /v1/tenants/{tenant}/partners/{partner}/onboarding-production/{production}", s.onboardingReleaseAction("production-status"))
	m.HandleFunc("GET /v1/tenants/{tenant}/partners/{partner}/onboarding-releases/{release}/runs", s.onboardingReleaseAction("production-list"))
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
		"POST /v1/tenants/{tenant}/partners/{partner}/workflow-runs/preview",
		"GET /v1/tenants/{tenant}/partners/{partner}/workflow-runs/{run}",
		"POST /v1/tenants/{tenant}/partners/{partner}/workflow-runs/{run}/work",
		"POST /v1/tenants/{tenant}/partners/{partner}/workflow-runs/{run}/refresh",
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
	case errors.Is(err, store.ErrSchedule):
		return 409, "schedule_authority_or_deadline_required"
	case errors.Is(err, store.ErrArrival):
		return 409, "arrival_authority_or_probe_required"
	case errors.Is(err, store.ErrCollection):
		return 409, "collection_authority_input_or_lease_required"
	case errors.Is(err, workflow.ErrRouting):
		return 409, "workflow_routing_decision_required"
	case errors.Is(err, store.ErrDispatchApproval):
		return 409, "dispatch_approval_required"
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
