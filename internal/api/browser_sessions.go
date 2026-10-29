package api

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
)

const browserCookieName = "__Host-freightctl-session"

type browserContextKey struct{}
type browserProof struct {
	Scope   store.Scope
	Session *store.BrowserSession
	CSRF    string
}

func sameBrowserOrigin(r *http.Request, mutation bool) bool {
	origin := r.Header.Get("Origin")
	if origin != "" && origin != "https://"+r.Host {
		return false
	}
	if mutation && origin == "" {
		return false
	}
	site := r.Header.Get("Sec-Fetch-Site")
	return site == "" || site == "same-origin" || site == "none"
}

func browserCookie(r *http.Request) (tenant, partner string, token *secure.Secret, err error) {
	var value string
	count := 0
	for _, cookie := range r.Cookies() {
		if cookie.Name == browserCookieName {
			count++
			if count > 1 {
				return "", "", nil, store.ErrUnauthorized
			}
			value = cookie.Value
		}
	}
	parts := strings.Split(value, ".")
	if len(parts) != 3 || !store.ValidID(parts[0]) || !store.ValidID(parts[1]) || len(parts[2]) != 64 {
		return "", "", nil, store.ErrUnauthorized
	}
	for _, c := range parts[2] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return "", "", nil, store.ErrUnauthorized
		}
	}
	token = secure.ProtectBytes([]byte(parts[2]))
	return parts[0], parts[1], token, nil
}

func clearBrowserCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: browserCookieName, Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1, Expires: time.Unix(1, 0).UTC()})
}

func noBrowserBody(w http.ResponseWriter, r *http.Request) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1)
	b, err := io.ReadAll(r.Body)
	return err == nil && len(b) == 0
}

func (s *Server) authenticateBrowser(w http.ResponseWriter, r *http.Request) (*http.Request, bool) {
	// Explicit bearer authentication never falls back to a different cookie
	// identity, including when the supplied bearer value is malformed.
	if r.Header.Get("Authorization") != "" || !strings.HasPrefix(r.URL.Path, "/v1/") {
		return r, true
	}
	if r.URL.Path == "/v1/browser/logout" {
		return r, true
	}
	_, err := r.Cookie(browserCookieName)
	if err != nil {
		return r, true
	}
	mutation := r.Method != http.MethodGet && r.Method != http.MethodHead
	if !sameBrowserOrigin(r, mutation) {
		fail(w, 403, "browser_origin_denied")
		return r, false
	}
	tenant, partner, token, err := browserCookie(r)
	if err != nil {
		requestFailure(w, r, err)
		return r, false
	}
	defer token.Close()
	csrf, err := secure.BrowserCSRFToken(token.Bytes)
	if err != nil {
		requestFailure(w, r, err)
		return r, false
	}
	defer csrf.Close()
	if mutation && !secure.EqualToken(csrf.Bytes, []byte(r.Header.Get("X-CSRF-Token"))) {
		fail(w, 403, "csrf_required")
		return r, false
	}
	if r.URL.Path != "/v1/browser/session" && !strings.HasPrefix(r.URL.Path, "/v1/tenants/"+tenant+"/partners/"+partner+"/") {
		requestFailure(w, r, store.ErrUnauthorized)
		return r, false
	}
	scope, session, err := s.Service.DB.BrowserScope(r.Context(), tenant, partner, secure.Digest(token.Bytes))
	if err != nil {
		requestFailure(w, r, err)
		return r, false
	}
	proof := browserProof{Scope: scope, Session: session, CSRF: string(csrf.Bytes)}
	return r.WithContext(context.WithValue(r.Context(), browserContextKey{}, proof)), true
}

func (s *Server) browserResponse(w http.ResponseWriter, r *http.Request, session *store.BrowserSession, identity *store.Identity, csrf string) {
	respond(w, 200, map[string]any{"identity": identity, "session": map[string]any{"id": session.ID, "expires_at": session.ExpiresAt.UTC(), "state": session.State}, "csrf_token": csrf, "replayed": session.Replayed,
		"limits": map[string]any{"max_file_bytes": s.Service.MaxFile, "min_chunk_bytes": custody.MinUploadChunk, "max_chunk_bytes": custody.MaxUploadChunk, "max_upload_chunks": 4096}})
}

func (s *Server) createBrowserSession(w http.ResponseWriter, r *http.Request) {
	if !sameBrowserOrigin(r, false) || !noBrowserBody(w, r) || !store.ValidBrowserOperationKey(r.Header.Get("Idempotency-Key")) {
		fail(w, 400, "invalid_browser_session_request")
		return
	}
	// Only the long-lived enrolled credential can create a short-lived session.
	if r.Header.Get("Authorization") == "" {
		failure(w, store.ErrUnauthorized)
		return
	}
	scope, err := scope(r)
	if err != nil {
		failure(w, err)
		return
	}
	credential := secure.ProtectBytes([]byte(r.Header.Get("Authorization")[7:]))
	defer credential.Close()
	token, err := secure.BrowserSessionToken(credential.Bytes, scope.Tenant, scope.Partner, r.Header.Get("Idempotency-Key"))
	if err != nil {
		failure(w, store.ErrUnauthorized)
		return
	}
	defer token.Close()
	session, identity, now, err := s.Service.DB.CreateBrowserSession(r.Context(), scope, r.Header.Get("Idempotency-Key"), secure.Digest(token.Bytes), s.BrowserSessionLifetime)
	if err != nil {
		failure(w, err)
		return
	}
	csrf, err := secure.BrowserCSRFToken(token.Bytes)
	if err != nil {
		failure(w, err)
		return
	}
	defer csrf.Close()
	if session.State == "active" && now.Before(session.ExpiresAt) {
		http.SetCookie(w, &http.Cookie{Name: browserCookieName, Value: scope.Tenant + "." + scope.Partner + "." + string(token.Bytes), Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, Expires: session.ExpiresAt.UTC(), MaxAge: max(1, int(session.ExpiresAt.Sub(now)/time.Second))})
	} else {
		clearBrowserCookie(w)
	}
	s.browserResponse(w, r, session, identity, string(csrf.Bytes))
}

func (s *Server) currentBrowserSession(w http.ResponseWriter, r *http.Request) {
	proof, ok := r.Context().Value(browserContextKey{}).(browserProof)
	if !ok {
		failure(w, store.ErrUnauthorized)
		return
	}
	identity, err := s.Service.DB.Identity(r.Context(), proof.Scope)
	if err != nil {
		failure(w, err)
		return
	}
	s.browserResponse(w, r, proof.Session, identity, proof.CSRF)
}

func (s *Server) logoutBrowser(w http.ResponseWriter, r *http.Request) {
	if !sameBrowserOrigin(r, true) || !store.ValidBrowserOperationKey(r.Header.Get("Idempotency-Key")) || !noBrowserBody(w, r) {
		fail(w, 400, "invalid_browser_logout_request")
		return
	}
	tenant, partner, token, err := browserCookie(r)
	if errors.Is(err, store.ErrUnauthorized) {
		if _, present := r.Cookie(browserCookieName); present == nil {
			failure(w, err)
			return
		}
		clearBrowserCookie(w)
		w.WriteHeader(204)
		return
	}
	if err != nil {
		failure(w, err)
		return
	}
	defer token.Close()
	csrf, err := secure.BrowserCSRFToken(token.Bytes)
	if err != nil {
		failure(w, err)
		return
	}
	defer csrf.Close()
	if !secure.EqualToken(csrf.Bytes, []byte(r.Header.Get("X-CSRF-Token"))) {
		fail(w, 403, "csrf_required")
		return
	}
	scope := store.Scope{Tenant: tenant, Partner: partner, BrowserSessionHash: secure.Digest(token.Bytes)}
	err = s.Service.DB.RevokeBrowserSession(r.Context(), scope, r.Header.Get("Idempotency-Key"))
	if err != nil && !errors.Is(err, store.ErrUnauthorized) {
		failure(w, err)
		return
	}
	clearBrowserCookie(w)
	w.WriteHeader(204)
}
