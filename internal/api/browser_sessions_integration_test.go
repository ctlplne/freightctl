//go:build integration

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/jackc/pgx/v5"
)

func browserAPI(t *testing.T, lifetime time.Duration, exchangeSettings ...custody.ExchangeSettings) (*custody.Service, store.Scope, *secure.Secret, *httptest.Server) {
	t.Helper()
	ctx := context.Background()
	adminRef, runtimeRef := os.Getenv("FREIGHTCTL_TEST_ADMIN_FILE"), os.Getenv("FREIGHTCTL_TEST_RUNTIME_FILE")
	if adminRef == "" || runtimeRef == "" {
		t.Fatal("real PostgreSQL references required")
	}
	secret, err := secure.ReadSecret(adminRef, 4096)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := pgx.Connect(ctx, string(secret.Bytes))
	secret.Close()
	if err != nil {
		t.Fatal("fixture admin connection failed")
	}
	name := "freightctl_browser_" + strings.ReplaceAll(secure.NewID(), "-", "")
	if _, err = admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		admin.Close(ctx)
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, err := admin.Exec(ctx, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)")
		if err != nil {
			t.Error(err)
		}
		admin.Close(ctx)
	})
	refs := []string{}
	for _, source := range []string{adminRef, runtimeRef} {
		b, err := secure.ReadSecret(source, 4096)
		if err != nil {
			t.Fatal(err)
		}
		u, err := url.Parse(string(b.Bytes))
		b.Close()
		if err != nil {
			t.Fatal("fixture DSN parse failed")
		}
		u.Path = "/" + name
		p := filepath.Join(t.TempDir(), "database.dsn")
		if err = os.WriteFile(p, []byte(u.String()), 0600); err != nil {
			t.Fatal(err)
		}
		refs = append(refs, p)
	}
	if err = store.Migrate(ctx, refs[0], filepath.Join(filepath.Dir(adminRef), "pg-runtime-password")); err != nil {
		t.Fatal(err)
	}
	credentialPath := filepath.Join(t.TempDir(), "credential")
	if err = secure.WriteToken(credentialPath); err != nil {
		t.Fatal(err)
	}
	scope := store.Scope{Tenant: secure.NewID(), Partner: secure.NewID()}
	if err = store.Provision(ctx, refs[0], scope.Tenant, scope.Partner, credentialPath); err != nil {
		t.Fatal(err)
	}
	credential, err := secure.ReadSecret(credentialPath, 64)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(credential.Close)
	scope.TokenHash = secure.Digest(credential.Bytes)
	db, err := store.Open(ctx, refs[1])
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Pool.Close)
	disk, err := custody.Open(filepath.Join(t.TempDir(), "custody"))
	if err != nil {
		t.Fatal(err)
	}
	s := &custody.Service{DB: db, Disk: disk, MaxFile: 8 << 20, MaxStored: 64 << 20, NamespaceMaxEntries: 1000}
	if len(exchangeSettings) > 1 {
		t.Fatal("fixture accepts at most one explicit exchange configuration")
	}
	if len(exchangeSettings) == 1 {
		s.Exchanges = exchangeSettings[0]
	}
	server := httptest.NewTLSServer(NewWithBrowserLifetime(s, nil, false, lifetime))
	t.Cleanup(server.Close)
	server.Client().Timeout = 10 * time.Second
	return s, scope, credential, server
}

func browserRequest(t *testing.T, server *httptest.Server, method, path string, cookie *http.Cookie, headers map[string]string, body string, expected int) (*http.Response, []byte) {
	t.Helper()
	r, err := http.NewRequest(method, server.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	response, err := server.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || response.StatusCode != expected {
		t.Fatalf("%s request: expected %d got %d, read error %v", method, expected, response.StatusCode, err)
	}
	return response, b
}

func loginBrowser(t *testing.T, server *httptest.Server, scope store.Scope, credential *secure.Secret) (*http.Cookie, string) {
	t.Helper()
	path := "/v1/tenants/" + scope.Tenant + "/partners/" + scope.Partner + "/browser-session"
	headers := map[string]string{"Authorization": "Bearer " + string(credential.Bytes), "Origin": server.URL, "Idempotency-Key": "browser-login"}
	response, data := browserRequest(t, server, "POST", path, nil, headers, "", 200)
	if len(response.Cookies()) != 1 {
		t.Fatal("missing unique cookie")
	}
	cookie := response.Cookies()[0]
	if cookie.Name != browserCookieName || !cookie.Secure || !cookie.HttpOnly || cookie.Path != "/" || cookie.Domain != "" || cookie.SameSite != http.SameSiteStrictMode || cookie.MaxAge < 1 {
		t.Fatal("unsafe session cookie attributes")
	}
	var value struct {
		CSRF     string         `json:"csrf_token"`
		Identity store.Identity `json:"identity"`
	}
	if json.Unmarshal(data, &value) != nil || len(value.CSRF) != 64 || value.Identity.Tenant != scope.Tenant {
		t.Fatal("invalid browser bootstrap")
	}
	if bytes.Contains(data, credential.Bytes) || strings.Contains(string(data), cookie.Value) || strings.Contains(cookie.Value, string(credential.Bytes)) {
		t.Fatal("parent/session secret leaked in status")
	}
	replay, _ := browserRequest(t, server, "POST", path, nil, headers, "", 200)
	if len(replay.Cookies()) != 1 || replay.Cookies()[0].Value != cookie.Value || !replay.Cookies()[0].Expires.Equal(cookie.Expires) {
		t.Fatal("login replay changed cookie or renewed expiry")
	}
	return cookie, value.CSRF
}

func TestBrowserCookieCSRFIsolationLogoutAndStreamingReadGate(t *testing.T) {
	service, scope, credential, server := browserAPI(t, 10*time.Minute)
	cookie, csrf := loginBrowser(t, server, scope, credential)
	prefix := "/v1/tenants/" + scope.Tenant + "/partners/" + scope.Partner
	browserRequest(t, server, "GET", prefix+"/identity", cookie, nil, "", 200)
	_, data := browserRequest(t, server, "GET", "/v1/browser/session", cookie, nil, "", 200)
	if strings.Contains(string(data), cookie.Value) || bytes.Contains(data, credential.Bytes) {
		t.Fatal("restore disclosed secret")
	}
	baseHeaders := map[string]string{"Origin": server.URL, "Idempotency-Key": "directory"}
	body := `{"operation":"mkdir","path":"/browser-directory"}`
	browserRequest(t, server, "POST", prefix+"/namespace/commands", cookie, baseHeaders, body, 403)
	baseHeaders["X-CSRF-Token"] = strings.Repeat("0", 64)
	browserRequest(t, server, "POST", prefix+"/namespace/commands", cookie, baseHeaders, body, 403)
	baseHeaders["X-CSRF-Token"] = csrf
	baseHeaders["Origin"] = "https://untrusted.invalid"
	browserRequest(t, server, "POST", prefix+"/namespace/commands", cookie, baseHeaders, body, 403)
	baseHeaders["Origin"] = server.URL
	baseHeaders["Sec-Fetch-Site"] = "cross-site"
	browserRequest(t, server, "POST", prefix+"/namespace/commands", cookie, baseHeaders, body, 403)
	delete(baseHeaders, "Sec-Fetch-Site")
	browserRequest(t, server, "POST", prefix+"/namespace/commands", cookie, baseHeaders, body, 200)
	browserRequest(t, server, "GET", "/v1/tenants/"+secure.NewID()+"/partners/"+scope.Partner+"/identity", cookie, nil, "", 401)
	browserRequest(t, server, "GET", prefix+"/identity", cookie, map[string]string{"Authorization": "Bearer invalid"}, "", 401)
	bytesIn := []byte("authorized browser stream remains subject to live logout")
	file, _, err := service.Accept(context.Background(), scope, "stream", int64(len(bytesIn)), secure.Digest(bytesIn), bytes.NewReader(bytesIn))
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(cookie.Value, ".")
	proof, _, err := service.DB.BrowserScope(context.Background(), scope.Tenant, scope.Partner, secure.Digest([]byte(parts[2])))
	if err != nil {
		t.Fatal(err)
	}
	_, reader, err := service.OpenFileReader(context.Background(), proof, file.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if n, err := reader.ReadAt(make([]byte, 1), 0); err != nil || n != 1 {
		t.Fatal("authorized stream did not start", err)
	}
	logoutHeaders := map[string]string{"Origin": server.URL, "Idempotency-Key": "logout", "X-CSRF-Token": csrf}
	response, _ := browserRequest(t, server, "POST", "/v1/browser/logout", cookie, logoutHeaders, "", 204)
	if len(response.Cookies()) != 1 || response.Cookies()[0].MaxAge != -1 {
		t.Fatal("logout retained cookie")
	}
	if n, err := reader.ReadAt(make([]byte, 1), 1); n != 0 || !errors.Is(err, store.ErrUnauthorized) {
		t.Fatal("open stream survived logout", n, err)
	}
	browserRequest(t, server, "GET", prefix+"/identity", cookie, nil, "", 401)
	browserRequest(t, server, "POST", "/v1/browser/logout", cookie, logoutHeaders, "", 204)
	browserRequest(t, server, "GET", prefix+"/identity", nil, map[string]string{"Authorization": "Bearer " + string(credential.Bytes)}, "", 200)
}

func TestBrowserCookieDatabaseExpiryIsEnforcedByHTTP(t *testing.T) {
	_, scope, credential, server := browserAPI(t, 2*time.Second)
	cookie, _ := loginBrowser(t, server, scope, credential)
	time.Sleep(2200 * time.Millisecond)
	browserRequest(t, server, "GET", "/v1/browser/session", cookie, nil, "", 401)
}

func TestBrowserLogoutOperationKeyCannotRevokeAnotherSession(t *testing.T) {
	_, scope, credential, server := browserAPI(t, 10*time.Minute)
	path := "/v1/tenants/" + scope.Tenant + "/partners/" + scope.Partner + "/browser-session"
	var cookies []*http.Cookie
	var csrf []string
	for _, key := range []string{"first-login", "second-login"} {
		r, b := browserRequest(t, server, "POST", path, nil, map[string]string{"Authorization": "Bearer " + string(credential.Bytes), "Origin": server.URL, "Idempotency-Key": key}, "", 200)
		var value struct {
			CSRF string `json:"csrf_token"`
		}
		if json.Unmarshal(b, &value) != nil || len(r.Cookies()) != 1 {
			t.Fatal("session fixture")
		}
		cookies = append(cookies, r.Cookies()[0])
		csrf = append(csrf, value.CSRF)
	}
	headers := map[string]string{"Origin": server.URL, "Idempotency-Key": "same-logout-command", "X-CSRF-Token": csrf[0]}
	browserRequest(t, server, "POST", "/v1/browser/logout", cookies[0], headers, "", 204)
	headers["X-CSRF-Token"] = csrf[1]
	browserRequest(t, server, "POST", "/v1/browser/logout", cookies[1], headers, "", 409)
	browserRequest(t, server, "GET", "/v1/browser/session", cookies[1], nil, "", 200)
}
