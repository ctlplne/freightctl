package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ctlplne/freightctl/internal/custody"
)

func TestTusCoreDuplicateControlsAndOverridesCannotUseReadCSRFRules(t *testing.T) {
	h := New(&custody.Service{}, nil)
	url := "https://freightctl.invalid/v1/tenants/11111111-1111-4111-8111-111111111111/partners/22222222-2222-4222-8222-222222222222/tus/uploads/33333333-3333-4333-8333-333333333333"
	for _, name := range []string{"Tus-Resumable", "Upload-Offset", "Content-Type", "X-HTTP-Method-Override"} {
		r := httptest.NewRequest("PATCH", url, strings.NewReader("data"))
		r.Header.Set("Authorization", "Bearer "+strings.Repeat("0", 64))
		r.Header.Set("Tus-Resumable", "1.0.0")
		r.Header.Set("Content-Type", "application/offset+octet-stream")
		r.Header.Set("Upload-Offset", "0")
		r.Header[name] = []string{"ambiguous", "ambiguous"}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 400 && w.Code != 412 && w.Code != 415 {
			t.Fatal("duplicate protocol controls reached storage", name, w.Code)
		}
	}
	r := httptest.NewRequest("GET", url, strings.NewReader("data"))
	r.Header.Set("Tus-Resumable", "1.0.0")
	r.Header.Set("X-HTTP-Method-Override", "PATCH")
	r.Header.Set("Content-Type", "application/offset+octet-stream")
	r.Header.Set("Upload-Offset", "0")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.AddCookie(&http.Cookie{Name: browserCookieName, Value: "untrusted-cookie"})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("GET override used read-only cookie/CSRF rules", w.Code)
	}
	r = httptest.NewRequest("OPTIONS", url, nil)
	r.Header["Tus-Resumable"] = []string{"unsupported", "ambiguous"}
	w = httptest.NewRecorder()
	if _, ok := prepareTusRequest(w, r); !ok {
		t.Fatal("OPTIONS did not ignore version header")
	}
}

func TestTusCoreRejectsVersionExtensionOffsetAndMediaAmbiguityBeforeDatabase(t *testing.T) {
	h := New(&custody.Service{}, nil)
	url := "https://freightctl.invalid/v1/tenants/11111111-1111-4111-8111-111111111111/partners/22222222-2222-4222-8222-222222222222/tus/uploads/33333333-3333-4333-8333-333333333333"
	for _, tc := range []struct {
		method  string
		headers map[string]string
		status  int
	}{
		{"HEAD", map[string]string{}, 412},
		{"HEAD", map[string]string{"Tus-Resumable": "1.1.0"}, 412},
		{"PATCH", map[string]string{"Tus-Resumable": "1.0.0", "Content-Type": "text/plain", "Upload-Offset": "0"}, 415},
		{"PATCH", map[string]string{"Tus-Resumable": "1.0.0", "Content-Type": "application/offset+octet-stream", "Upload-Offset": "-1"}, 400},
		{"PATCH", map[string]string{"Tus-Resumable": "1.0.0", "Content-Type": "application/offset+octet-stream", "Upload-Offset": "0", "Upload-Concat": "partial"}, 400},
		{"GET", map[string]string{"Tus-Resumable": "1.0.0", "X-HTTP-Method-Override": "PATCH", "Content-Type": "text/plain", "Upload-Offset": "0"}, 415},
	} {
		r := httptest.NewRequest(tc.method, url, strings.NewReader("data"))
		r.Header.Set("Authorization", "Bearer "+strings.Repeat("0", 64))
		for k, v := range tc.headers {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatalf("tus control missing or reached storage: want%d got%d", tc.status, w.Code)
		}
		if w.Header().Get("Tus-Resumable") != "1.0.0" || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("missing tus version/cache boundary")
		}
	}
}
