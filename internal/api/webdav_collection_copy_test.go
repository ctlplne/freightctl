package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDAVCollectionCopyRequiresExactIdentityAndExplicitDepthChoice(t *testing.T) {
	request := func() *http.Request {
		r := httptest.NewRequest("COPY", "https://localhost/v1/tenants/t/partners/p/dav/source/", nil)
		r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 64))
		r.Header.Set("X-Freightctl-Namespace-Revision", "10000000-1111-4111-8111-111111111111:1")
		r.Header.Set("Idempotency-Key", "collection-copy-original")
		r.Header.Set("Overwrite", "F")
		r.Header.Set("Destination", "https://localhost/v1/tenants/t/partners/p/dav/target/")
		return r
	}
	for _, depth := range []string{"", "0", "infinity"} {
		r := request()
		if depth != "" {
			r.Header.Set("Depth", depth)
		}
		w := httptest.NewRecorder()
		if !prepareDAVRequest(w, r) {
			t.Fatalf("valid collection copy refused;depth=%q,status=%d", depth, w.Code)
		}
	}
	for _, test := range []struct {
		name   string
		change func(*http.Request)
		status int
	}{
		{"no condition", func(r *http.Request) { r.Header.Del("X-Freightctl-Namespace-Revision") }, 428},
		{"duplicate condition", func(r *http.Request) {
			r.Header.Add("X-Freightctl-Namespace-Revision", "10000000-1111-4111-8111-111111111111:2")
		}, 400},
		{"finite depth", func(r *http.Request) { r.Header.Set("Depth", "1") }, 400},
		{"duplicate depth", func(r *http.Request) { r.Header.Add("Depth", "0"); r.Header.Add("Depth", "infinity") }, 400},
		{"overwrite", func(r *http.Request) { r.Header.Set("Overwrite", "T") }, 428},
		{"no overwrite", func(r *http.Request) { r.Header.Del("Overwrite") }, 428},
		{"byte condition", func(r *http.Request) { r.Header.Set("If-Match", "unrelated") }, 400},
		{"foreign destination", func(r *http.Request) { r.Header.Set("Destination", "https://foreign.invalid/target/") }, 400},
		{"file destination", func(r *http.Request) { r.Header.Set("Destination", "/v1/tenants/t/partners/p/dav/target") }, 400},
		{"empty fragment", func(r *http.Request) { r.Header.Set("Destination", "/v1/tenants/t/partners/p/dav/target/#") }, 400},
		{"body", func(r *http.Request) { r.ContentLength = 1 }, 415},
		{"unknown length", func(r *http.Request) { r.ContentLength = -1 }, 415},
		{"no key", func(r *http.Request) { r.Header.Del("Idempotency-Key") }, 400},
		{"root", func(r *http.Request) { r.URL.Path = "/v1/tenants/t/partners/p/dav/" }, 400},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := request()
			test.change(r)
			w := httptest.NewRecorder()
			if prepareDAVRequest(w, r) || w.Code != test.status {
				t.Fatal("unsafe collection copy escaped input contract", w.Code)
			}
		})
	}
}
