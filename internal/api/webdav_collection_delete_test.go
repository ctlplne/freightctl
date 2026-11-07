package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDAVCollectionDeleteRequiresExactRootIdentityAndFullDepth(t *testing.T) {
	request := func() *http.Request {
		r := httptest.NewRequest("DELETE", "https://localhost/v1/tenants/t/partners/p/dav/source/", nil)
		r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 64))
		r.Header.Set("X-Freightctl-Namespace-Revision", "10000000-1111-4111-8111-111111111111:1")
		r.Header.Set("Idempotency-Key", "collection-delete-original")
		r.Header.Set("Depth", "infinity")
		return r
	}
	for _, depth := range []bool{true, false} {
		r := request()
		if !depth {
			r.Header.Del("Depth")
		}
		w := httptest.NewRecorder()
		if !prepareDAVRequest(w, r) {
			t.Fatalf("complete revision-bound collection removal refused before service: %d", w.Code)
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
		{"zero depth", func(r *http.Request) { r.Header.Set("Depth", "0") }, 400},
		{"duplicate depth", func(r *http.Request) { r.Header.Add("Depth", "infinity") }, 400},
		{"byte condition", func(r *http.Request) { r.Header.Set("If-Match", "unrelated") }, 400},
		{"DAV condition", func(r *http.Request) { r.Header.Set("If", "(<opaquelocktoken:unrelated>)") }, 400},
		{"destination", func(r *http.Request) { r.Header.Set("Destination", "/another/") }, 400},
		{"overwrite", func(r *http.Request) { r.Header.Set("Overwrite", "T") }, 400},
		{"no key", func(r *http.Request) { r.Header.Del("Idempotency-Key") }, 400},
		{"body", func(r *http.Request) { r.ContentLength = 1 }, 415},
		{"unknown length", func(r *http.Request) { r.ContentLength = -1 }, 415},
		{"root", func(r *http.Request) { r.URL.Path = "/v1/tenants/t/partners/p/dav/" }, 400},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := request()
			test.change(r)
			w := httptest.NewRecorder()
			if prepareDAVRequest(w, r) || w.Code != test.status {
				t.Fatal("unsafe collection removal escaped the input contract", w.Code)
			}
		})
	}
}
