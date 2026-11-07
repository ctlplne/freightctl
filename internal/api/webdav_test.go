package api

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ctlplne/freightctl/internal/custody"
)

func TestWebDAVReadProfileRequiresOrdinaryBearerBeforeNamespaceAccess(t *testing.T) {
	handler := New(&custody.Service{}, nil)
	for _, method := range []string{"OPTIONS", "PROPFIND", "GET", "HEAD", "PUT", "LOCK"} {
		r := httptest.NewRequest(method, "https://localhost/v1/tenants/example/partners/partner/dav/", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != 401 || w.Header().Get("DAV") != "" || w.Header().Get("ETag") != "" || strings.Contains(w.Body.String(), "multistatus") {
			t.Fatalf("%s disclosed a namespace or missed authentication: status=%d", method, w.Code)
		}
	}
}

func TestWebDAVRejectsAmbiguousNamesBeforeServeMuxRedirects(t *testing.T) {
	handler := New(&custody.Service{}, nil)
	for _, tail := range []string{"../escape", "a/../b", "%2e%2e/escape", "a%2fb", "a//b", "/", ".freightctl/receipt", "file?path=/another"} {
		r := httptest.NewRequest("PROPFIND", "https://localhost/v1/tenants/t/partners/p/dav/"+tail, nil)
		r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 64))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != 400 || w.Header().Get("Location") != "" {
			t.Fatalf("ambiguous DAV path was redirected or reached storage: %q %d", tail, w.Code)
		}
	}
}
