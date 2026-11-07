package api

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ctlplne/freightctl/internal/custody"
)

func TestProcessingOutputPolicyControlsRejectUntrustedAuthorityBeforeDatabase(t *testing.T) {
	h := New(&custody.Service{}, nil)
	base := "https://freightctl.invalid/v1/tenants/11111111-1111-4111-8111-111111111111/partners/22222222-2222-4222-8222-222222222222/processing-output-policies"
	for _, route := range []struct{ method, path string }{{"GET", base}, {"POST", base}, {"GET", base + "/33333333-3333-4333-8333-333333333333/1"}, {"POST", base + "/33333333-3333-4333-8333-333333333333/1/revoke"}} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(route.method, route.path, strings.NewReader(`{}`)))
		if w.Code != 401 {
			t.Fatal("output contract bypassed authentication", w.Code)
		}
	}
	for _, body := range []string{`{"producer_id":"33333333-3333-4333-8333-333333333333","producer_authority_revision":1}`, `{"publisher_id":"invented"}`, `{"default_ingress":true}`, `{"ROOT":"/"}`} {
		r := httptest.NewRequest("POST", base, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+strings.Repeat("0", 64))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatal("untrusted output authority reached database", w.Code)
		}
	}
}
