package api

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ctlplne/freightctl/internal/custody"
)

func TestProcessingProposalPublicControlsRequireAuthenticationAndHaveNoApprovalAction(t *testing.T) {
	h := New(&custody.Service{}, nil)
	base := "https://freightctl.invalid/v1/tenants/11111111-1111-4111-8111-111111111111/partners/22222222-2222-4222-8222-222222222222/processing-proposals"
	id := "/33333333-3333-4333-8333-333333333333"
	for _, route := range []struct{ method, path string }{{"POST", base}, {"GET", base}, {"GET", base + id}, {"POST", base + id + "/adopt"}, {"POST", base + id + "/reject"}, {"POST", base + id + "/withdraw"}} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(route.method, route.path, strings.NewReader(`{}`)))
		if w.Code != 401 {
			t.Fatal("proposal control bypassed authentication", route.path, w.Code)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", base+id+"/approve", strings.NewReader(`{}`)))
	if w.Code != 404 {
		t.Fatal("proposal exposed approval route", w.Code)
	}
}

func TestProcessingProposalPaginationAndClaimedAuthorityRefuseBeforeDatabase(t *testing.T) {
	h := New(&custody.Service{}, nil)
	base := "https://freightctl.invalid/v1/tenants/11111111-1111-4111-8111-111111111111/partners/22222222-2222-4222-8222-222222222222/processing-proposals"
	for _, query := range []string{"?limit=0", "?limit=101", "?limit=bad", "?after=not-a-uuid"} {
		r := httptest.NewRequest("GET", base+query, nil)
		r.Header.Set("Authorization", "Bearer "+strings.Repeat("0", 64))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 400 || !strings.Contains(w.Body.String(), "invalid_processing_proposal") {
			t.Fatal("invalid selector reached database", query, w.Code)
		}
	}
	for _, body := range []string{`{"executor_id":"33333333-3333-4333-8333-333333333333","author":{"authority_revision":1}}`, `{"executor_id":"33333333-3333-4333-8333-333333333333","approved":true}`} {
		r := httptest.NewRequest("POST", base, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+strings.Repeat("0", 64))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatal("caller-declared proposal authority reached database", w.Code)
		}
	}
}
