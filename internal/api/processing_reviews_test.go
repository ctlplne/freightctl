package api

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ctlplne/freightctl/internal/custody"
)

func TestProcessingReviewPublicControlsRequireAuthenticationBeforeStateAccess(t *testing.T) {
	handler := New(&custody.Service{}, nil)
	base := "https://freightctl.invalid/v1/tenants/11111111-1111-4111-8111-111111111111/partners/22222222-2222-4222-8222-222222222222/processing-reviews"
	id := "/33333333-3333-4333-8333-333333333333"
	for _, route := range []struct{ method, path string }{{"GET", base}, {"POST", base}, {"GET", base + id}, {"POST", base + id + "/approve"}, {"POST", base + id + "/reject"}, {"POST", base + id + "/withdraw"}, {"POST", base + id + "/adopt"}} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(route.method, route.path, strings.NewReader(`{}`)))
		if response.Code != 401 {
			t.Fatalf("public control bypassed authentication: %s %s: %d", route.method, route.path, response.Code)
		}
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest("GET", strings.TrimSuffix(base, "processing-reviews")+"processing-workflows", nil))
	if response.Code != 401 {
		t.Fatal("catalog bypassed authentication", response.Code)
	}
}

func TestProcessingCatalogAPIRefusesInvalidPaginationBeforeDatabase(t *testing.T) {
	h := New(&custody.Service{}, nil)
	base := "https://freightctl.invalid/v1/tenants/11111111-1111-4111-8111-111111111111/partners/22222222-2222-4222-8222-222222222222/processing-workflows"
	for _, query := range []string{"?limit=0", "?limit=101", "?limit=bad", "?after=not-a-uuid"} {
		r := httptest.NewRequest("GET", base+query, nil)
		r.Header.Set("Authorization", "Bearer "+strings.Repeat("0", 64))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 400 || !strings.Contains(w.Body.String(), "invalid_processing_catalog") {
			t.Fatal("bad catalog selector reached database or another control", w.Code)
		}
	}
}
