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
}
