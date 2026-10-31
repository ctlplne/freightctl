package api

import (
	"github.com/ctlplne/freightctl/internal/custody"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOnboardingTestCannotInventRecipientsEvidenceOrApproval(t *testing.T) {
	handler := New(&custody.Service{}, nil)
	for _, path := range []string{"onboarding-tests/preview", "onboarding-tests"} {
		for _, body := range []string{`{"endpoint":"https://untrusted.invalid"}`, `{"definition":{"approved":true,"succeeded":true}}`, `{"definition":{},"definition":{}}`, strings.Repeat(" ", 33<<10)} {
			req := httptest.NewRequest(http.MethodPost, "https://freightctl.invalid/v1/tenants/00000000-0000-0000-0000-000000000001/partners/00000000-0000-0000-0000-000000000002/"+path, strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+strings.Repeat("0", 64))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, req)
			if response.Code != 400 {
				t.Fatal("typed test intent must refuse invented authority at input boundary", path, response.Code)
			}
		}
	}
}
