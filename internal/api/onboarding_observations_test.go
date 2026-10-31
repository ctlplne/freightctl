package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ctlplne/freightctl/internal/custody"
)

func TestOnboardingObservationCannotInventReceiptsTrustOrResend(t *testing.T) {
	handler := New(&custody.Service{}, nil)
	for _, path := range []string{"onboarding-observations/preview", "onboarding-observations"} {
		for _, body := range []string{`{"endpoint":"https://untrusted.invalid"}`, `{"definition":{"succeeded":true,"resend":true}}`, `{"definition":{},"definition":{}}`, strings.Repeat(" ", 33<<10)} {
			req := httptest.NewRequest(http.MethodPost, "https://freightctl.invalid/v1/tenants/00000000-0000-0000-0000-000000000001/partners/00000000-0000-0000-0000-000000000002/"+path, strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+strings.Repeat("0", 64))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, req)
			if response.Code != 400 {
				t.Fatal("typed observation must refuse supplied trust/results at input boundary", path, response.Code)
			}
		}
	}
}
