package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ctlplne/freightctl/internal/custody"
)

// This exercises the real routing/decoder boundary without opening a listener
// or database. Client text cannot supply a receipt, endpoint or activation.
func TestOnboardingExchangeReviewRejectsClientInventedEvidence(t *testing.T) {
	handler := New(&custody.Service{}, nil)
	for _, body := range []string{`{"approved":true}`, `{"receipt":{"business_acceptance":"accepted"}}`, `{"endpoint":"https://untrusted.invalid","key_file":"/private"}`, `{"run_id":"x","run_id":"y"}`, strings.Repeat(" ", 33<<10)} {
		req := httptest.NewRequest(http.MethodPost, "https://freightctl.invalid/v1/tenants/00000000-0000-0000-0000-000000000001/partners/00000000-0000-0000-0000-000000000002/onboarding-exchange-review", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+strings.Repeat("0", 64))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		if response.Code != 400 {
			t.Fatalf("invented evidence must be rejected at the input boundary: status %d", response.Code)
		}
	}
}
