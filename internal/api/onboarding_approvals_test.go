package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ctlplne/freightctl/internal/custody"
)

func TestOnboardingApprovalRejectsInventedAuthorityAndDisclosure(t *testing.T) {
	h := New(&custody.Service{}, nil)
	for _, path := range []string{"onboarding-approval-policy", "onboarding-approval-reviews/preview", "onboarding-approval-reviews", "onboarding-approval-reviews/00000000-0000-0000-0000-000000000003/approve"} {
		for _, body := range []string{`{"approved":true,"reviewer_authority_revision":1}`, `{"snapshot":{"recipient":"untrusted.invalid"}}`, `{"mode":"independent","mode":"author"}`, strings.Repeat(" ", 33<<10)} {
			r := httptest.NewRequest(http.MethodPost, "https://freightctl.invalid/v1/tenants/00000000-0000-0000-0000-000000000001/partners/00000000-0000-0000-0000-000000000002/"+path, strings.NewReader(body))
			r.Header.Set("Authorization", "Bearer "+strings.Repeat("0", 64))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 400 {
				t.Fatalf("approval boundary must reject invented authority/disclosure: %s: %d", path, w.Code)
			}
		}
	}
}
