package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ctlplne/freightctl/internal/custody"
)

func TestOutboundDispatchApprovalRejectsInventedAuthorityAndEffects(t *testing.T) {
	h := New(&custody.Service{}, nil)
	for _, route := range []string{"outbound-dispatch-policy", "outbound-dispatch-reviews/preview", "outbound-dispatch-reviews", "outbound-dispatch-reviews/00000000-0000-0000-0000-000000000003/approve"} {
		for _, body := range []string{`{"approved":true,"reviewer_authority_revision":1}`, `{"snapshot":{"address":"untrusted.invalid:22"}}`, `{"mode":"independent","mode":"author"}`, strings.Repeat(" ", 33<<10)} {
			r := httptest.NewRequest(http.MethodPost, "https://freightctl.invalid/v1/tenants/00000000-0000-0000-0000-000000000001/partners/00000000-0000-0000-0000-000000000002/"+route, strings.NewReader(body))
			r.Header.Set("Authorization", "Bearer "+strings.Repeat("0", 64))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 400 {
				t.Fatalf("dispatch review must refuse invented authority/effects: %s: %d", route, w.Code)
			}
		}
	}
}
