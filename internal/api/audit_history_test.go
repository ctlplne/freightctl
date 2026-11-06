package api

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ctlplne/freightctl/internal/custody"
)

func TestAuditHistoryRejectsRawPayloadAndAmbiguousSelectorsBeforeDatabase(t *testing.T) {
	h := New(&custody.Service{}, nil)
	url := "https://freightctl.invalid/v1/tenants/11111111-1111-4111-8111-111111111111/partners/22222222-2222-4222-8222-222222222222/audit/history/search"
	for _, body := range []string{`null`, `{"limit":0}`, `{"limit":101}`, `{"limit":10,"include_payload":true}`, `{"limit":10,"actor_id":"not-an-id"}`, `{"limit":10,"limit":20}`, `{"limit":10,"LIMIT":20}`, `{"limit":10,"from":"2026-11-05T00:00:00.0000001Z"}`, strings.Repeat(" ", 8193)} {
		r := httptest.NewRequest("POST", url, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+strings.Repeat("0", 64))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatalf("history control reached storage or missing route: %d", w.Code)
		}
	}
}
