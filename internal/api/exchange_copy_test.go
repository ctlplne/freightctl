package api

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/freightctl/internal/custody"
)

func TestReceivedCopyRefusesInventedAuthorityAndUnsafeDestinationBeforeDatabase(t *testing.T) {
	h := New(&custody.Service{MaxFile: 1024, Exchanges: custody.ExchangeSettings{MaxLifetime: time.Hour, MaxSenders: 16, MaxOpenViews: 128, MaxEndpoints: 16}}, nil)
	url := "https://freightctl.invalid/v1/tenants/11111111-1111-4111-8111-111111111111/partners/22222222-2222-4222-8222-222222222222/exchange-copies"
	valid := `{"exchange_id":"33333333-3333-4333-8333-333333333333","request_hash":"` + strings.Repeat("b", 64) + `","artifact":{"file_revision_id":"44444444-4444-4444-8444-444444444444","size_bytes":8,"sha256":"` + strings.Repeat("a", 64) + `","acceptance_policy":"integrity-only-v1"},"virtual_path":"/new.dat"}`
	for _, body := range []string{`null`, `{}`, strings.Replace(valid, `"/new.dat"`, `"/../escape"`, 1), strings.Replace(valid, `"/new.dat"`, `"/"`, 1), strings.TrimSuffix(valid, "}") + `,"overwrite":true}`, strings.TrimSuffix(valid, "}") + `,"actor_id":"invented"}`, strings.TrimSuffix(valid, "}") + `,"execute":true}`, strings.TrimSuffix(valid, "}") + `,"exchange_id":"55555555-5555-4555-8555-555555555555"}`, strings.Repeat(" ", 16385)} {
		r := httptest.NewRequest("POST", url, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+strings.Repeat("0", 64))
		r.Header.Set("Idempotency-Key", "stable-copy")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatalf("copy control reached storage or missing route: %d", w.Code)
		}
	}
}
