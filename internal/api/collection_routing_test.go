package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ctlplne/freightctl/internal/custody"
)

func TestCapturedRoutingAPIRejectsInventedPlansAndAuthorityBeforeStorage(t *testing.T) {
	h := New(&custody.Service{}, nil)
	job := "workflow-collections/00000000-0000-0000-0000-000000000003/routing"
	for _, route := range []string{job + "/preview", job + "/inputs/00000000-0000-0000-0000-000000000004/preview", job + "/proposals", job + "/00000000-0000-0000-0000-000000000005/approve", job + "/00000000-0000-0000-0000-000000000005/revoke", job + "/00000000-0000-0000-0000-000000000005/withdraw"} {
		for _, body := range []string{`{"approved":true}`, `{"extend_deadline":true}`, `{"facts":{"source":{"name":"invented.csv"}}}`, `{"inputs":[{"input_id":"invented","plan_hash":"invented"}]}`, `{"definition_hash":"first","definition_hash":"second"}`, strings.Repeat(" ", 33<<10)} {
			r := httptest.NewRequest(http.MethodPost, "https://freightctl.invalid/v1/tenants/00000000-0000-0000-0000-000000000001/partners/00000000-0000-0000-0000-000000000002/"+route, strings.NewReader(body))
			r.Header.Set("Authorization", "Bearer "+strings.Repeat("0", 64))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("routing must reject invented plans, cutoff or approval before database access: %s: %d", route, w.Code)
			}
		}
	}
	for _, query := range []string{"after=-1", "after=2147483648", "after=letters", "limit=0", "limit=101", "limit=99999999999999999999999"} {
		r := httptest.NewRequest(http.MethodGet, "https://freightctl.invalid/v1/tenants/00000000-0000-0000-0000-000000000001/partners/00000000-0000-0000-0000-000000000002/"+job+"?"+query, nil)
		r.Header.Set("Authorization", "Bearer "+strings.Repeat("0", 64))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("routing history must reject invalid or overflowing cursors: %s: %d", query, w.Code)
		}
	}
}
