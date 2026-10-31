package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ctlplne/freightctl/internal/custody"
)

func TestArrivalAPIRejectsInventedObservationAndLeaseBeforeStorage(t *testing.T) {
	h := New(&custody.Service{}, nil)
	for _, action := range []string{"probe", "admit", "cancel"} {
		for _, body := range []string{`{"observed_at":"2030-01-01T00:00:00Z"}`, `{"manifest":{"schema_version":1}}`, `{"lease_until":"2030-01-01T00:00:00Z"}`, `{"definition_hash":"x","definition_hash":"y"}`, strings.Repeat(" ", 33<<10)} {
			r := httptest.NewRequest(http.MethodPost, "https://freightctl.invalid/v1/tenants/00000000-0000-0000-0000-000000000001/partners/00000000-0000-0000-0000-000000000002/workflow-schedule-arrivals/00000000-0000-0000-0000-000000000003/"+action, strings.NewReader(body))
			r.Header.Set("Authorization", "Bearer "+strings.Repeat("0", 64))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 400 {
				t.Fatalf("arrival %s accepted invented observation, lease or ambiguous input: %d", action, w.Code)
			}
		}
	}
}
