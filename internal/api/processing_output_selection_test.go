package api

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ctlplne/freightctl/internal/custody"
)

func TestProcessingOutputMetadataSelectionRefusesAmbiguousQueriesBeforeDatabase(t *testing.T) {
	h := New(&custody.Service{}, nil)
	base := "https://freightctl.invalid/v1/tenants/11111111-1111-4111-8111-111111111111/partners/22222222-2222-4222-8222-222222222222/checks/33333333-3333-4333-8333-333333333333/processing-contracts?"
	id := "output_policy_id=44444444-4444-4444-8444-444444444444&output_policy_version=1&output_policy_hash="
	for _, query := range []string{"output_policy_id=missing", id + strings.Repeat("A", 64), id + strings.Repeat("a", 64) + "&output_policy_version=2", "producer_id=untrusted", "approved=true", strings.Repeat("x", 1025)} {
		r := httptest.NewRequest("GET", base+query, nil)
		r.Header.Set("Authorization", "Bearer "+strings.Repeat("0", 64))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatal("ambiguous output selection reached database", w.Code)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", base+"approved=true", nil))
	if w.Code != 401 {
		t.Fatal("metadata selection bypassed authentication", w.Code)
	}
}
