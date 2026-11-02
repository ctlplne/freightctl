package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ctlplne/freightctl/internal/custody"
)

func TestCollectedHandoffAPIRejectsInventedPlansCutoffsApprovalsAndInvalidCursors(t *testing.T) {
	h := New(&custody.Service{}, nil)
	base := "https://freightctl.invalid/v1/tenants/00000000-0000-0000-0000-000000000001/partners/00000000-0000-0000-0000-000000000002/workflow-collections/00000000-0000-0000-0000-000000000003/handoffs"
	for _, suffix := range []string{"/preview", "/proposals", "/00000000-0000-0000-0000-000000000004/approve", "/00000000-0000-0000-0000-000000000004/cancel", "/00000000-0000-0000-0000-000000000004/execute"} {
		for _, body := range []string{`{"approved":true}`, `{"extend_deadline":true}`, `{"plan":{"selected_steps":["invented_recipient"]}}`, `{"facts":{"source":{"name":"invented.csv"}}}`, `{"definition_hash":"first","definition_hash":"second"}`, strings.Repeat(" ", 33<<10)} {
			r := httptest.NewRequest(http.MethodPost, base+suffix, strings.NewReader(body))
			r.Header.Set("Authorization", "Bearer "+strings.Repeat("0", 64))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("handoff admitted invented authority before storage: %s: %d", suffix, w.Code)
			}
		}
	}
	for _, query := range []string{"?after=invented", "?limit=0", "?limit=101", "?limit=wrong", "?limit=9999999999999999999999"} {
		r := httptest.NewRequest(http.MethodGet, base+query, nil)
		r.Header.Set("Authorization", "Bearer "+strings.Repeat("0", 64))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("handoff history admitted invalid cursor: %s: %d", query, w.Code)
		}
	}
}
