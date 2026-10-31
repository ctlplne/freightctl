package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ctlplne/freightctl/internal/custody"
)

func TestScheduleAPIRejectsInventedAuthorityAndCalendarBeforeStorage(t *testing.T) {
	h := New(&custody.Service{}, nil)
	for _, route := range []string{"workflow-schedules/preview", "workflow-schedules/drafts", "workflow-schedules/00000000-0000-0000-0000-000000000003/1/activate", "workflow-schedules/00000000-0000-0000-0000-000000000003/1/tick"} {
		for _, body := range []string{`{"approved":true,"authority_revision":1}`, `{"clock_override":"2030-01-01T00:00:00Z"}`, `{"limit":1,"limit":100}`, strings.Repeat(" ", 33<<10)} {
			r := httptest.NewRequest(http.MethodPost, "https://freightctl.invalid/v1/tenants/00000000-0000-0000-0000-000000000001/partners/00000000-0000-0000-0000-000000000002/"+route, strings.NewReader(body))
			r.Header.Set("Authorization", "Bearer "+strings.Repeat("0", 64))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 400 {
				t.Fatalf("schedule must refuse invented authority/clock: %s: %d", route, w.Code)
			}
		}
	}
}
