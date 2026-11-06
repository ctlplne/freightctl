package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ctlplne/freightctl/internal/custody"
)

func TestProjectionIntentRoutesRejectAuthorityInjectionAndWorkerSubstitution(t *testing.T) {
	s := New(&custody.Service{}, nil)
	prefix := "/v1/tenants/00000000-0000-0000-0000-000000000001/partners/00000000-0000-0000-0000-000000000002"
	id := "00000000-0000-0000-0000-000000000003"
	for _, c := range []struct{ path, body string }{
		{"/checks/" + id + "/projections", `{"plan":{},"approved":true}`},
		{"/projections/" + id + "/decide", `{"operation":"approve","force_clean":true}`},
		{"/projections/" + id + "/start", `{"worker_id":"chosen-by-client"}`},
		{"/projections/" + id + "/work", `{"projection_id":"00000000-0000-0000-0000-000000000004","attempt":1,"worker_id":"00000000-0000-0000-0000-000000000005"}`},
		{"/projections/" + id + "/work", `{"attempt":1,"attempt":2}`},
		{"/projections/" + id + "/work", `{"execute":"shell"}`},
	} {
		r := httptest.NewRequest(http.MethodPost, "https://freightctl.invalid"+prefix+c.path, strings.NewReader(c.body))
		r.Header.Set("Authorization", "Bearer "+strings.Repeat("0", 64))
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatalf("untrusted intent operation reached execution: %d", w.Code)
		}
	}
}
