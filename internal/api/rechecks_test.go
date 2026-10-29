package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ctlplne/freightctl/internal/custody"
)

func TestRecheckRoutesRejectUntrustedExecutionAndCopyBodies(t *testing.T) {
	server := httptest.NewTLSServer(New(&custody.Service{}, nil))
	defer server.Close()
	prefix := "/v1/tenants/00000000-0000-0000-0000-000000000001/partners/00000000-0000-0000-0000-000000000002"
	for _, tc := range []struct{ route, body string }{
		{"/checks/00000000-0000-0000-0000-000000000003/recheck-preview", `{"force_clean":true}`},
		{"/checks/00000000-0000-0000-0000-000000000003/rechecks", `{"plan":{},"approved":true}`},
		{"/checks/00000000-0000-0000-0000-000000000003/rechecks", `{"plan":{},"plan":{}}`},
		{"/rechecks/00000000-0000-0000-0000-000000000003/decide", `{"operation":"approve","definition_hash":"x","run_shell":"x"}`},
		{"/rechecks/00000000-0000-0000-0000-000000000003/copy", `{}`},
		{"/rechecks/00000000-0000-0000-0000-000000000003/copy", strings.Repeat(" ", 33<<10)},
	} {
		req, err := http.NewRequest(http.MethodPost, server.URL+prefix+tc.route, strings.NewReader(tc.body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+strings.Repeat("0", 64))
		resp, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 400 {
			t.Fatal(tc.route, "untrusted command body accepted", resp.StatusCode)
		}
	}
}
