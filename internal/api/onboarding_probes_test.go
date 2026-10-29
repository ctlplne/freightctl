package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ctlplne/freightctl/internal/custody"
)

func TestOnboardingProbeCannotChooseEndpointCredentialsOrInventResult(t *testing.T) {
	server := httptest.NewTLSServer(New(&custody.Service{}, nil))
	defer server.Close()
	for _, body := range []string{`{"endpoint":"https://untrusted.invalid"}`, `{"key_file":"/untrusted/private"}`, `{"succeeded":true,"approved":true}`, `{"plan":{},"plan":{}}`, strings.Repeat(" ", 33<<10)} {
		req, err := http.NewRequest(http.MethodPost, server.URL+"/v1/tenants/00000000-0000-0000-0000-000000000001/partners/00000000-0000-0000-0000-000000000002/onboarding-probes", strings.NewReader(body))
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
			t.Fatal("untrusted probe authority accepted", resp.StatusCode)
		}
	}
}
