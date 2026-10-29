package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ctlplne/freightctl/internal/custody"
)

func TestMalformedOnboardingCannotSelectAuthorityOrActivation(t *testing.T) {
	server := httptest.NewTLSServer(New(&custody.Service{}, nil))
	defer server.Close()
	for _, body := range []string{`{"approved":true,"active":true}`, `{"plan_id":"first","plan_id":"second"}`, `{"plan_id":"x","definition":{"endpoint":"https://untrusted.invalid"}}`, strings.Repeat(" ", 33<<10)} {
		req, err := http.NewRequest(http.MethodPost, server.URL+"/v1/tenants/00000000-0000-0000-0000-000000000001/partners/00000000-0000-0000-0000-000000000002/onboarding-plans", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+strings.Repeat("0", 64))
		response, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("malformed command returned %d, want 400", response.StatusCode)
		}
	}
}
