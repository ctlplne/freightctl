package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ctlplne/freightctl/internal/custody"
)

func TestMalformedAssistanceInputReportsClientError(t *testing.T) {
	// No database/model is used: malformed input must fail before service access.
	server := httptest.NewTLSServer(New(&custody.Service{}, nil))
	defer server.Close()
	for _, body := range []string{`{"kind":"propose","approved":true}`, `{"kind":"propose","kind":"diagnose"}`, strings.Repeat(" ", 33<<10)} {
		req, err := http.NewRequest(http.MethodPost, server.URL+"/v1/tenants/00000000-0000-0000-0000-000000000001/partners/00000000-0000-0000-0000-000000000002/ai/jobs", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+strings.Repeat("0", 64))
		response, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != 400 {
			t.Fatalf("malformed input returned HTTP %d, want 400", response.StatusCode)
		}
	}
}
