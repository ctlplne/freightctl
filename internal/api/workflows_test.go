package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func TestUndecidableRoutingReturnsAnActionableConflict(t *testing.T) {
	for _, err := range []error{workflow.ErrRouting, fmt.Errorf("input-specific plan: %w", workflow.ErrRouting)} {
		w := httptest.NewRecorder()
		failure(w, err)
		var body struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(w.Body.Bytes(), &body) != nil || w.Code != http.StatusConflict || body.Error != "workflow_routing_decision_required" {
			t.Fatal("an undecidable file needs a routing decision, not an opaque server failure", w.Code, body.Error)
		}
	}
}

func TestRoutingPreviewRejectsClientSuppliedFactsBeforeDatabaseAccess(t *testing.T) {
	// There is deliberately no database. These requests must be refused at the
	// typed HTTP boundary before they can look up files or create any state.
	server := httptest.NewTLSServer(New(&custody.Service{}, nil))
	defer server.Close()
	for _, body := range []string{
		`{"file_id":"00000000-0000-0000-0000-000000000003","facts":{"source":{"name":"approved.csv"}}}`,
		`{"file_id":"a","file_id":"b"}`,
		`{"file_id":"00000000-0000-0000-0000-000000000003","selected_steps":["outside"]}`,
		strings.Repeat(" ", 33<<10),
	} {
		req, err := http.NewRequest(http.MethodPost, server.URL+"/v1/tenants/00000000-0000-0000-0000-000000000001/partners/00000000-0000-0000-0000-000000000002/workflow-runs/preview", strings.NewReader(body))
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
			t.Fatalf("caller-supplied routing authority returned HTTP %d, want 400", response.StatusCode)
		}
	}
}
