package api

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func proposalMCPArguments(t *testing.T, name string) map[string]any {
	t.Helper()
	id := "11111111-1111-4111-8111-111111111111"
	if name == "freightctl.list_processing_proposals" {
		return map[string]any{"limit": 1}
	}
	if name == "freightctl.inspect_processing_proposal" {
		return map[string]any{"proposal_id": id}
	}
	if name == "freightctl.propose_processing_definition" {
		raw, err := os.ReadFile("../../web/tests/fixtures/processing-workflow.json")
		if err != nil {
			t.Fatal(err)
		}
		var fixture struct {
			Definition any `json:"definition"`
		}
		if json.Unmarshal(raw, &fixture) != nil {
			t.Fatal("fixture")
		}
		return map[string]any{"request_key": "original-proposal", "request": map[string]any{"executor_id": id, "definition": fixture.Definition, "expires_at": "2026-12-01T00:00:00Z"}}
	}
	args := map[string]any{"proposal_id": id, "request_key": "original-decision", "request": map[string]any{"definition_hash": strings.Repeat("a", 64), "expected_revision": 1}}
	if name == "freightctl.close_processing_proposal" {
		args["action"] = "withdraw"
	}
	return args
}

func TestMCPProcessingProposalsBindOrdinaryMetadataAndNeverExposeApproval(t *testing.T) {
	wanted := map[string]bool{"freightctl.propose_processing_definition": false, "freightctl.list_processing_proposals": true, "freightctl.inspect_processing_proposal": true, "freightctl.adopt_processing_proposal": false, "freightctl.close_processing_proposal": false}
	var catalog []*mcp.Tool
	if json.Unmarshal(mcpCatalog, &catalog) != nil {
		t.Fatal("catalog")
	}
	seen := map[string]bool{}
	for _, tool := range catalog {
		read, ok := wanted[tool.Name]
		if !ok {
			continue
		}
		seen[tool.Name] = true
		if tool.Annotations == nil || tool.Annotations.ReadOnlyHint != read || tool.Annotations.OpenWorldHint == nil || *tool.Annotations.OpenWorldHint {
			t.Fatal("proposal tool misrepresented effect", tool.Name)
		}
		raw, _ := json.Marshal(tool.InputSchema)
		var schema jsonschema.Schema
		if json.Unmarshal(raw, &schema) != nil {
			t.Fatal("schema")
		}
		resolved, err := schema.Resolve(nil)
		if err != nil {
			t.Fatal(err)
		}
		args := proposalMCPArguments(t, tool.Name)
		if err := resolved.Validate(args); err != nil {
			t.Fatal("ordinary proposal metadata refused", tool.Name, err)
		}
		for _, field := range []string{"approved", "author", "actor_id", "credentials", "bytes", "execute", "tenant_id"} {
			args[field] = true
			if resolved.Validate(args) == nil {
				t.Fatal("proposal tool accepted ambient authority", tool.Name, field)
			}
			delete(args, field)
		}
		if tool.Name == "freightctl.close_processing_proposal" {
			args["action"] = "approve"
			if resolved.Validate(args) == nil {
				t.Fatal("proposal tool became an approval")
			}
		}
	}
	if len(seen) != len(wanted) {
		t.Fatal("missing independent definition proposal tools", seen)
	}
}
