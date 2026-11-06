package api

import (
	"encoding/json"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestMCPCopyIsSeparateWriteWithoutOverwriteOrExecutionAuthority(t *testing.T) {
	var tools []*mcp.Tool
	if json.Unmarshal(mcpCatalog, &tools) != nil {
		t.Fatal("catalog decode")
	}
	for _, tool := range tools {
		if tool.Name != "freightctl.copy_received_artifact" {
			continue
		}
		if tool.Annotations == nil || tool.Annotations.ReadOnlyHint || !tool.Annotations.IdempotentHint || tool.Annotations.OpenWorldHint == nil || *tool.Annotations.OpenWorldHint {
			t.Fatal("copy misrepresented writes or external effects")
		}
		wire, _ := json.Marshal(tool.InputSchema)
		var schema jsonschema.Schema
		if json.Unmarshal(wire, &schema) != nil {
			t.Fatal("schema decode")
		}
		resolved, err := schema.Resolve(nil)
		if err != nil {
			t.Fatal(err)
		}
		var request map[string]any
		if json.Unmarshal([]byte(`{"exchange_id":"11111111-1111-4111-8111-111111111111","request_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","artifact":{"file_revision_id":"22222222-2222-4222-8222-222222222222","size_bytes":8,"sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","acceptance_policy":"integrity-only-v1"},"virtual_path":"/new.dat"}`), &request) != nil {
			t.Fatal("fixture")
		}
		args := map[string]any{"request": request, "request_key": "original-copy"}
		if resolved.Validate(args) != nil {
			t.Fatal("ordinary exact copy refused")
		}
		for _, field := range []string{"overwrite", "mode", "actor_id", "root", "url", "credentials", "execute", "content", "bytes"} {
			request[field] = "untrusted"
			if resolved.Validate(args) == nil {
				t.Fatal("copy accepted extra authority", field)
			}
			delete(request, field)
		}
		return
	}
	t.Fatal("missing separately authorized received-copy tool")
}
