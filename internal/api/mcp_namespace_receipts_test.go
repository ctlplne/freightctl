package api

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/ctlplne/freightctl/internal/store"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestMCPNamespaceReceiptKeepsMetadataOnlyInputAndHistoricalOutput(t *testing.T) {
	var catalog []*mcp.Tool
	if json.Unmarshal(mcpCatalog, &catalog) != nil {
		t.Fatal("catalog unavailable")
	}
	var tool *mcp.Tool
	for _, candidate := range catalog {
		if candidate.Name == "freightctl.namespace_receipt" {
			tool = candidate
		}
	}
	if tool == nil {
		t.Fatal("agent cannot recover its original private namespace receipt without executing a command")
	}
	if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint || tool.Annotations.DestructiveHint == nil || *tool.Annotations.DestructiveHint || !tool.Annotations.IdempotentHint || tool.Annotations.OpenWorldHint == nil || *tool.Annotations.OpenWorldHint {
		t.Fatal("receipt tool misstates effects")
	}
	raw, err := os.ReadFile("../../docs/api/namespace-receipts.openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Components struct {
			Schemas map[string]json.RawMessage `json:"schemas"`
		} `json:"components"`
	}
	if json.Unmarshal(raw, &document) != nil {
		t.Fatal("receipt contract unavailable")
	}
	var original, output map[string]any
	if json.Unmarshal(document.Components.Schemas["OriginalPathCommand"], &original) != nil || json.Unmarshal(document.Components.Schemas["PathCommandReceipt"], &output) != nil {
		t.Fatal("receipt types unavailable")
	}
	delete(original["properties"].(map[string]any), "property_changes")
	original["properties"].(map[string]any)["operation"].(map[string]any)["enum"] = []any{"mkdir", "publish", "copy", "rename", "remove", "rmdir", "setstat", "move_tree", "remove_tree", "copy_tree", "copy_dir"}
	wanted := map[string]any{"type": "object", "properties": map[string]any{"command": original, "request_key": map[string]any{"type": "string", "pattern": "^[A-Za-z0-9._:-]{1,128}$"}}, "required": []any{"command", "request_key"}, "additionalProperties": false}
	inputRaw, _ := json.Marshal(tool.InputSchema)
	outputRaw, _ := json.Marshal(tool.OutputSchema)
	var input, actualOutput map[string]any
	if json.Unmarshal(inputRaw, &input) != nil || json.Unmarshal(outputRaw, &actualOutput) != nil || !reflect.DeepEqual(input, wanted) || !reflect.DeepEqual(actualOutput, output) {
		t.Fatal("receipt MCP schema lost metadata-only typed binding or historical result constraints")
	}
	var schema jsonschema.Schema
	if json.Unmarshal(inputRaw, &schema) != nil {
		t.Fatal("receipt input unavailable")
	}
	resolved, err := schema.Resolve(nil)
	if err != nil {
		t.Fatal(err)
	}
	valid := []byte(`{"request_key":"original-delete","command":{"operation":"remove_tree","path":"/source","expected_entry_id":"10000000-1111-4111-8111-111111111111","expected_revision":1}}`)
	if _, err = decodeMCPToolArguments(valid, resolved); err != nil {
		t.Fatal("original metadata selection refused", err)
	}
	for _, bad := range []string{
		`{"request_key":"original-delete","command":{"operation":"remove_tree","path":"/source","property_changes":[]}}`,
		`{"request_key":"original-delete","command":{"operation":"properties","path":"/source"}}`,
		`{"request_key":"original-delete","command":{"operation":"remove_tree","path":"/source","tenant_id":"invented"}}`,
		`{"request_key":"original-delete","command":{"operation":"remove_tree","path":"/source"},"execute":true}`,
		`{"request_key":"original-delete","command":{"operation":"remove_tree","path":"/source","PATH":"/other"}}`,
	} {
		if _, err = decodeMCPToolArguments([]byte(bad), resolved); err == nil {
			t.Fatal("receipt tool admitted content,hidden authority or aliased metadata")
		}
	}
}

func TestMCPNamespaceReceiptRejectsContentAndMalformedControlBeforeService(t *testing.T) {
	for _, command := range []string{
		`null`,
		`{"operation":"properties","path":"/source"}`,
		`{"operation":"remove_tree","path":"/source","property_changes":null}`,
		`{"operation":"remove_tree","path":"/source","property_changes":[]}`,
		`{"operation":"remove_tree","path":"/source","path":"/other"}`,
		`{"operation":"remove_tree","path":"/source","execute":true}`,
		strings.Repeat(" ", 16<<10) + `{}`,
	} {
		_, err := (&Server{}).mcpNamespaceReceipt(context.Background(), store.Scope{}, mcpToolArguments{Key: "original", Command: json.RawMessage(command)})
		if !errors.Is(err, store.ErrExchangeInput) {
			t.Fatal("MCP receipt read reached service with content or malformed selection", err)
		}
	}
}
