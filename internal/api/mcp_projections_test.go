package api

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ctlplne/freightctl/internal/checks"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func projectionMCPArguments(t *testing.T, name string) map[string]any {
	t.Helper()
	id := "11111111-1111-4111-8111-111111111111"
	hash := strings.Repeat("a", 64)
	if name == "freightctl.preview_record_projection" {
		return map[string]any{"file_id": id, "request": map[string]any{"profile": checks.ScopedProjectionProfile, "reason": "Review private deterministic processing", "definition": map[string]any{"schema_version": 1, "kind": "record_projection", "source_policy_hash": hash, "output_kind": "json_records", "columns": []any{map[string]any{"source": "account", "target": "account"}}}}}
	}
	if name == "freightctl.propose_record_projection" {
		args := projectionMCPArguments(t, "freightctl.preview_record_projection")
		args["request_key"] = "propose-original"
		args["review_hash"] = hash
		return args
	}
	a := map[string]any{"projection_id": id}
	if name == "freightctl.start_record_projection" {
		a["request_key"] = "start-original"
		a["request"] = map[string]any{"definition_hash": hash, "expected_revision": 2}
	}
	if name == "freightctl.work_record_projection" {
		a["request_key"] = "work-original"
		a["request"] = map[string]any{"projection_id": id, "attempt": 1, "worker_id": id}
	}
	return a
}

func TestMCPProjectionRepliesRedactPrivateBindingsAndSeparateHistoricalResults(t *testing.T) {
	id := "11111111-1111-4111-8111-111111111111"
	hash := strings.Repeat("a", 64)
	plan := checks.ProjectionPlan{Schema: 2, Profile: checks.ScopedProjectionProfile, Context: checks.RecheckPlan{Root: "/SYNTHETIC_PRIVATE_ROOT", Reason: "SYNTHETIC_PRIVATE_REASON", Source: checks.RecheckSource{File: store.File{ID: id, Size: 50, SHA256: hash, Policy: store.CSVIntakePrefix + hash}, Check: &checks.RecheckCheck{Binding: store.CheckBinding{Target: &store.PathCommand{Path: "/SYNTHETIC_PRIVATE_FILENAME"}}}}}}
	preview := &checks.ProjectionPreview{Plan: plan}
	metadata, err := mcpProjectionPreview(preview)
	if err != nil {
		t.Fatal(err)
	}
	def := checks.ProjectionDefinition{Schema: 1, Plan: plan, Slots: []string{"22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333", "44444444-4444-4444-8444-444444444444"}}
	wire, _ := json.Marshal(def)
	r := &store.RecordProjection{ID: id, SourceID: id, Hash: secure.Digest(wire), Definition: wire, State: "proposed", Revision: 1, Result: json.RawMessage(`{}`)}
	facts, err := mcpProjectionFacts(r, true, false, "original-command-receipt")
	if err != nil {
		t.Fatal(err)
	}
	if facts["current"] != "not-checked" || facts["observation"] != "original-command-receipt" {
		t.Fatal("historical receipt claimed current authority")
	}
	for _, value := range []any{metadata, facts} {
		out, _ := json.Marshal(value)
		for _, private := range []string{"SYNTHETIC_PRIVATE_ROOT", "SYNTHETIC_PRIVATE_REASON", "SYNTHETIC_PRIVATE_FILENAME", "staging_slots", "namespace_root\"", "definition\""} {
			if strings.Contains(string(out), private) {
				t.Fatal("private host binding entered model context")
			}
		}
	}
	r.Hash = strings.Repeat("b", 64)
	if _, err = mcpProjectionFacts(r, false, true, "current-observation"); err == nil {
		t.Fatal("corrupt private definition narrated as success")
	}
}

func TestMCPProjectionToolsKeepScopedPreparationApprovalAndExecutionSeparate(t *testing.T) {
	var tools []*mcp.Tool
	if json.Unmarshal(mcpCatalog, &tools) != nil {
		t.Fatal("catalog")
	}
	want := map[string]bool{"freightctl.preview_record_projection": true, "freightctl.propose_record_projection": false, "freightctl.inspect_record_projection": true, "freightctl.start_record_projection": false, "freightctl.work_record_projection": false}
	count := 0
	for _, tool := range tools {
		if tool.Name == "freightctl.approve_record_projection" || tool.Name == "freightctl.release_record_projection" {
			t.Fatal("model tool supplies approval or release")
		}
		read, ok := want[tool.Name]
		if !ok {
			continue
		}
		count++
		if tool.Annotations == nil || tool.Annotations.ReadOnlyHint != read || !tool.Annotations.IdempotentHint || tool.Annotations.DestructiveHint == nil || *tool.Annotations.DestructiveHint || tool.Annotations.OpenWorldHint == nil || *tool.Annotations.OpenWorldHint {
			t.Fatal("processing effects misrepresented")
		}
		wire, _ := json.Marshal(tool.InputSchema)
		var schema jsonschema.Schema
		if json.Unmarshal(wire, &schema) != nil {
			t.Fatal("schema")
		}
		resolved, err := schema.Resolve(nil)
		if err != nil {
			t.Fatal(err)
		}
		args := projectionMCPArguments(t, tool.Name)
		raw, _ := json.Marshal(args)
		if _, err := decodeMCPToolArguments(raw, resolved); err != nil {
			t.Fatal("ordinary scoped request rejected", tool.Name, err)
		}
		for _, field := range []string{"approved", "release", "credentials", "bytes", "content", "recipient", "actor_id", "namespace_root"} {
			args[field] = "untrusted"
			raw, _ = json.Marshal(args)
			if _, err := decodeMCPToolArguments(raw, resolved); err == nil {
				t.Fatal("tool accepted ambient authority or payload", tool.Name, field)
			}
			delete(args, field)
		}
		if tool.Name == "freightctl.preview_record_projection" {
			args["request"].(map[string]any)["profile"] = checks.ProjectionReviewProfile
			raw, _ = json.Marshal(args)
			if _, err := decodeMCPToolArguments(raw, resolved); err == nil {
				t.Fatal("model tool requested legacy root profile")
			}
		}
	}
	if count != 5 {
		t.Fatal("missing fixed scoped processing tools", count)
	}
}
