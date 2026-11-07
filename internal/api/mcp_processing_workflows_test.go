package api

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/recordplan"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func processingMCPArguments(t *testing.T, name string) map[string]any {
	t.Helper()
	id := "11111111-1111-4111-8111-111111111111"
	hash := strings.Repeat("a", 64)
	if name == "freightctl.processing_contracts" {
		return map[string]any{"file_id": id}
	}
	if name == "freightctl.start_processing_workflow" {
		return map[string]any{"request": map[string]any{"workflow": map[string]any{"id": id, "version": 1, "hash": hash}, "file_id": id}, "request_key": "original-run"}
	}
	args := map[string]any{"run_id": id}
	if name != "freightctl.inspect_processing_workflow" {
		args["request_key"] = "original-action"
	}
	if name == "freightctl.cancel_processing_workflow" {
		args["request"] = map[string]any{"definition_hash": hash, "expected_revision": 1}
	}
	return args
}

func TestMCPProcessingContractsOptionalOutputReferenceRemainsClosedAndReadOnly(t *testing.T) {
	var tools []*mcp.Tool
	if json.Unmarshal(mcpCatalog, &tools) != nil {
		t.Fatal("catalog")
	}
	for _, tool := range tools {
		if tool.Name != "freightctl.processing_contracts" {
			continue
		}
		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
			t.Fatal("contract selection acquired an effect")
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
		args := processingMCPArguments(t, tool.Name)
		args["output_policy"] = map[string]any{"id": "22222222-2222-4222-8222-222222222222", "version": 1, "hash": strings.Repeat("a", 64)}
		if err = resolved.Validate(args); err != nil {
			t.Fatal("exact output reference rejected", err)
		}
		args["output_policy"].(map[string]any)["approved"] = true
		if resolved.Validate(args) == nil {
			t.Fatal("model supplied approval through output metadata")
		}
		return
	}
	t.Fatal("processing metadata tool missing")
}

func processingToolDefinition(t *testing.T) workflow.Definition {
	t.Helper()
	id := "11111111-1111-4111-8111-111111111111"
	hash := strings.Repeat("a", 64)
	d, err := workflow.Normalize(workflow.Definition{Schema: 3, Name: "PRIVATE_NAME", Processing: &workflow.ProcessingTask{ID: "private_step", Kind: "records.project", Definition: recordplan.Projection{Schema: 1, Kind: "record_projection", Engine: "freightctl-record-projection-v1", SourcePolicyHash: hash, OutputKind: "json_records", Columns: []recordplan.Column{{Source: "PRIVATE_COLUMN", Target: "account"}}, MaxBytes: 8192, MaxRecordBytes: 1024, MaxRows: 4, TimeoutSeconds: 2}, OutputPolicy: workflow.Reference{ID: id, Version: 2, Hash: hash}, Reason: "PRIVATE_REASON", TargetPath: "/PRIVATE_TARGET"}})
	if err != nil {
		t.Fatal(err)
	}
	return d
}
func TestMCPProcessingWorkflowMetadataRedactsBindingsAndKeepsOriginalVersusCurrent(t *testing.T) {
	id := "11111111-1111-4111-8111-111111111111"
	hash := strings.Repeat("a", 64)
	d := processingToolDefinition(t)
	wire, _ := json.Marshal(d)
	review, err := mcpWorkflowReview(&workflow.Preview{Definition: d, Hash: secure.Digest(wire), ApprovalRequired: true})
	if err != nil {
		t.Fatal(err)
	}
	r := &store.WorkflowRun{ID: id, WorkflowID: id, WorkflowVersion: 1, WorkflowHash: hash, FileID: id, Source: store.File{ID: id, Size: 16, SHA256: hash, Policy: store.CSVIntakePrefix + hash}, Root: "/PRIVATE_ROOT", StorageID: "PRIVATE_STORAGE", Reason: "PRIVATE_SERVER_ERROR", State: "queued", Revision: 1}
	raw, _ := json.Marshal(r)
	original, err := mcpProcessingAcceptance(&workflow.Result{Resource: raw, Replayed: true})
	if err != nil || original["current"] != "not-checked" || original["acceptance"] != "recorded-run-and-processing-intent-only" {
		t.Fatal("original acceptance was treated as processing or release", err)
	}
	v := &workflow.RunView{Run: r, ObservedState: "attention", ObservedReason: "output_held", Steps: []workflow.RunStepView{}, Processing: &workflow.ProcessingObservation{ID: id, Hash: hash, State: "completed", Revision: 3, Attempts: 1, FileID: id, Current: true}}
	current, err := mcpProcessingStatus(v, "current-observation")
	if err != nil {
		t.Fatal(err)
	}
	historical, err := mcpProcessingStatus(v, "original-command-receipt")
	if err != nil || historical["processing"].(map[string]any)["current"] != "not-checked" {
		t.Fatal("historical observation claimed current authority", err)
	}
	for _, value := range []any{review, original, current, historical} {
		encoded, _ := json.Marshal(value)
		if strings.Contains(string(encoded), "PRIVATE_") || strings.Contains(string(encoded), "private_step") || strings.Contains(string(encoded), "namespace_root\"") || strings.Contains(string(encoded), "definition\"") {
			t.Fatal("private definition or host binding entered model context")
		}
	}
	v.Steps = []workflow.RunStepView{{DeliveryID: id}}
	if _, err = mcpProcessingStatus(v, "current-observation"); err == nil {
		t.Fatal("delivery workflow reinterpreted as processing")
	}
}

func TestMCPProcessingWorkflowSchemasRequireExplicitTypedRulesAndRejectInjectedAuthority(t *testing.T) {
	var tools []*mcp.Tool
	_ = json.Unmarshal(mcpCatalog, &tools)
	for _, tool := range tools {
		if tool.Name != "freightctl.validate_workflow" && tool.Name != "freightctl.propose_workflow" {
			continue
		}
		wire, _ := json.Marshal(tool.InputSchema)
		var schema jsonschema.Schema
		_ = json.Unmarshal(wire, &schema)
		resolved, err := schema.Resolve(nil)
		if err != nil {
			t.Fatal(err)
		}
		definition := processingToolDefinition(t)
		raw, _ := json.Marshal(definition)
		var d map[string]any
		_ = json.Unmarshal(raw, &d)
		request := map[string]any{"definition": d}
		args := map[string]any{"request": request}
		if tool.Name == "freightctl.propose_workflow" {
			request["expected_version"] = 0
			args["request_key"] = "original-proposal"
		}
		valid, _ := json.Marshal(args)
		if _, err = decodeMCPToolArguments(valid, resolved); err != nil {
			t.Fatal("typed processing refused", tool.Name, err)
		}
		for _, mutate := range []func(map[string]any){func(d map[string]any) { d["approved"] = true }, func(d map[string]any) { d["steps"] = []any{map[string]any{"kind": "sftp.deliver"}} }, func(d map[string]any) { d["program"] = map[string]any{} }, func(d map[string]any) { d["processing"].(map[string]any)["release"] = true }, func(d map[string]any) {
			d["processing"].(map[string]any)["definition"].(map[string]any)["engine"] = "shell"
		}} {
			var changed map[string]any
			_ = json.Unmarshal(valid, &changed)
			mutate(changed["request"].(map[string]any)["definition"].(map[string]any))
			bad, _ := json.Marshal(changed)
			if _, err = decodeMCPToolArguments(bad, resolved); err == nil {
				t.Fatal("task acquired unreviewed execution or delivery authority", tool.Name)
			}
		}
	}
}

func TestMCPProcessingWorkflowCatalogKeepsApprovalReleaseAndOtherProfilesOutsideTools(t *testing.T) {
	var tools []*mcp.Tool
	if json.Unmarshal(mcpCatalog, &tools) != nil {
		t.Fatal("catalog")
	}
	want := map[string]bool{"freightctl.processing_contracts": true, "freightctl.start_processing_workflow": false, "freightctl.inspect_processing_workflow": true, "freightctl.work_processing_workflow": false, "freightctl.refresh_processing_workflow": false, "freightctl.cancel_processing_workflow": false}
	for _, tool := range tools {
		if tool.Name == "freightctl.approve_processing_workflow" || tool.Name == "freightctl.release_processing_output" {
			t.Fatal("model acquired approval or release")
		}
		if read, ok := want[tool.Name]; ok {
			if tool.Annotations == nil || tool.Annotations.ReadOnlyHint != read || !tool.Annotations.IdempotentHint {
				t.Fatal("processing effects misrepresented")
			}
			delete(want, tool.Name)
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing fixed processing workflow controls: %v", want)
	}
}

func TestMCPWorkflowValidationDoesNotDependOnReceiveAdapterConfiguration(t *testing.T) {
	s := &Server{Service: &custody.Service{}}
	if _, err := s.callMCPTool(context.Background(), store.Scope{}, "freightctl.validate_workflow", mcpToolArguments{Request: json.RawMessage(`{"definition":{"approved":true}}`)}); !errors.Is(err, workflow.ErrInput) {
		t.Fatal("ordinary workflow validation depended on an exchange adapter before typed rejection", err)
	}
}
