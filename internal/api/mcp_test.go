package api

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/freightctl/internal/custody"
)

func TestMCPRejectsAmbiguousEnvelopeBeforeDatabase(t *testing.T) {
	h := New(&custody.Service{MaxFile: 1024, Exchanges: custody.ExchangeSettings{MaxLifetime: time.Hour, MaxSenders: 16, MaxOpenViews: 128, MaxEndpoints: 16}}, nil)
	for _, body := range []string{`{}`, `null`, `[]`, `{"jsonrpc":"2.0","jsonrpc":"1.0"}`, `{"jsonrpc":"2.0","JSONRPC":"1.0"}`, `{"sender_actor_id":"invented"}`, strings.Repeat(" ", 32769)} {
		r := httptest.NewRequest("POST", "https://freightctl.invalid/v1/tenants/11111111-1111-4111-8111-111111111111/partners/22222222-2222-4222-8222-222222222222/mcp", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+strings.Repeat("0", 64))
		r.Header.Set("Accept", "application/json, text/event-stream")
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("MCP-Protocol-Version", "2026-07-28")
		r.Header.Set("Mcp-Method", "tools/list")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatalf("MCP malformed authority reached database or missing route: %d", w.Code)
		}
	}
}

func TestMCPControlEnvelopeKeepsNestedMeaningAndExactIDs(t *testing.T) {
	valid := `{"jsonrpc":"2.0","id":"review-1","method":"tools/call","params":{"name":"freightctl.identity","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`
	request := httptest.NewRequest("POST", "https://freightctl.invalid/mcp", nil)
	if _, err := inspectMCPEnvelope(request, []byte(valid)); err != nil {
		t.Fatal("valid modern envelope refused")
	}
	for _, raw := range []string{
		strings.Replace(valid, `"arguments":{}`, `"arguments":{"request":{"recipient":"one","RECIPIENT":"two"}}`, 1),
		strings.Replace(valid, `"id":"review-1"`, `"id":1.1`, 1), strings.Replace(valid, `"id":"review-1"`, `"id":9007199254740992`, 1),
		strings.Replace(valid, `"arguments":{}`, `"arguments":null`, 1), strings.Replace(valid, `"arguments":{}`, `"arguments":{},"tenant_id":"invented"`, 1),
		valid + `{}`, strings.Replace(valid, `"arguments":{}`, `"arguments":`+strings.Repeat(`[`, 17)+`0`+strings.Repeat(`]`, 17), 1),
	} {
		if _, err := inspectMCPEnvelope(request, []byte(raw)); err == nil {
			t.Fatal("ambiguous or privilege-bearing envelope accepted")
		}
	}
}

func TestMCPMediaOriginAndHeaderAmbiguityRefuseBeforeDatabase(t *testing.T) {
	h := New(&custody.Service{MaxFile: 1024, Exchanges: custody.ExchangeSettings{MaxLifetime: time.Hour, MaxSenders: 16, MaxOpenViews: 128, MaxEndpoints: 16}}, nil)
	for _, change := range []func(*http.Request){
		func(r *http.Request) { r.Header.Set("Origin", "https://untrusted.invalid") },
		func(r *http.Request) {
			r.Header.Add("Origin", "https://freightctl.invalid")
			r.Header.Add("Origin", "https://untrusted.invalid")
		},
		func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") },
		func(r *http.Request) { r.Header.Set("Accept", "application/json") },
		func(r *http.Request) { r.Header.Add("MCP-Protocol-Version", "2025-11-25") },
		func(r *http.Request) { r.Header.Set("Mcp-Session-Id", "untrusted-session") },
	} {
		r := httptest.NewRequest("POST", "https://freightctl.invalid/v1/tenants/11111111-1111-4111-8111-111111111111/partners/22222222-2222-4222-8222-222222222222/mcp", strings.NewReader(`{}`))
		r.Header.Set("Authorization", "Bearer "+strings.Repeat("0", 64))
		r.Header.Set("Accept", "application/json, text/event-stream")
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("MCP-Protocol-Version", mcpProtocolVersion)
		r.Header.Set("Mcp-Method", "tools/list")
		change(r)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 400 && w.Code != 403 {
			t.Fatal("MCP transport guard failed", w.Code)
		}
	}
}

func TestMCPToolSchemasBindOrdinaryRequestsAndExcludeAmbientAuthority(t *testing.T) {
	var tools []*mcp.Tool
	if err := json.Unmarshal(mcpCatalog, &tools); err != nil || len(tools) != 43 {
		t.Fatal("missing fixed tool catalog", err)
	}
	raw, err := os.ReadFile("../../web/tests/fixtures/artifact-exchange.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Request json.RawMessage `json:"request"`
		Hash    string          `json:"sha256"`
		Closure json.RawMessage `json:"closure"`
	}
	if json.Unmarshal(raw, &fixture) != nil {
		t.Fatal("fixture decode")
	}
	seen := map[string]bool{}
	for _, tool := range tools {
		if seen[tool.Name] || tool.Annotations == nil || tool.Annotations.OpenWorldHint == nil || *tool.Annotations.OpenWorldHint != (tool.Name == "freightctl.work_onward") {
			t.Fatal("unsafe/duplicate tool metadata")
		}
		seen[tool.Name] = true
		wire, _ := json.Marshal(tool.InputSchema)
		var schema jsonschema.Schema
		if json.Unmarshal(wire, &schema) != nil {
			t.Fatal("schema decode")
		}
		resolved, err := schema.Resolve(nil)
		if err != nil {
			t.Fatal("schema resolution", err)
		}
		var args map[string]any
		switch tool.Name {
		case "freightctl.propose_processing_definition", "freightctl.list_processing_proposals", "freightctl.inspect_processing_proposal", "freightctl.adopt_processing_proposal", "freightctl.close_processing_proposal":
			args = proposalMCPArguments(t, tool.Name)
		case "freightctl.list_processing_workflows":
			args = map[string]any{"limit": 1}
		case "freightctl.processing_contracts", "freightctl.start_processing_workflow", "freightctl.inspect_processing_workflow", "freightctl.work_processing_workflow", "freightctl.refresh_processing_workflow", "freightctl.cancel_processing_workflow":
			args = processingMCPArguments(t, tool.Name)
		case "freightctl.preview_record_projection", "freightctl.propose_record_projection", "freightctl.inspect_record_projection", "freightctl.start_record_projection", "freightctl.work_record_projection":
			args = projectionMCPArguments(t, tool.Name)
		case "freightctl.copy_received_artifact":
			args = map[string]any{"request": map[string]any{"exchange_id": "44444444-4444-4444-8444-444444444444", "request_hash": fixture.Hash, "artifact": map[string]any{"file_revision_id": "55555555-5555-4555-8555-555555555555", "size_bytes": 8, "sha256": fixture.Hash, "acceptance_policy": "integrity-only-v1"}, "virtual_path": "/new.dat"}, "request_key": "original-copy"}
		case "freightctl.exchange_trace":
			args = map[string]any{"exchange_id": "55555555-5555-4555-8555-555555555555", "direction": "incoming"}
		case "freightctl.validate_workflow", "freightctl.propose_workflow":
			request := map[string]any{"definition": map[string]any{"schema_version": 1, "name": "Reviewed draft", "steps": []any{map[string]any{"id": "send", "kind": "sftp.deliver", "connection": map[string]any{"id": "55555555-5555-4555-8555-555555555555", "version": 1, "hash": fixture.Hash}, "filename": "new.dat"}}}}
			args = map[string]any{"request": request}
			if tool.Name == "freightctl.propose_workflow" {
				request["expected_version"] = 0
				args["request_key"] = "original-draft"
			}
		case "freightctl.artifact_upload_start":
			args = map[string]any{"virtual_path": "/new.dat", "size_bytes": 8, "sha256": fixture.Hash, "request_key": "stable-create"}
		case "freightctl.artifact_upload_status", "freightctl.artifact_upload_complete", "freightctl.artifact_upload_abort":
			args = map[string]any{"upload_id": "55555555-5555-4555-8555-555555555555"}
			if tool.Name != "freightctl.artifact_upload_status" {
				args["request_key"] = "stable-action"
			}
		case "freightctl.artifact_ingress_descriptor":
			args = map[string]any{"size_bytes": 8, "sha256": fixture.Hash, "request_key": "original-upload-key"}
		case "freightctl.collection_source":
			args = map[string]any{"collection_id": "44444444-4444-4444-8444-444444444444", "input_id": "55555555-5555-4555-8555-555555555555"}

		case "freightctl.prepare_onward", "freightctl.start_onward":
			args = map[string]any{"request": map[string]any{"schema_version": 1, "profile": "ordered-workflow-onward-v1", "workflow": map[string]any{"id": "44444444-4444-4444-8444-444444444444", "version": 1, "hash": fixture.Hash}, "artifact": map[string]any{"file_revision_id": "55555555-5555-4555-8555-555555555555", "size_bytes": 8, "sha256": fixture.Hash, "acceptance_policy": "integrity-only-v1"}}}
			if tool.Name == "freightctl.start_onward" {
				args["review_hash"] = fixture.Hash
				args["request_key"] = "original-key"
			}
		case "freightctl.onward_status", "freightctl.work_onward":
			args = map[string]any{"run_id": "55555555-5555-4555-8555-555555555555"}
			if tool.Name == "freightctl.work_onward" {
				args["request_key"] = "original-key"
			}
			args["receipt_key"] = "original-start-key"
			args["start"] = map[string]any{"review_hash": fixture.Hash, "request": map[string]any{"schema_version": 1, "profile": "ordered-workflow-onward-v1", "workflow": map[string]any{"id": "44444444-4444-4444-8444-444444444444", "version": 1, "hash": fixture.Hash}, "artifact": map[string]any{"file_revision_id": "55555555-5555-4555-8555-555555555555", "size_bytes": 8, "sha256": fixture.Hash, "acceptance_policy": "integrity-only-v1"}}}

		case "freightctl.prepare_exchange":
			args = map[string]any{"request": json.RawMessage(fixture.Request)}
		case "freightctl.offer_exchange":
			args = map[string]any{"request": json.RawMessage(fixture.Request), "request_hash": fixture.Hash, "request_key": "original-key"}
		case "freightctl.close_exchange":
			args = map[string]any{"command": fixture.Closure, "request_key": "original-key"}
		case "freightctl.exchange_source":
			args = map[string]any{"file_id": "55555555-5555-4555-8555-555555555555"}
		case "freightctl.exchange_endpoint", "freightctl.incoming_exchanges":
			args = map[string]any{"endpoint_id": "44444444-4444-4444-8444-444444444444"}
		case "freightctl.inspect_exchange", "freightctl.retrieval_descriptor", "freightctl.exchange_receipt":
			args = map[string]any{"exchange_id": "55555555-5555-4555-8555-555555555555"}
		default:
			args = map[string]any{}
		}
		encoded, _ := json.Marshal(args)
		if _, err := decodeMCPToolArguments(encoded, resolved); err != nil {
			t.Fatal("ordinary fixture refused by declared tool schema", tool.Name, err)
		}
		for _, field := range []string{"tenant_id", "sender_actor_id", "approved", "credentials", "url", "execute"} {
			args[field] = "untrusted"
			encoded, _ = json.Marshal(args)
			if _, err := decodeMCPToolArguments(encoded, resolved); err == nil {
				t.Fatal("tool accepted ambient authority", tool.Name, field)
			}
			delete(args, field)
		}
	}
}

func TestMCPResumableArtifactControlsExposeOnlyOwnedMetadataOperations(t *testing.T) {
	var tools []*mcp.Tool
	if json.Unmarshal(mcpCatalog, &tools) != nil {
		t.Fatal("catalog decode")
	}
	wanted := map[string]bool{"freightctl.artifact_upload_start": false, "freightctl.artifact_upload_status": false, "freightctl.artifact_upload_complete": false, "freightctl.artifact_upload_abort": false}
	for _, tool := range tools {
		if _, ok := wanted[tool.Name]; !ok {
			continue
		}
		wanted[tool.Name] = true
		if tool.Annotations == nil || tool.Annotations.ReadOnlyHint != (tool.Name == "freightctl.artifact_upload_status") || tool.Annotations.OpenWorldHint == nil || *tool.Annotations.OpenWorldHint {
			t.Fatal("upload control misrepresented its effects", tool.Name)
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
		args := map[string]any{"upload_id": "55555555-5555-4555-8555-555555555555"}
		if tool.Name == "freightctl.artifact_upload_start" {
			args = map[string]any{"virtual_path": "/new.dat", "size_bytes": 8, "sha256": strings.Repeat("a", 64), "request_key": "stable-create"}
		} else if tool.Name != "freightctl.artifact_upload_status" {
			args["request_key"] = "stable-action"
		}
		if resolved.Validate(args) != nil {
			t.Fatal("valid metadata refused", tool.Name)
		}
		for _, field := range []string{"bytes", "content", "host_path", "url", "expected_revision", "mode", "actor_id", "credentials", "root", "execute"} {
			args[field] = "untrusted"
			if resolved.Validate(args) == nil {
				t.Fatal("upload accepted extra authority/content", tool.Name, field)
			}
			delete(args, field)
		}
	}
	for name, found := range wanted {
		if !found {
			t.Error("missing resumable artifact metadata tool", name)
		}
	}
}

func TestMCPWorkflowReviewAndProposalDoNotSupplyApprovalOrExecution(t *testing.T) {
	var tools []*mcp.Tool
	if json.Unmarshal(mcpCatalog, &tools) != nil {
		t.Fatal("catalog decode")
	}
	for _, name := range []string{"freightctl.validate_workflow", "freightctl.propose_workflow"} {
		found := false
		for _, tool := range tools {
			if tool.Name != name {
				continue
			}
			found = true
			if tool.Annotations == nil || tool.Annotations.ReadOnlyHint != (name == "freightctl.validate_workflow") || tool.Annotations.OpenWorldHint == nil || *tool.Annotations.OpenWorldHint {
				t.Fatal("proposal/validation overstated safety", name)
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
			definition := map[string]any{"schema_version": 1, "name": "Reviewed draft", "steps": []any{map[string]any{"id": "send", "kind": "sftp.deliver", "connection": map[string]any{"id": "55555555-5555-4555-8555-555555555555", "version": 1, "hash": strings.Repeat("a", 64)}, "filename": "new.dat"}}}
			request := map[string]any{"definition": definition}
			args := map[string]any{"request": request}
			if name == "freightctl.propose_workflow" {
				request["expected_version"] = 0
				args["request_key"] = "original-draft"
			}
			encoded, _ := json.Marshal(args)
			if _, err := decodeMCPToolArguments(encoded, resolved); err != nil {
				t.Fatal("ordinary typed workflow refused", name, err)
			}
			for _, field := range []string{"approved", "execute", "actor_id", "credentials", "tenant_id"} {
				request[field] = "untrusted"
				encoded, _ = json.Marshal(args)
				if _, err := decodeMCPToolArguments(encoded, resolved); err == nil {
					t.Fatal("proposal accepted authority", name, field)
				}
				delete(request, field)
			}
			definition["shell"] = "untrusted"
			encoded, _ = json.Marshal(args)
			if _, err := decodeMCPToolArguments(encoded, resolved); err == nil {
				t.Fatal("definition accepted executable extension", name)
			}
			delete(definition, "shell")
			definition["schema_version"] = 2
			number := map[string]any{"op": "ge", "field": "file.size_bytes", "number": "0"}
			definition["program"] = map[string]any{"nodes": []any{map[string]any{"kind": "if", "when": map[string]any{"op": "all", "all": []any{number}}, "then": []any{map[string]any{"kind": "deliver", "step": "send"}}, "else": []any{map[string]any{"kind": "keep_local", "reason": "unmatched"}}}}}
			encoded, _ = json.Marshal(args)
			if _, err := decodeMCPToolArguments(encoded, resolved); err != nil {
				t.Fatal("recursive typed condition or exact quoted zero refused", name, err, resolved.Validate(args), strictMCPJSON(encoded))
			}
			definitionRaw, _ := json.Marshal(definition)
			var typed workflow.Definition
			if workflow.Decode(definitionRaw, &typed) != nil {
				t.Fatal("typed condition decode")
			}
			if _, err := workflow.Normalize(typed); err != nil {
				t.Fatal("positive recursive condition was not a valid ordinary workflow", err)
			}
			number["number"] = 0
			encoded, _ = json.Marshal(args)
			if _, err := decodeMCPToolArguments(encoded, resolved); err == nil {
				t.Fatal("quoted integer contract weakened", name)
			}
		}
		if !found {
			t.Error("missing ordinary workflow tool", name)
		}
	}
}

func TestMCPOfferHashAndClosureMeaningRefuseBeforeDatabase(t *testing.T) {
	raw, err := os.ReadFile("../../web/tests/fixtures/artifact-exchange.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Request json.RawMessage `json:"request"`
		Hash    string          `json:"sha256"`
	}
	if json.Unmarshal(raw, &fixture) != nil {
		t.Fatal("fixture decode")
	}
	server := &Server{Service: &custody.Service{MaxFile: 1024, Exchanges: custody.ExchangeSettings{MaxLifetime: time.Hour, MaxSenders: 16, MaxOpenViews: 128, MaxEndpoints: 16}}}
	_, err = server.callMCPTool(context.Background(), store.Scope{}, "freightctl.offer_exchange", mcpToolArguments{Request: fixture.Request, Hash: strings.Repeat("f", 64), Key: "original-key"})
	if !errors.Is(err, store.ErrRevision) {
		t.Fatal("changed preparation hash reached database")
	}
	_, err = server.callMCPTool(context.Background(), store.Scope{}, "freightctl.offer_exchange", mcpToolArguments{Request: fixture.Request, Hash: fixture.Hash, Key: "invalid key"})
	if !errors.Is(err, store.ErrExchangeInput) {
		t.Fatal("invalid operation key reached database")
	}
	_, err = server.callMCPTool(context.Background(), store.Scope{}, "freightctl.close_exchange", mcpToolArguments{Command: json.RawMessage(`{"operation":"cancel","approved":true}`), Key: "original-key"})
	if !errors.Is(err, store.ErrExchangeInput) {
		t.Fatal("invented closure authority reached database")
	}
}

func TestMCPEvidenceRejectsDirectionAuthorityBeforeDatabase(t *testing.T) {
	s := &Server{Service: &custody.Service{MaxFile: 1024, Exchanges: custody.ExchangeSettings{MaxLifetime: time.Hour, MaxSenders: 16, MaxOpenViews: 128, MaxEndpoints: 16}}}
	for _, args := range []mcpToolArguments{{Exchange: "33333333-3333-4333-8333-333333333333", Direction: "admin"}, {Exchange: "not-an-id", Direction: "incoming"}, {Exchange: "33333333-3333-4333-8333-333333333333"}} {
		if _, err := s.callMCPTool(context.Background(), store.Scope{}, "freightctl.exchange_trace", args); !errors.Is(err, store.ErrExchangeInput) {
			t.Fatal("tool reached database with unapproved direction/identity", err)
		}
	}
}

func TestMCPOnwardProjectionKeepsTransportReferencesAndRawObservationsOutOfContext(t *testing.T) {
	run := &store.WorkflowRun{ID: "11111111-1111-4111-8111-111111111111", WorkflowID: "22222222-2222-4222-8222-222222222222", WorkflowVersion: 1, WorkflowHash: strings.Repeat("a", 64), FileID: "33333333-3333-4333-8333-333333333333", Source: store.File{ID: "33333333-3333-4333-8333-333333333333", Size: 3, SHA256: strings.Repeat("b", 64), Policy: "integrity-only-v1"}, Root: "/private/partner", StorageID: "private-storage-reference", State: "ready", Reason: "private-receiver-error", Plan: json.RawMessage(`{"extracted_text":"private-file-contents"}`)}
	raw, _ := json.Marshal(workflow.OnwardRunReceipt{WorkflowRun: *run, Profile: workflow.OnwardProfile, ReviewHash: strings.Repeat("c", 64), WorkflowRevision: 2})
	acceptance, err := mcpOnwardAcceptance(&workflow.Result{Resource: raw, Replayed: true})
	if err != nil {
		t.Fatal(err)
	}
	status, err := mcpOnwardStatus(&workflow.RunView{Run: run, ObservedState: "succeeded", ObservedReason: "private-server-banner", Steps: []workflow.RunStepView{{ID: "private-business-step-name", Ordinal: 1, DeliveryID: "44444444-4444-4444-8444-444444444444", State: "succeeded", Observation: json.RawMessage(`{"password":"private-password","path":"/private/remote","business_acceptance":"accepted"}`)}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []map[string]any{acceptance, status} {
		encoded, _ := json.Marshal(value)
		if strings.Contains(string(encoded), "private-") || strings.Contains(string(encoded), "/private/") || value["receiver_persistence"] != "unknown" || value["business_processing"] != "unknown" {
			t.Fatal("MCP projected private bytes/references or upgraded receipt meaning")
		}
	}
	if acceptance["current_state"] != "not-checked" || acceptance["acceptance"] != "recorded-run-and-intents-only" || status["observed_state"] != "succeeded" {
		t.Fatal("historical acceptance confused current observations")
	}
}
