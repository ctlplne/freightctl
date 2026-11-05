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
	if err := json.Unmarshal(mcpCatalog, &tools); err != nil || len(tools) != 16 {
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
