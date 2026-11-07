//go:build integration

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/freightctl/internal/checks"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestMCPStockClientTypedProcessingWorksWithoutReceiveAdapterAndKeepsApprovalOutsideTools(t *testing.T) {
	service, manager, admin, server := browserAPI(t, 600*time.Second)
	if _, _, err := service.ExchangeLimits(); err == nil {
		t.Fatal("fixture unexpectedly enabled receive adapter")
	}
	cookie, csrf := loginBrowser(t, server, manager, admin)
	prefix := "/v1/tenants/" + manager.Tenant + "/partners/" + manager.Partner
	token, _ := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "write", "check_run", "workflow_manage", "workflow_approve", "workflow_execute"})
	actor := store.Scope{Tenant: manager.Tenant, Partner: manager.Partner, TokenHash: secure.Digest(token.Bytes)}
	control := &checks.Service{Custody: service}
	policy, err := checks.Normalize(checks.Policy{Schema: 1, Kind: "csv", Columns: []checks.Column{{Name: "account", Type: "text", Required: true, MaxBytes: 32}}, MaxBytes: 8192, MaxRows: 4, MaxRecordBytes: 1024, TimeoutSeconds: 2})
	if err != nil {
		t.Fatal(err)
	}
	input, err := control.Register(t.Context(), manager, "tools-input-policy", checks.PolicyRequest{Definition: policy})
	if err != nil {
		t.Fatal(err)
	}
	var inputPolicy store.Configuration
	_ = json.Unmarshal(input.Resource, &inputPolicy)
	body := "account\n0001\n"
	source, _, err := service.Accept(t.Context(), actor, "tools-input", int64(len(body)), secure.Digest([]byte(body)), strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = control.Run(t.Context(), actor, source.ID, "tools-source-check"); err != nil {
		t.Fatal(err)
	}
	output := policy
	output.Schema = 2
	output.Kind = "json_records"
	registered, err := control.Register(t.Context(), manager, "tools-output-policy", checks.PolicyRequest{ExpectedVersion: 1, Definition: output})
	if err != nil {
		t.Fatal(err)
	}
	var outputPolicy store.Configuration
	_ = json.Unmarshal(registered.Resource, &outputPolicy)
	rules, err := checks.NormalizeRecordProjection(policy, checks.RecordProjection{Schema: 1, Kind: "record_projection", SourcePolicyHash: inputPolicy.Hash, OutputKind: "json_records", Columns: []checks.ProjectionColumn{{Source: "account", Target: "account"}}})
	if err != nil {
		t.Fatal(err)
	}
	definition := workflow.Definition{Schema: 3, Name: "PRIVATE_WORKFLOW_NAME", Processing: &workflow.ProcessingTask{ID: "project", Kind: "records.project", Definition: rules, OutputPolicy: workflow.Reference{ID: outputPolicy.ID, Version: outputPolicy.Version, Hash: outputPolicy.Hash}, Reason: "PRIVATE_PROCESSING_REASON"}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	httpClient := *server.Client()
	httpClient.Transport = mcpCredentialTransport{next: httpClient.Transport, token: token, origin: server.URL}
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client := mcp.NewClient(&mcp.Implementation{Name: "freightctl-typed-processing-stock-client", Version: "1"}, &mcp.ClientOptions{Capabilities: &mcp.ClientCapabilities{}})
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: server.URL + prefix + "/mcp", HTTPClient: &httpClient, MaxRetries: -1}, &mcp.ClientSessionOptions{ProtocolVersion: mcpProtocolVersion})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	call := func(name string, args map[string]any) map[string]any {
		t.Helper()
		reply, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "freightctl." + name, Arguments: args})
		if err != nil || reply.IsError {
			t.Fatal("stock typed processing call failed", name, err)
		}
		raw, err := json.Marshal(reply.StructuredContent)
		if err != nil || strings.Contains(string(raw), "PRIVATE_") || strings.Contains(string(raw), body) || strings.Contains(string(raw), "storage_id") || strings.Contains(string(raw), "staging_slots") || strings.Contains(string(raw), "namespace_root\"") {
			t.Fatal("private fields entered model context", err)
		}
		var value map[string]any
		if json.Unmarshal(raw, &value) != nil {
			t.Fatal("reply")
		}
		return value
	}
	described := call("processing_contracts", map[string]any{"file_id": source.ID})
	if described["profile"] != "record-processing-contracts-v1" {
		t.Fatal("no current source contract")
	}
	call("validate_workflow", map[string]any{"request": workflow.PreviewRequest{Definition: definition, FileID: source.ID}})
	proposed := call("propose_workflow", map[string]any{"request": workflow.DraftRequest{Definition: definition}, "request_key": "typed-proposal"})
	id := proposed["workflow_id"].(string)
	hash := proposed["definition_hash"].(string)
	request := workflow.RunRequest{Workflow: workflow.Reference{ID: id, Version: 1, Hash: hash}, FileID: source.ID}
	unapproved, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "freightctl.start_processing_workflow", Arguments: map[string]any{"request": request, "request_key": "not-approved"}})
	if err != nil || !unapproved.IsError {
		t.Fatal("tool supplied its own approval", err)
	}
	_, _ = exchangeAPIRequest(t, server, "POST", prefix+"/workflows/"+id+"/1/approve", nil, map[string]string{"Authorization": "Bearer " + string(token.Bytes), "Idempotency-Key": "separate-human-approval"}, exchangeAPIJSON(t, workflow.Decision{Hash: hash, Revision: 1}), 200)
	accepted := call("start_processing_workflow", map[string]any{"request": request, "request_key": "typed-run"})
	run := accepted["run_id"].(string)
	if accepted["acceptance"] != "recorded-run-and-processing-intent-only" || accepted["current"] != "not-checked" {
		t.Fatal("acceptance promised output")
	}
	worked := call("work_processing_workflow", map[string]any{"run_id": run, "request_key": "typed-work"})
	status := worked["status"].(map[string]any)
	p := status["processing"].(map[string]any)
	file := p["output_file_id"].(string)
	if status["observed_state"] != "attention" || status["observed_reason"] != "output_held" || p["output_released_at_observation"] != false {
		t.Fatal("tool processing implied release")
	}
	if _, _, err = service.Download(ctx, actor, file); !errors.Is(err, store.ErrState) {
		t.Fatal("held output leaked", err)
	}
	replay := call("work_processing_workflow", map[string]any{"run_id": run, "request_key": "typed-work"})
	if replay["replayed"] != true || replay["attempt"].(map[string]any)["current"] != "not-checked" {
		t.Fatal("old key reinterpreted current work")
	}
	call("inspect_processing_workflow", map[string]any{"run_id": run})
}
