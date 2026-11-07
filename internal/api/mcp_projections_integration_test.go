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
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestMCPStockClientScopedProcessingKeepsApprovalAndHeldBytesOutsideTools(t *testing.T) {
	service, manager, admin, server := browserAPI(t, 600*time.Second, custody.ExchangeSettings{MaxLifetime: time.Hour, MaxSenders: 16, MaxOpenViews: 128, MaxEndpoints: 16})
	cookie, csrf := loginBrowser(t, server, manager, admin)
	prefix := "/v1/tenants/" + manager.Tenant + "/partners/" + manager.Partner
	token, _ := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "write", "check_run", "workflow_manage", "workflow_approve", "workflow_execute"})
	actor := store.Scope{Tenant: manager.Tenant, Partner: manager.Partner, TokenHash: secure.Digest(token.Bytes)}
	control := &checks.Service{Custody: service}
	policy, err := checks.Normalize(checks.Policy{Schema: 1, Kind: "csv", Columns: []checks.Column{{Name: "account", Type: "text", Required: true, MaxBytes: 32}, {Name: "amount", Type: "decimal", Required: true, MaxBytes: 32, Precision: 12, Scale: 2}, {Name: "day", Type: "date", Required: true, MaxBytes: 10}}, MaxBytes: 8192, MaxRows: 4, MaxRecordBytes: 1024, TimeoutSeconds: 2})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = control.Register(context.Background(), manager, "scope-input-policy", checks.PolicyRequest{Definition: policy}); err != nil {
		t.Fatal(err)
	}
	body := "account,amount,day\n0001,1.01,2026-10-28\n"
	source, _, err := service.Accept(context.Background(), actor, "scope-input", int64(len(body)), secure.Digest([]byte(body)), strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = control.Run(context.Background(), actor, source.ID, "scope-source-check"); err != nil {
		t.Fatal(err)
	}
	sourcePolicy := strings.TrimPrefix(source.Policy, store.CSVIntakePrefix)
	output := policy
	output.Schema = 2
	output.Kind = "json_records"
	if _, err = control.Register(context.Background(), manager, "scope-output-policy", checks.PolicyRequest{ExpectedVersion: 1, Definition: output}); err != nil {
		t.Fatal(err)
	}
	options := checks.ProjectionOptions{Profile: checks.ScopedProjectionProfile, Reason: "SYNTHETIC_PRIVATE_PROCESSING_REASON", Definition: checks.RecordProjection{Schema: 1, Kind: "record_projection", SourcePolicyHash: sourcePolicy, OutputKind: "json_records", Columns: []checks.ProjectionColumn{{Source: "account", Target: "account"}, {Source: "amount", Target: "amount"}, {Source: "day", Target: "day"}}}}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	httpClient := *server.Client()
	httpClient.Timeout = 15 * time.Second
	httpClient.Transport = mcpCredentialTransport{next: httpClient.Transport, token: token, origin: server.URL}
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client := mcp.NewClient(&mcp.Implementation{Name: "freightctl-stock-processing-client", Version: "1"}, &mcp.ClientOptions{Capabilities: &mcp.ClientCapabilities{}})
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: server.URL + prefix + "/mcp", HTTPClient: &httpClient, MaxRetries: -1}, &mcp.ClientSessionOptions{ProtocolVersion: mcpProtocolVersion})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	call := func(name string, args map[string]any) map[string]any {
		t.Helper()
		response, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "freightctl." + name, Arguments: args})
		if err != nil || response.IsError {
			t.Fatal("stock processing call failed", name, err)
		}
		raw, err := json.Marshal(response.StructuredContent)
		if err != nil || strings.Contains(string(raw), options.Reason) || strings.Contains(string(raw), body) || strings.Contains(string(raw), "staging_slots") || strings.Contains(string(raw), "namespace_root\"") {
			t.Fatal("private bindings or contents entered model context", err)
		}
		var result map[string]any
		if json.Unmarshal(raw, &result) != nil {
			t.Fatal("metadata result")
		}
		return result
	}
	review := call("preview_record_projection", map[string]any{"file_id": source.ID, "request": options})
	proposed := call("propose_record_projection", map[string]any{"file_id": source.ID, "request": options, "review_hash": review["review_hash"], "request_key": "scope-propose"})
	id := proposed["projection_id"].(string)
	// This separate ordinary API call is the explicit approval. The fixed tool
	// catalog provides no approval operation and cannot add approval fields.
	headers := map[string]string{"Authorization": "Bearer " + string(token.Bytes), "Idempotency-Key": "scope-approve"}
	_, raw := exchangeAPIRequest(t, server, "POST", prefix+"/projections/"+id+"/decide", nil, headers, exchangeAPIJSON(t, checks.PolicyRecheckDecision{Operation: "approve", Hash: proposed["definition_hash"].(string), Revision: int64(proposed["revision"].(float64))}), 200)
	var approved checks.Result
	if json.Unmarshal(raw, &approved) != nil {
		t.Fatal("approval receipt")
	}
	started := call("start_record_projection", map[string]any{"projection_id": id, "request": checks.ProjectionStartDecision{Hash: proposed["definition_hash"].(string), Revision: 2}, "request_key": "scope-start"})
	worked := call("work_record_projection", map[string]any{"projection_id": id, "request": started["attempt"], "request_key": "scope-work"})
	if worked["state"] != "completed" || worked["acceptance"] != "durable-held-pending-checks-and-release" || worked["current"] != "not-checked" {
		t.Fatal("processing overstated its receipt")
	}
	artifact := worked["artifact"].(map[string]any)
	if _, _, err = service.Download(ctx, actor, artifact["file_revision_id"].(string)); !errors.Is(err, store.ErrState) {
		t.Fatal("MCP processing released held bytes", err)
	}
	replay := call("work_record_projection", map[string]any{"projection_id": id, "request": started["attempt"], "request_key": "scope-work"})
	if replay["replayed"] != true {
		t.Fatal("original work receipt not recovered")
	}
	// Source proof is now stale relative to this changed output policy. The
	// original proposal key must still recover its original,private-bound receipt.
	output.MaxRows--
	if _, err = control.Register(ctx, manager, "later-output-policy", checks.PolicyRequest{ExpectedVersion: 2, Definition: output}); err != nil {
		t.Fatal(err)
	}
	recovered := call("propose_record_projection", map[string]any{"file_id": source.ID, "request": options, "review_hash": review["review_hash"], "request_key": "scope-propose"})
	if recovered["projection_id"] != id || recovered["replayed"] != true {
		t.Fatal("source revalidation reinterpreted original proposal")
	}
}
