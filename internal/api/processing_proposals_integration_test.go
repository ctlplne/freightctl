//go:build integration

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/ctlplne/freightctl/internal/checks"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestProcessingProposalHTTPSAndStockMCPAllowDefinitionAuthorWithoutBytesButNeverApproval(t *testing.T) {
	s, manager, admin, server := browserAPI(t, 600*time.Second)
	cookie, csrf := loginBrowser(t, server, manager, admin)
	prefix := "/v1/tenants/" + manager.Tenant + "/partners/" + manager.Partner
	authorToken, author := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"workflow_manage"})
	executorToken, executor := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "write", "check_run", "workflow_manage", "workflow_execute"})
	control := &checks.Service{Custody: s}
	input, err := checks.Normalize(checks.Policy{Schema: 1, Kind: "csv", Columns: []checks.Column{{Name: "account", Type: "text", Required: true, MaxBytes: 32}}, MaxBytes: 8192, MaxRows: 4, MaxRecordBytes: 1024, TimeoutSeconds: 2})
	if err != nil {
		t.Fatal(err)
	}
	output := input
	output.Schema, output.Kind = 2, "json_records"
	registered, err := control.RegisterOutputPolicy(t.Context(), manager, "public-authored-output", checks.OutputPolicyRequest{Producer: executor.Actor, Definition: output})
	if err != nil {
		t.Fatal(err)
	}
	var outputRecord checks.OutputPolicyRecord
	if json.Unmarshal(registered.Resource, &outputRecord) != nil || outputRecord.Policy == nil {
		t.Fatal("output contract")
	}
	inputRaw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := checks.NormalizeRecordProjection(input, checks.RecordProjection{Schema: 1, Kind: "record_projection", SourcePolicyHash: secure.Digest(inputRaw), OutputKind: "json_records", Columns: []checks.ProjectionColumn{{Source: "account", Target: "account"}}})
	if err != nil {
		t.Fatal(err)
	}
	definition := workflow.Definition{Schema: 3, Name: "PRIVATE_AUTHORING_NAME", Processing: &workflow.ProcessingTask{ID: "project", Kind: "records.project", Definition: rules, OutputPolicy: workflow.Reference{ID: outputRecord.Policy.ID, Version: outputRecord.Policy.Version, Hash: outputRecord.Policy.Hash}, Reason: "PRIVATE_AUTHORING_REASON"}}
	request := workflow.ProcessingProposalRequest{Executor: executor.Actor, Definition: definition, ExpiresAt: time.Now().UTC().Truncate(time.Second).Add(time.Hour)}
	post := func(token *secure.Secret, path, key string, body any, status int) []byte {
		t.Helper()
		_, raw := exchangeAPIRequest(t, server, "POST", prefix+path, nil, map[string]string{"Authorization": "Bearer " + string(token.Bytes), "Idempotency-Key": key}, exchangeAPIJSON(t, body), status)
		return raw
	}
	var proposed workflow.Result
	if json.Unmarshal(post(authorToken, "/processing-proposals", "public-author-propose", request, 200), &proposed) != nil {
		t.Fatal("public proposal envelope")
	}
	var receipt struct {
		Profile  string                               `json:"profile"`
		Proposal store.ProcessingProposalSummary      `json:"proposal"`
		Workflow *workflow.ProcessingReviewedWorkflow `json:"adopted_workflow"`
	}
	if json.Unmarshal(proposed.Resource, &receipt) != nil || receipt.Profile != workflow.ProcessingProposalProfile || receipt.Proposal.Author != author.Actor || receipt.Proposal.Executor != executor.Actor || receipt.Workflow != nil {
		t.Fatal("proposal supplied authority or changed participants")
	}
	id := receipt.Proposal.ID
	decision := workflow.Decision{Hash: receipt.Proposal.Hash, Revision: receipt.Proposal.Revision}
	post(authorToken, "/processing-proposals/"+id+"/adopt", "author-cannot-adopt", decision, 403)
	_, _ = exchangeAPIRequest(t, server, "GET", prefix+"/files/11111111-1111-4111-8111-111111111111", nil, map[string]string{"Authorization": "Bearer " + string(authorToken.Bytes)}, nil, 403)
	_, _ = exchangeAPIRequest(t, server, "GET", prefix+"/processing-proposals/"+id, cookie, map[string]string{"Origin": server.URL}, nil, 404)
	var adopted workflow.Result
	if json.Unmarshal(post(executorToken, "/processing-proposals/"+id+"/adopt", "public-executor-adopt", decision, 200), &adopted) != nil || json.Unmarshal(adopted.Resource, &receipt) != nil || receipt.Workflow == nil || receipt.Workflow.State != "draft" || receipt.Workflow.ApprovalAuthority != 0 {
		t.Fatal("public adoption bypassed ordinary approval")
	}
	var replay workflow.Result
	if json.Unmarshal(post(executorToken, "/processing-proposals/"+id+"/adopt", "public-executor-adopt", decision, 200), &replay) != nil || !replay.Replayed || !bytes.Equal(adopted.Resource, replay.Resource) {
		t.Fatal("public adoption replay duplicated draft")
	}
	post(executorToken, "/workflows/"+receipt.Workflow.ID+"/1/approve", "no-implicit-approval", workflow.Decision{Hash: receipt.Workflow.Hash, Revision: receipt.Workflow.Revision}, 403)

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	connect := func(token *secure.Secret) *mcp.ClientSession {
		t.Helper()
		client := mcp.NewClient(&mcp.Implementation{Name: "freightctl-authored-definition-stock-client", Version: "1"}, nil)
		httpClient := *server.Client()
		httpClient.Transport = mcpCredentialTransport{next: httpClient.Transport, token: token, origin: server.URL}
		httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: server.URL + prefix + "/mcp", HTTPClient: &httpClient, MaxRetries: -1}, &mcp.ClientSessionOptions{ProtocolVersion: mcpProtocolVersion})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { session.Close() })
		return session
	}
	authorClient, executorClient := connect(authorToken), connect(executorToken)
	call := func(session *mcp.ClientSession, name string, args map[string]any) map[string]any {
		t.Helper()
		reply, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "freightctl." + name, Arguments: args})
		if err != nil || reply.IsError {
			t.Fatal("stock authored-definition tool failed", name, err)
		}
		raw, err := json.Marshal(reply.StructuredContent)
		if err != nil {
			t.Fatal(err)
		}
		var value map[string]any
		if json.Unmarshal(raw, &value) != nil {
			t.Fatal("stock tool result")
		}
		return value
	}
	proposal := call(authorClient, "propose_processing_definition", map[string]any{"request": request, "request_key": "stock-author-propose"})
	proposalID := proposal["proposal_id"].(string)
	metadata := call(executorClient, "inspect_processing_proposal", map[string]any{"proposal_id": proposalID})
	if metadata["definition"] != nil || metadata["definition_disclosed"] != false || metadata["approval"] != "not-granted" || metadata["execution"] != "not-granted" {
		t.Fatal("default model metadata disclosed rules or claimed authority")
	}
	disclosed := call(executorClient, "inspect_processing_proposal", map[string]any{"proposal_id": proposalID, "disclose_definition": true})
	if disclosed["definition"] == nil || disclosed["definition_disclosed"] != true {
		t.Fatal("explicit authorized definition disclosure failed")
	}
	stockAdopted := call(executorClient, "adopt_processing_proposal", map[string]any{"proposal_id": proposalID, "request_key": "stock-executor-adopt", "request": workflow.Decision{Hash: proposal["definition_hash"].(string), Revision: 1}})
	if stockAdopted["recorded_state"] != "adopted" || stockAdopted["approval"] != "not-granted" || stockAdopted["execution"] != "not-granted" || stockAdopted["adopted_workflow"] == nil {
		t.Fatal("stock adoption lost draft/authority boundary")
	}
}
