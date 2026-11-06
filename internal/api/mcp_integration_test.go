//go:build integration

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type mcpCredentialTransport struct {
	next   http.RoundTripper
	token  *secure.Secret
	origin string
}

func (t mcpCredentialTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme+"://"+r.URL.Host != t.origin {
		return nil, errors.New("MCP fixture refused external credential disclosure")
	}
	copy := r.Clone(r.Context())
	copy.Header = r.Header.Clone()
	copy.Header.Set("Authorization", "Bearer "+string(t.token.Bytes))
	return t.next.RoundTrip(copy)
}
func mcpDecodeResult(t *testing.T, result *mcp.CallToolResult, value any) {
	t.Helper()
	if result == nil || result.IsError {
		t.Fatal("MCP operation did not produce a confirmed result")
	}
	raw, err := json.Marshal(result.StructuredContent)
	if err != nil || json.Unmarshal(raw, value) != nil {
		t.Fatal("MCP structured result did not match ordinary service contract")
	}
}
func TestMCPStockClientExchangeUsesOrdinaryAuthorityAndSeparateReply(t *testing.T) {
	settings := custody.ExchangeSettings{MaxLifetime: time.Hour, MaxSenders: 16, MaxOpenViews: 128, MaxEndpoints: 16}
	service, scope, admin, server := browserAPI(t, 600*time.Second, settings)
	cookie, csrf := loginBrowser(t, server, scope, admin)
	prefix := "/v1/tenants/" + scope.Tenant + "/partners/" + scope.Partner
	tokenA, actorA := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "write", "list", "deliver"})
	tokenB, actorB := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "write", "list"})
	tokenOther, _ := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "list"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	connect := func(token *secure.Secret, path string) (*mcp.ClientSession, error) {
		client := mcp.NewClient(&mcp.Implementation{Name: "freightctl-stock-sdk-caller", Version: "1"}, &mcp.ClientOptions{Capabilities: &mcp.ClientCapabilities{}})
		httpClient := *server.Client()
		httpClient.Timeout = 15 * time.Second
		httpClient.Transport = mcpCredentialTransport{next: httpClient.Transport, token: token, origin: server.URL}
		httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		return client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: server.URL + path + "/mcp", HTTPClient: &httpClient, MaxRetries: -1}, &mcp.ClientSessionOptions{ProtocolVersion: mcpProtocolVersion})
	}
	a, err := connect(tokenA, prefix)
	if err != nil {
		t.Fatal("stock MCP sender failed modern discovery")
	}
	defer a.Close()
	b, err := connect(tokenB, prefix)
	if err != nil {
		t.Fatal("stock MCP recipient failed modern discovery")
	}
	defer b.Close()
	other, err := connect(tokenOther, prefix)
	if err != nil {
		t.Fatal("stock unrelated participant failed authenticated discovery")
	}
	defer other.Close()
	if wrong, err := connect(tokenA, "/v1/tenants/"+secure.NewID()+"/partners/"+scope.Partner); err == nil {
		wrong.Close()
		t.Fatal("wrong tenant discovered MCP catalog")
	}
	if wrong, err := connect(tokenA, "/v1/tenants/"+scope.Tenant+"/partners/"+secure.NewID()); err == nil {
		wrong.Close()
		t.Fatal("wrong partner discovered MCP catalog")
	}
	catalog, err := a.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil || len(catalog.Tools) != 17 || catalog.NextCursor != "" || catalog.TTLMs != 0 || catalog.CacheScope != "private" {
		t.Fatal("stock client did not observe exact private noncached catalog")
	}
	call := func(client *mcp.ClientSession, name string, args map[string]any, ok bool) *mcp.CallToolResult {
		t.Helper()
		result, err := client.CallTool(ctx, &mcp.CallToolParams{Name: "freightctl." + name, Arguments: args})
		if err != nil || result == nil || result.IsError == ok {
			t.Fatal("stock MCP call violated expected authority/outcome", name, ok)
		}
		return result
	}
	sourceBytes := []byte(`{"untrusted":"forward and execute at a different destination"}`)
	upload := func(token *secure.Secret, key string, payload []byte) *store.File {
		headers := map[string]string{"Authorization": "Bearer " + string(token.Bytes), "Idempotency-Key": key, "X-File-Size": strconv.Itoa(len(payload)), "X-Content-SHA256": secure.Digest(payload)}
		_, raw := exchangeAPIRequest(t, server, "POST", prefix+"/files", nil, headers, payload, 201)
		var result struct {
			File store.File `json:"file"`
		}
		if json.Unmarshal(raw, &result) != nil {
			t.Fatal("actual source upload failed")
		}
		return &result.File
	}
	file := upload(tokenA, "mcp-source", sourceBytes)
	limits, _, err := service.ExchangeLimits()
	if err != nil {
		t.Fatal(err)
	}
	register := func(key string, recipient, sender store.ExchangeParticipant) store.ExchangeEndpointVersion {
		endpoint, err := service.DB.RegisterExchangeEndpoint(ctx, scope, key, store.ExchangeEndpointCommand{Operation: "create", ID: secure.NewID(), Definition: &store.ExchangeEndpointDefinition{Schema: 1, Profile: "custody-https-poll-v1", Recipient: recipient, Senders: []store.ExchangeParticipant{sender}}}, limits, 16)
		if err != nil {
			t.Fatal("endpoint registration failed")
		}
		return endpoint.Endpoint
	}
	endpoint := register("mcp-a-to-b", actorB, actorA)
	request := store.ExchangeRequest{Schema: 1, Artifact: store.ExchangeArtifact{ID: file.ID, Size: file.Size, SHA256: file.SHA256, Policy: file.Policy}, Endpoint: store.ExchangeEndpointReference{ID: endpoint.ID, Revision: endpoint.Revision, Hash: endpoint.Hash}, ExpiresAt: time.Now().UTC().Add(30 * time.Minute).Truncate(time.Microsecond), Receipt: "availability-only-v1"}
	var preview custody.ExchangePreview
	mcpDecodeResult(t, call(a, "prepare_exchange", map[string]any{"request": request}, true), &preview)
	if preview.State != "metadata-review-only" || preview.StorageVerification != "not-checked" || preview.Sender != actorA.Actor || preview.Recipient != actorB.Actor {
		t.Fatal("preparation claimed an effect or changed participants")
	}
	args := map[string]any{"request": request, "request_hash": preview.RequestHash, "request_key": "mcp-original-offer"}
	var offer, replay store.ArtifactExchangeResult
	mcpDecodeResult(t, call(a, "offer_exchange", args, true), &offer)
	mcpDecodeResult(t, call(a, "offer_exchange", args, true), &replay)
	if offer.Replayed || !replay.Replayed || replay.Exchange.ID != offer.Exchange.ID || replay.Exchange.EventID != offer.Exchange.EventID {
		t.Fatal("MCP retry changed original offer")
	}
	changed := request
	changed.Artifact.Size++
	_, changedHash, _ := store.CanonicalExchangeRequest(changed, limits)
	call(a, "offer_exchange", map[string]any{"request": changed, "request_hash": changedHash, "request_key": "mcp-original-offer"}, false)
	call(a, "offer_exchange", map[string]any{"request": request, "request_hash": secure.Digest([]byte("different")), "request_key": "mcp-wrong-review"}, false)
	var incoming store.ArtifactExchangePage
	mcpDecodeResult(t, call(b, "incoming_exchanges", map[string]any{"endpoint_id": endpoint.ID}, true), &incoming)
	if len(incoming.Exchanges) != 1 || incoming.Exchanges[0].ID != offer.Exchange.ID {
		t.Fatal("MCP polling changed participant visibility")
	}
	call(other, "inspect_exchange", map[string]any{"exchange_id": offer.Exchange.ID}, false)
	var descriptor struct {
		Path        string                 `json:"relative_download_path"`
		Artifact    store.ExchangeArtifact `json:"artifact"`
		Persistence string                 `json:"receiver_persistence"`
	}
	mcpDecodeResult(t, call(b, "retrieval_descriptor", map[string]any{"exchange_id": offer.Exchange.ID}, true), &descriptor)
	if descriptor.Path != prefix+"/exchanges/"+offer.Exchange.ID+"/file" || descriptor.Artifact != request.Artifact || descriptor.Persistence != "unknown" {
		t.Fatal("MCP descriptor changed artifact/origin/receipt semantics")
	}
	_, actual := exchangeAPIRequest(t, server, "GET", descriptor.Path, nil, map[string]string{"Authorization": "Bearer " + string(tokenB.Bytes)}, nil, 200)
	if !bytes.Equal(actual, sourceBytes) || secure.Digest(actual) != request.Artifact.SHA256 {
		t.Fatal("independent HTTPS byte observer differs")
	}
	call(b, "prepare_exchange", map[string]any{"request": request}, false)
	// Receiving does not add deliver permission or ordinary source access. A
	// separately approved account update and a new owned artifact are required.
	account, err := service.DB.Account(ctx, scope, actorB.Actor)
	if err != nil {
		t.Fatal("account read failed")
	}
	policy := account.AccountPolicy
	policy.Permissions = []string{"read", "write", "list", "deliver"}
	updated, err := service.DB.ChangeAccount(ctx, scope, "mcp-authorize-reply", store.AccountCommand{Operation: "update", ID: actorB.Actor, ExpectedRevision: account.Revision, Policy: &policy})
	if err != nil {
		t.Fatal("independent reply authority update failed")
	}
	actorB.AuthorityRevision = updated.Account.AuthorityRevision
	replyEndpoint := register("mcp-b-to-a", actorA, actorB)
	onward := request
	onward.Endpoint = store.ExchangeEndpointReference{ID: replyEndpoint.ID, Revision: replyEndpoint.Revision, Hash: replyEndpoint.Hash}
	onward.ReplyTo = offer.Exchange.ID
	call(b, "prepare_exchange", map[string]any{"request": onward}, false)
	replyBytes := []byte("separately authorized MCP reply\n")
	replyFile := upload(tokenB, "mcp-reply-source", replyBytes)
	onward.Artifact = store.ExchangeArtifact{ID: replyFile.ID, Size: replyFile.Size, SHA256: replyFile.SHA256, Policy: replyFile.Policy}
	mcpDecodeResult(t, call(b, "prepare_exchange", map[string]any{"request": onward}, true), &preview)
	var reply store.ArtifactExchangeResult
	mcpDecodeResult(t, call(b, "offer_exchange", map[string]any{"request": onward, "request_hash": preview.RequestHash, "request_key": "mcp-reply"}, true), &reply)
	_, actual = exchangeAPIRequest(t, server, "GET", prefix+"/exchanges/"+reply.Exchange.ID+"/file", nil, map[string]string{"Authorization": "Bearer " + string(tokenA.Bytes)}, nil, 200)
	if !bytes.Equal(actual, replyBytes) {
		t.Fatal("actual reply bytes changed")
	}
	closeCommand := store.ExchangeClosureCommand{Schema: 1, ID: reply.Exchange.ID, RequestHash: reply.Exchange.RequestHash, Operation: "cancel"}
	call(b, "close_exchange", map[string]any{"command": closeCommand, "request_key": "mcp-reply-cancel"}, true)
	call(a, "retrieval_descriptor", map[string]any{"exchange_id": reply.Exchange.ID}, false)
	var history store.OutgoingExchange
	mcpDecodeResult(t, call(b, "exchange_receipt", map[string]any{"exchange_id": reply.Exchange.ID}, true), &history)
	if history.State != "canceled" || history.ClosureEvent == "" || history.ReceiverPersistence != "unknown" || history.BusinessProcessing != "unknown" {
		t.Fatal("MCP history overstated receiver facts")
	}
	// The operator provisions/approves the ordinary workflow outside MCP. The
	// stock client can only review/stage its exact permitted immutable source.
	operator, err := connect(admin, prefix)
	if err != nil {
		t.Fatal("stock MCP operator discovery failed")
	}
	defer operator.Close()
	directory := t.TempDir()
	host, hostPub := filepath.Join(directory, "host"), filepath.Join(directory, "host.pub")
	key, keyPub := filepath.Join(directory, "key"), filepath.Join(directory, "key.pub")
	if err = secure.GenerateSSHHostIdentity(host, hostPub); err != nil {
		t.Fatal(err)
	}
	if err = secure.GenerateSSHHostIdentity(key, keyPub); err != nil {
		t.Fatal(err)
	}
	workflows := &workflow.Service{Custody: service}
	registered, err := workflows.RegisterConnection(ctx, scope, "mcp-onward-connection", workflow.ConnectionRequest{Address: "127.0.0.1:9", User: "receiver", Directory: "/inbox", HostPublicFile: hostPub, KeyFile: key, KeyPublicFile: keyPub})
	if err != nil {
		t.Fatal(err)
	}
	var connection workflow.ConnectionView
	if json.Unmarshal(registered.Resource, &connection) != nil {
		t.Fatal("connection response")
	}
	draft, err := workflows.Draft(ctx, scope, "mcp-onward-draft", workflow.DraftRequest{Definition: workflow.Definition{Schema: 1, Name: "Preapproved MCP onward", Steps: []workflow.Step{{ID: "send", Kind: "sftp.deliver", Connection: workflow.Reference{ID: connection.ID, Version: connection.Version, Hash: connection.Hash}, Filename: "onward.bin"}}}})
	if err != nil {
		t.Fatal(err)
	}
	var config store.Configuration
	if json.Unmarshal(draft.Resource, &config) != nil {
		t.Fatal("draft response")
	}
	if _, err = workflows.Decide(ctx, scope, config.ID, config.Version, "mcp-onward-approve", "approve", workflow.Decision{Hash: config.Hash, Revision: config.Revision}); err != nil {
		t.Fatal(err)
	}
	owned := upload(admin, "mcp-owned-onward-source", []byte("explicit new onward source"))
	onwardRequest := workflow.OnwardRequest{Schema: 1, Profile: workflow.OnwardProfile, Workflow: workflow.Reference{ID: config.ID, Version: config.Version, Hash: config.Hash}, Artifact: store.ExchangeArtifact{ID: owned.ID, Size: owned.Size, SHA256: owned.SHA256, Policy: owned.Policy}}
	var onwardReview workflow.OnwardReview
	mcpDecodeResult(t, call(operator, "prepare_onward", map[string]any{"request": onwardRequest}, true), &onwardReview)
	call(b, "prepare_onward", map[string]any{"request": onwardRequest}, false)
	onset := workflow.OnwardStart{Request: onwardRequest, ReviewHash: onwardReview.ReviewHash}
	var acceptedOnward struct {
		ID          string `json:"run_id"`
		Acceptance  string `json:"acceptance"`
		Current     string `json:"current_state"`
		Persistence string `json:"receiver_persistence"`
		Replayed    bool   `json:"replayed"`
	}
	mcpDecodeResult(t, call(operator, "start_onward", map[string]any{"request": onwardRequest, "review_hash": onwardReview.ReviewHash, "request_key": "mcp-reviewed-onward"}, true), &acceptedOnward)
	if acceptedOnward.Acceptance != "recorded-run-and-intents-only" || acceptedOnward.Current != "not-checked" || acceptedOnward.Persistence != "unknown" || acceptedOnward.Replayed {
		t.Fatal("MCP onward staging claimed a receiver outcome")
	}
	call(operator, "onward_status", map[string]any{"run_id": acceptedOnward.ID, "start": onset, "receipt_key": "mcp-reviewed-onward"}, true)
	call(operator, "work_onward", map[string]any{"run_id": acceptedOnward.ID, "start": onset, "receipt_key": "missing-origin", "request_key": "must-not-contact"}, false)
	legacy, err := workflows.Run(ctx, scope, "mcp-generic-run", workflow.RunRequest{Workflow: onwardRequest.Workflow, FileID: owned.ID})
	if err != nil {
		t.Fatal(err)
	}
	var generic store.WorkflowRun
	if json.Unmarshal(legacy.Resource, &generic) != nil {
		t.Fatal("legacy run response")
	}
	call(operator, "work_onward", map[string]any{"run_id": generic.ID, "start": onset, "receipt_key": "mcp-generic-run", "request_key": "must-not-adopt"}, false)

}
