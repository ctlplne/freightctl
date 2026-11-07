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
	if err != nil || len(catalog.Tools) != 43 || catalog.NextCursor != "" || catalog.TTLMs != 0 || catalog.CacheScope != "private" {
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
	ingressRequest := custody.IngressDescriptorRequest{Size: int64(len(sourceBytes)), SHA256: secure.Digest(sourceBytes), Key: "mcp-source"}
	var ingress custody.IngressDescriptor
	mcpDecodeResult(t, call(a, "artifact_ingress_descriptor", map[string]any{"size_bytes": ingressRequest.Size, "sha256": ingressRequest.SHA256, "request_key": ingressRequest.Key}, true), &ingress)
	if ingress.Request != ingressRequest || ingress.Path != prefix+"/files" || ingress.Method != "POST" || ingress.State != "metadata-only" || ingress.Availability != "not-checked" || ingress.Headers["Authorization"] != "" || ingress.Headers["Idempotency-Key"] != ingressRequest.Key || ingress.Headers["X-Content-SHA256"] != ingressRequest.SHA256 || ingress.Headers["X-File-Size"] != strconv.Itoa(len(sourceBytes)) {
		t.Fatal("stock descriptor changed scope/integrity or disclosed a credential")
	}
	_, ingressRaw := exchangeAPIRequest(t, server, "POST", prefix+"/artifact-ingress/previews", nil, map[string]string{"Authorization": "Bearer " + string(tokenA.Bytes)}, exchangeAPIJSON(t, ingressRequest), 200)
	var apiIngress custody.IngressDescriptor
	if json.Unmarshal(ingressRaw, &apiIngress) != nil {
		t.Fatal("ordinary ingress review")
	}
	apiWire, _ := json.Marshal(apiIngress)
	mcpWire, _ := json.Marshal(ingress)
	if !bytes.Equal(apiWire, mcpWire) {
		t.Fatal("API and stock MCP ingress metadata differ")
	}
	if bytes.Contains(apiWire, tokenA.Bytes) || bytes.Contains(apiWire, []byte("Authorization")) || bytes.Contains(apiWire, []byte("forward and execute")) {
		t.Fatal("descriptor exposed a credential or artifact contents")
	}
	call(other, "artifact_ingress_descriptor", map[string]any{"size_bytes": ingressRequest.Size, "sha256": ingressRequest.SHA256, "request_key": ingressRequest.Key}, false)
	// A separate confined participant uses ordinary namespace upload services.
	// Its bytes never enter tool arguments/results, and receiving supplies no write.
	mode := uint32(0770)
	if _, err := service.PathCommand(ctx, scope, "mcp-ingress-directory", store.PathCommand{Operation: "mkdir", Path: "/agent-ingress", Mode: &mode}); err != nil {
		t.Fatal("confined upload directory", err)
	}
	uploadToken, uploadActor := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "write", "list"})
	accountForUpload, err := service.DB.Account(ctx, scope, uploadActor.Actor)
	if err != nil {
		t.Fatal("upload account", err)
	}
	uploadPolicy := accountForUpload.AccountPolicy
	uploadPolicy.Root = "/agent-ingress"
	if _, err = service.DB.ChangeAccount(ctx, scope, "mcp-confine-upload", store.AccountCommand{Operation: "update", ID: uploadActor.Actor, ExpectedRevision: accountForUpload.Revision, Policy: &uploadPolicy}); err != nil {
		t.Fatal("confine upload account", err)
	}
	uploader, err := connect(uploadToken, prefix)
	if err != nil {
		t.Fatal("confined MCP discovery", err)
	}
	defer uploader.Close()
	payload := bytes.Repeat([]byte("synthetic untrusted artifact;forwarding requires a separate grant\n"), 2200)
	newArgs := map[string]any{"virtual_path": "/new.dat", "size_bytes": len(payload), "sha256": secure.Digest(payload), "request_key": "mcp-ticket-create"}
	var ticket, ticketReplay mcpUploadDescriptor
	mcpDecodeResult(t, call(uploader, "artifact_upload_start", newArgs, true), &ticket)
	if ticket.Upload.State != "open" || ticket.Upload.Path != "/new.dat" || ticket.Upload.Offset != 0 || ticket.Observation != "original-command-receipt" || ticket.CurrentState != "not-checked" || ticket.Availability != "not-checked" {
		t.Fatal("ticket creation claimed acceptance/current availability")
	}
	call(other, "artifact_upload_start", newArgs, false)
	for _, operation := range []string{"status", "complete", "abort"} {
		args := map[string]any{"upload_id": ticket.Upload.ID}
		if operation != "status" {
			args["request_key"] = "foreign-ticket-action"
		}
		call(b, "artifact_upload_"+operation, args, false)
	}
	for _, forbidden := range []string{"/../escape", "/.freightctl/uploads/forged"} {
		args := map[string]any{"virtual_path": forbidden, "size_bytes": 0, "sha256": secure.Digest(nil), "request_key": "mcp-unsafe-target"}
		call(uploader, "artifact_upload_start", args, false)
	}
	// All chunk bytes use the existing authenticated HTTPS data route. The host
	// can recover progress after ignoring a response;this is not a process-kill claim.
	appendChunk := func(key string, offset int, chunk []byte) {
		headers := map[string]string{"Authorization": "Bearer " + string(uploadToken.Bytes), "Idempotency-Key": key, "Upload-Offset": strconv.Itoa(offset), "X-File-Size": strconv.Itoa(len(chunk)), "X-Content-SHA256": secure.Digest(chunk), "Content-Type": "application/octet-stream"}
		exchangeAPIRequest(t, server, "PATCH", ticket.AppendPath, nil, headers, chunk, 200)
	}
	first := payload[:64<<10]
	appendChunk("mcp-ticket-first", 0, first)
	appendChunk("mcp-ticket-first", 0, first)
	var progress mcpUploadDescriptor
	mcpDecodeResult(t, call(uploader, "artifact_upload_status", map[string]any{"upload_id": ticket.Upload.ID}, true), &progress)
	if progress.Upload.Offset != 64<<10 || progress.Upload.Chunks != 1 || progress.Upload.FileID != "" || progress.Observation != "current-ticket-metadata" {
		t.Fatal("checkpoint not exact or partial artifact published")
	}
	mcpDecodeResult(t, call(uploader, "artifact_upload_start", newArgs, true), &ticketReplay)
	if !ticketReplay.Replayed || ticketReplay.Upload.ID != ticket.Upload.ID || ticketReplay.Upload.Offset != 0 || ticketReplay.CurrentState != "not-checked" {
		t.Fatal("original creation receipt became current progress")
	}
	newFileMode := uint32(0600)
	ordinaryCreate := custody.CreateUpload{Path: "/new.dat", Size: int64(len(payload)), SHA256: secure.Digest(payload), Mode: &newFileMode}
	_, ordinaryRaw := exchangeAPIRequest(t, server, "POST", prefix+"/uploads", nil, map[string]string{"Authorization": "Bearer " + string(uploadToken.Bytes), "Idempotency-Key": "mcp-ticket-create"}, exchangeAPIJSON(t, ordinaryCreate), 200)
	var ordinaryReplay custody.UploadResult
	if json.Unmarshal(ordinaryRaw, &ordinaryReplay) != nil || !ordinaryReplay.Replayed || ordinaryReplay.Upload.ID != ticket.Upload.ID {
		t.Fatal("MCP ticket used different ordinary receipt semantics")
	}
	changedArgs := map[string]any{"virtual_path": "/new.dat", "size_bytes": len(payload) + 1, "sha256": secure.Digest(payload), "request_key": "mcp-ticket-create"}
	call(uploader, "artifact_upload_start", changedArgs, false)
	appendChunk("mcp-ticket-second", 64<<10, payload[64<<10:])
	finishArgs := map[string]any{"upload_id": ticket.Upload.ID, "request_key": "mcp-ticket-finish"}
	var accepted, acceptedReplay mcpUploadDescriptor
	mcpDecodeResult(t, call(uploader, "artifact_upload_complete", finishArgs, true), &accepted)
	mcpDecodeResult(t, call(uploader, "artifact_upload_complete", finishArgs, true), &acceptedReplay)
	if accepted.Upload.State != "completed" || accepted.Upload.FileID == "" || accepted.Upload.Acceptance != "durable-local-integrity-only" || acceptedReplay.Upload.FileID != accepted.Upload.FileID || !acceptedReplay.Replayed || accepted.ReceiverPersistence != "unknown" || accepted.BusinessProcessing != "unknown" || accepted.Availability != "not-checked" {
		t.Fatal("completion changed exact receipt or overstated outcomes")
	}
	_, received := exchangeAPIRequest(t, server, "GET", prefix+"/namespace/file?path=/new.dat", nil, map[string]string{"Authorization": "Bearer " + string(uploadToken.Bytes)}, nil, 200)
	if !bytes.Equal(received, payload) || secure.Digest(received) != ticket.Upload.SHA256 {
		t.Fatal("independent confined HTTPS byte observer differs")
	}
	for _, result := range []*mcpUploadDescriptor{&ticket, &progress, &accepted, &acceptedReplay} {
		raw, _ := json.Marshal(result)
		if bytes.Contains(raw, uploadToken.Bytes) || bytes.Contains(raw, []byte("synthetic untrusted artifact")) || bytes.Contains(raw, []byte("/agent-ingress")) {
			t.Fatal("tool leaked content,credential or actual root")
		}
	}
	call(uploader, "artifact_upload_start", map[string]any{"virtual_path": "/new.dat", "size_bytes": 0, "sha256": secure.Digest(nil), "request_key": "mcp-refuse-overwrite"}, false)
	var abortTicket, aborted mcpUploadDescriptor
	mcpDecodeResult(t, call(uploader, "artifact_upload_start", map[string]any{"virtual_path": "/aborted.dat", "size_bytes": 0, "sha256": secure.Digest(nil), "request_key": "mcp-abort-create"}, true), &abortTicket)
	abortArgs := map[string]any{"upload_id": abortTicket.Upload.ID, "request_key": "mcp-abort"}
	mcpDecodeResult(t, call(uploader, "artifact_upload_abort", abortArgs, true), &aborted)
	if aborted.Upload.State != "aborted" || aborted.Upload.FileID != "" {
		t.Fatal("abort claimed publication")
	}
	mcpDecodeResult(t, call(uploader, "artifact_upload_abort", abortArgs, true), &aborted)
	if !aborted.Replayed {
		t.Fatal("abort retry lost receipt")
	}
	// Upload tickets and receipts are actor-private even from a root runtime
	// account. Inspect cardinality as their actual owner; do not bypass RLS.
	uploadScope := store.Scope{Tenant: scope.Tenant, Partner: scope.Partner, TokenHash: secure.Digest(uploadToken.Bytes)}
	ticketTx, err := service.DB.Begin(ctx, uploadScope)
	if err != nil {
		t.Fatal(err)
	}
	var ticketCount, chunkCount, receiptCount, publishedCount int
	err = ticketTx.Tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM upload_sessions WHERE actor_id=$1),(SELECT count(*) FROM upload_chunks WHERE upload_id=$2),(SELECT count(*) FROM upload_receipts WHERE actor_id=$1),(SELECT count(*) FROM namespace_entries WHERE owner_actor_id=$1 AND path='/agent-ingress/new.dat' AND file_id=$3 AND mode=384 AND NOT deleted)`, uploadActor.Actor, ticket.Upload.ID, accepted.Upload.FileID).Scan(&ticketCount, &chunkCount, &receiptCount, &publishedCount)
	ticketTx.Tx.Rollback(ctx)
	if err != nil || ticketCount != 2 || chunkCount != 2 || receiptCount != 6 || publishedCount != 1 {
		t.Fatal("ticket replay or publication changed durable cardinality", err, ticketCount, chunkCount, receiptCount, publishedCount)
	}
	uploadPolicy.Permissions = []string{"read", "list"}
	currentUploadAccount, err := service.DB.Account(ctx, scope, uploadActor.Actor)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.DB.ChangeAccount(ctx, scope, "mcp-revoke-ticket-write", store.AccountCommand{Operation: "update", ID: uploadActor.Actor, ExpectedRevision: currentUploadAccount.Revision, Policy: &uploadPolicy}); err != nil {
		t.Fatal(err)
	}
	call(uploader, "artifact_upload_status", map[string]any{"upload_id": ticket.Upload.ID}, false)
	call(uploader, "artifact_upload_complete", finishArgs, false)
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
	// Ordinary cookie/CSRF and official SDK reads project the same immutable
	// facts. The selected direction does not supply a role or sender fallback.
	cookieB, csrfB := loginBrowser(t, server, scope, tokenB)
	traceRequest := store.ExchangeTraceRequest{ID: offer.Exchange.ID, Direction: "incoming"}
	exchangeAPIRequest(t, server, "POST", prefix+"/exchange-traces/previews", cookieB, map[string]string{"Origin": server.URL, "X-CSRF-Token": "incorrect"}, exchangeAPIJSON(t, traceRequest), 403)
	traceScope := store.Scope{Tenant: scope.Tenant, Partner: scope.Partner, TokenHash: secure.Digest(tokenA.Bytes)}
	traceSnapshot := func() [4]int {
		t.Helper()
		tx, err := service.DB.Begin(ctx, traceScope)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Tx.Rollback(ctx)
		var counts [4]int
		if err = tx.Tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM events),(SELECT count(*) FROM artifact_exchanges),(SELECT count(*) FROM artifact_exchange_commands),(SELECT count(*) FROM delivery_intents)`).Scan(&counts[0], &counts[1], &counts[2], &counts[3]); err != nil {
			t.Fatal(err)
		}
		return counts
	}
	traceBefore := traceSnapshot()
	if traceBefore[1] != 1 || traceBefore[2] != 1 {
		t.Fatal("trace snapshot did not see sender owned records")
	}
	var agentTrace, apiTrace, senderTrace store.ExchangeTrace
	mcpDecodeResult(t, call(b, "exchange_trace", map[string]any{"exchange_id": offer.Exchange.ID, "direction": "incoming"}, true), &agentTrace)
	mcpDecodeResult(t, call(a, "exchange_trace", map[string]any{"exchange_id": offer.Exchange.ID, "direction": "outgoing"}, true), &senderTrace)
	_, traceRaw := exchangeAPIRequest(t, server, "POST", prefix+"/exchange-traces/previews", cookieB, map[string]string{"Origin": server.URL, "X-CSRF-Token": csrfB}, exchangeAPIJSON(t, traceRequest), 200)
	if json.Unmarshal(traceRaw, &apiTrace) != nil {
		t.Fatal("ordinary cookie evidence decode")
	}
	for _, v := range []store.ExchangeTrace{agentTrace, apiTrace, senderTrace} {
		if v.RequestHash != offer.Exchange.RequestHash || v.Artifact == nil || *v.Artifact != request.Artifact || len(v.Events) != 2 || v.CheckedAt.IsZero() || v.StorageVerification != "not-checked" || v.Retrieval != "unknown" || v.ReceiverPersistence != "unknown" || v.BusinessProcessing != "unknown" {
			t.Fatal("API/MCP evidence changed authorized source/receipt")
		}
	}
	apiEvents, _ := json.Marshal(apiTrace.Events)
	agentEvents, _ := json.Marshal(agentTrace.Events)
	senderEvents, _ := json.Marshal(senderTrace.Events)
	if !bytes.Equal(apiEvents, agentEvents) || !bytes.Equal(apiEvents, senderEvents) {
		t.Fatal("shared surfaces changed immutable evidence times or identities")
	}
	if bytes.Contains(traceRaw, tokenB.Bytes) || bytes.Contains(traceRaw, sourceBytes) || bytes.Contains(traceRaw, []byte(service.Disk.Identity())) || bytes.Contains(traceRaw, []byte("payload")) {
		t.Fatal("evidence disclosed private content,credential,storage or raw event")
	}
	call(other, "exchange_trace", map[string]any{"exchange_id": offer.Exchange.ID, "direction": "incoming"}, false)
	call(b, "exchange_trace", map[string]any{"exchange_id": offer.Exchange.ID, "direction": "outgoing"}, false)
	if traceSnapshot() != traceBefore {
		t.Fatal("evidence reads created domain events,views,receipts or intents")
	}
	copyRequest := store.ExchangeCopyRequest{ExchangeCopyOrigin: store.ExchangeCopyOrigin{ExchangeID: offer.Exchange.ID, RequestHash: offer.Exchange.RequestHash, Artifact: request.Artifact}, Path: "/mcp-owned-copy.dat"}
	copyArgs := map[string]any{"request": copyRequest, "request_key": "mcp-copy-original"}
	call(a, "copy_received_artifact", copyArgs, false)
	call(other, "copy_received_artifact", copyArgs, false)
	var copied, copiedReplay custody.ExchangeCopyResult
	mcpDecodeResult(t, call(b, "copy_received_artifact", copyArgs, true), &copied)
	if copied.Replayed || copied.Artifact.ID == request.Artifact.ID || copied.Artifact.SHA256 != request.Artifact.SHA256 || copied.Artifact.Size != request.Artifact.Size || copied.Source != copyRequest.ExchangeCopyOrigin || copied.CurrentState != "not-checked" || copied.ReceiverPersistence != "unknown" || copied.BusinessProcessing != "unknown" {
		t.Fatal("MCP copy changed custody or invented a stronger receipt")
	}
	_, copyRaw := exchangeAPIRequest(t, server, "POST", prefix+"/exchange-copies", cookieB, map[string]string{"Origin": server.URL, "X-CSRF-Token": csrfB, "Idempotency-Key": "mcp-copy-original"}, exchangeAPIJSON(t, copyRequest), 200)
	if json.Unmarshal(copyRaw, &copiedReplay) != nil || !copiedReplay.Replayed || copiedReplay.EventID != copied.EventID || copiedReplay.Artifact != copied.Artifact || bytes.Contains(copyRaw, sourceBytes) || bytes.Contains(copyRaw, tokenB.Bytes) || bytes.Contains(copyRaw, []byte(service.Disk.Identity())) {
		t.Fatal("API/MCP copy original receipt differs or discloses private bytes")
	}
	_, copyBytes := exchangeAPIRequest(t, server, "GET", prefix+"/files/"+copied.Artifact.ID, nil, map[string]string{"Authorization": "Bearer " + string(tokenB.Bytes)}, nil, 200)
	if !bytes.Equal(copyBytes, sourceBytes) {
		t.Fatal("independent HTTPS copy observer differs")
	}
	mcpDecodeResult(t, call(b, "copy_received_artifact", copyArgs, true), &copiedReplay)
	if !copiedReplay.Replayed || copiedReplay.EventID != copied.EventID || copiedReplay.Artifact != copied.Artifact {
		t.Fatal("MCP copy retry changed original identity")
	}
	changedCopy := copyRequest
	changedCopy.Path = "/changed-target.dat"
	call(b, "copy_received_artifact", map[string]any{"request": changedCopy, "request_key": "mcp-copy-original"}, false)
	call(b, "copy_received_artifact", map[string]any{"request": copyRequest, "request_key": "mcp-copy-overwrite"}, false)
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
	// The old view's recipient stamp is now stale. Own-copy receipt recovery
	// still uses current ordinary write/owned-receipt access without reopening it.
	mcpDecodeResult(t, call(b, "copy_received_artifact", copyArgs, true), &copiedReplay)
	if !copiedReplay.Replayed || copiedReplay.Artifact != copied.Artifact || copiedReplay.EventID != copied.EventID {
		t.Fatal("stale source view prevented owned copy receipt recovery")
	}
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
	// The operator provisions connections and separately approves the onward
	// workflow. A tool proposal creates only an ordinary unapproved draft.
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
	reviewDefinition := workflow.Definition{Schema: 1, Name: "MCP draft proposal", Steps: []workflow.Step{{ID: "send", Kind: "sftp.deliver", Connection: workflow.Reference{ID: connection.ID, Version: connection.Version, Hash: connection.Hash}, Filename: "proposal.bin"}}}
	workflowSnapshot := func() [5]int {
		t.Helper()
		tx, err := service.DB.Begin(ctx, scope)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Tx.Rollback(ctx)
		var counts [5]int
		if err = tx.Tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM workflow_revisions),(SELECT count(*) FROM workflow_receipts),(SELECT count(*) FROM events),(SELECT count(*) FROM workflow_runs),(SELECT count(*) FROM delivery_intents)`).Scan(&counts[0], &counts[1], &counts[2], &counts[3], &counts[4]); err != nil {
			t.Fatal(err)
		}
		return counts
	}
	beforeValidation := workflowSnapshot()
	previewRequest := workflow.PreviewRequest{Definition: reviewDefinition}
	var reviewMetadata map[string]any
	mcpDecodeResult(t, call(operator, "validate_workflow", map[string]any{"request": previewRequest}, true), &reviewMetadata)
	_, previewRaw := exchangeAPIRequest(t, server, "POST", prefix+"/workflows/validate", cookie, map[string]string{"Origin": server.URL, "X-CSRF-Token": csrf}, exchangeAPIJSON(t, previewRequest), 200)
	var ordinaryPreview workflow.Preview
	if json.Unmarshal(previewRaw, &ordinaryPreview) != nil || reviewMetadata["definition_hash"] != ordinaryPreview.Hash || reviewMetadata["durable_effects"] != "none" || reviewMetadata["storage_verification"] != "not-checked" || reviewMetadata["approval_required"] != true {
		t.Fatal("MCP validation changed ordinary plan or claimed effects")
	}
	call(a, "validate_workflow", map[string]any{"request": previewRequest}, false)
	if workflowSnapshot() != beforeValidation {
		t.Fatal("validation created durable state")
	}
	draftRequest := workflow.DraftRequest{Definition: reviewDefinition}
	draftArgs := map[string]any{"request": draftRequest, "request_key": "mcp-proposal-original"}
	var proposed, replayedProposal map[string]any
	mcpDecodeResult(t, call(operator, "propose_workflow", draftArgs, true), &proposed)
	mcpDecodeResult(t, call(operator, "propose_workflow", draftArgs, true), &replayedProposal)
	if proposed["definition_hash"] != ordinaryPreview.Hash || proposed["accepted_state"] != "draft" || proposed["current_state"] != "not-checked" || proposed["approval_required"] != true || proposed["external_contact"] != false || proposed["replayed"] != false || replayedProposal["workflow_id"] != proposed["workflow_id"] || replayedProposal["replayed"] != true {
		t.Fatal("proposal replay changed identity or supplied approval")
	}
	call(a, "propose_workflow", draftArgs, false)
	changedDraft := draftRequest
	changedDraft.Definition.Name = "Changed draft meaning"
	call(operator, "propose_workflow", map[string]any{"request": changedDraft, "request_key": "mcp-proposal-original"}, false)
	_, draftRaw := exchangeAPIRequest(t, server, "POST", prefix+"/workflows/drafts", cookie, map[string]string{"Origin": server.URL, "X-CSRF-Token": csrf, "Idempotency-Key": "mcp-proposal-original"}, exchangeAPIJSON(t, draftRequest), 200)
	var ordinaryDraft workflow.Result
	if json.Unmarshal(draftRaw, &ordinaryDraft) != nil || !ordinaryDraft.Replayed {
		t.Fatal("ordinary API lost same proposal receipt")
	}
	var originalDraft store.Configuration
	if json.Unmarshal(ordinaryDraft.Resource, &originalDraft) != nil || originalDraft.ID != proposed["workflow_id"] || originalDraft.State != "draft" || originalDraft.Hash != ordinaryPreview.Hash || originalDraft.ApprovalAuthority != 0 {
		t.Fatal("proposal was approved or changed original configuration")
	}
	afterProposal := workflowSnapshot()
	if afterProposal != [5]int{beforeValidation[0] + 1, beforeValidation[1] + 1, beforeValidation[2] + 2, beforeValidation[3], beforeValidation[4]} {
		t.Fatal("draft retries created extra configuration/receipt/event/run/intent state")
	}
	for _, metadata := range []map[string]any{reviewMetadata, proposed, replayedProposal} {
		wire, _ := json.Marshal(metadata)
		for _, hidden := range []string{connection.ID, "proposal.bin", "MCP draft proposal", "127.0.0.1", "/inbox", key, keyPub, hostPub, string(admin.Bytes)} {
			if bytes.Contains(wire, []byte(hidden)) {
				t.Fatal("workflow tool disclosed private plan/transport material")
			}
		}
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
	unapproved := onwardRequest
	unapproved.Workflow = workflow.Reference{ID: originalDraft.ID, Version: originalDraft.Version, Hash: originalDraft.Hash}
	beforeUnapproved := workflowSnapshot()
	call(operator, "prepare_onward", map[string]any{"request": unapproved}, false)
	call(operator, "start_onward", map[string]any{"request": unapproved, "review_hash": secure.Digest([]byte("invented approval")), "request_key": "mcp-unapproved-no-run"}, false)
	if workflowSnapshot() != beforeUnapproved {
		t.Fatal("tool draft became executable or created an intent without approval")
	}
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
