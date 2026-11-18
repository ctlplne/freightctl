//go:build integration && (linux || darwin)

package workflow

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/delivery"
	"github.com/ctlplne/freightctl/internal/store"
)

// The producer serves a separate freightctl FTPS database and disk over real
// TLS. A stock HTTPS caller receives the collected revision. The final stock
// SFTP receiver owns a separate filesystem and SSH identity.
func TestFTPSCollectionToAgentAndSeparatelyApprovedStockSFTP(t *testing.T) {
	binary := routingKeyCLI(t)
	for _, implicit := range []bool{false, true} {
		t.Run(fmt.Sprintf("implicit-%t", implicit), func(t *testing.T) {
			x := newFTPSCollection(t, implicit, false, false)
			body := []byte("abc")
			original := publishFTPSCollectionObject(t, x, "one.csv", body)
			manifest := publishFTPSCollectionManifest(t, x, x.source.Manifest, []CollectionFile{{Name: "one.csv", Size: int64(len(body)), SHA256: original.SHA256}})

			proveCollectionAgentOnward(t, x.f, x.selection, binary, body, original.ID, manifest, x.listener.contacts.Load)
			if !bytes.Equal(readReceiverBytes(t, x.producer, "/inbox/one.csv"), body) {
				t.Fatal("read-only collection changed the producer bytes")
			}
		})
	}
}

func proveCollectionAgentOnward(t *testing.T, f *fixture, selection CollectionSelection, binary string, body []byte, sourceFileID string, manifest *CollectionManifest, contacts func() int64) {
	t.Helper()
	service := f.s.Custody
	service.Exchanges = custody.ExchangeSettings{MaxLifetime: time.Hour, MaxSenders: 16, MaxOpenViews: 16, MaxEndpoints: 16}
	client := collectedExchangeStockClient(t, f, binary)
	sender := client(f.tokenPath)
	job := captureCollectionOverHTTPS(t, sender, selection, contacts)
	captured := requireCollectedBytes(t, f, job.ID, body)
	input := captured.Inputs[0]
	if (contacts != nil && contacts() != 1) || captured.Job.Attempts != 1 || captured.Job.Fence != 1 || input.RunID != nil {
		t.Fatal("capture made extra producer contacts or staged a run")
	}
	// A normal partner-readable collection path can independently grant
	// access. Make this source owner-only before testing the receive view.
	entry, err := service.StatPath(f.ctx, f.scope, input.Target)
	if err != nil {
		t.Fatal(err)
	}
	mode := uint32(0600)
	if _, err = service.PathCommand(f.ctx, f.scope, "protect-collected-source", store.PathCommand{
		Operation: "setstat", Path: input.Target, Mode: &mode, ExpectedRevision: &entry.Revision,
	}); err != nil {
		t.Fatal("cannot bind the collected namespace entry to owner-only access", err)
	}

	token := filepath.Join(t.TempDir(), "agent.token")
	if err = secure.WriteToken(token); err != nil {
		t.Fatal(err)
	}
	secret, err := secure.ReadSecret(token, 64)
	if err != nil {
		t.Fatal(err)
	}
	proof := secure.Digest(secret.Bytes)
	secret.Close()
	curl := client(token)
	account := store.AccountCommand{Operation: "create", ID: secure.NewID(), CredentialHash: proof,
		Policy: &store.AccountPolicy{Label: "Receiving agent", Root: "/", Permissions: []string{"read", "list", "write"}}}
	if _, err = service.DB.ChangeAccount(f.ctx, f.scope, "enroll-receiving-agent", account); err != nil {
		t.Fatal(err)
	}
	agent := store.Scope{Tenant: f.scope.Tenant, Partner: f.scope.Partner, TokenHash: proof}
	if _, stream, err := service.OpenFileReader(f.ctx, agent, *input.FileID); !errors.Is(err, store.ErrNotFound) {
		if stream != nil {
			stream.Close()
		}
		t.Fatal("recipient fixture already has ordinary access to the captured source", err)
	}
	participant := func(scope store.Scope) store.ExchangeParticipant {
		t.Helper()
		id, err := service.DB.Identity(f.ctx, scope)
		if err != nil {
			t.Fatal(err)
		}
		return store.ExchangeParticipant{Tenant: scope.Tenant, Partner: scope.Partner, Actor: id.Actor,
			AuthorityRevision: id.AuthorityRevision, RootPolicyDigest: id.RootPolicyDigest}
	}
	endpointRequest := store.ExchangeEndpointCommand{
		Operation: "create", ID: secure.NewID(), Definition: &store.ExchangeEndpointDefinition{
			Schema: 1, Profile: "custody-https-poll-v1", Recipient: participant(agent), Senders: []store.ExchangeParticipant{participant(f.scope)},
		}}
	endpoint := readStockExchangeJSON[store.ExchangeEndpointResult](t, sender("/exchange-endpoints/commands", "register-collection-recipient", endpointRequest, 200))
	if endpoint.Replayed || endpoint.Endpoint.ID != endpointRequest.ID || endpoint.Endpoint.Revision != 1 {
		t.Fatal("HTTPS endpoint enrollment returned a different revision")
	}

	// The sender reviews an exact captured input through the ordinary CLI.
	// A receiver token cannot see the actor-private collection source.
	var beforeReview, afterReview int
	if err = f.admin.QueryRow(f.ctx, `SELECT count(*) FROM events`).Scan(&beforeReview); err != nil {
		t.Fatal(err)
	}
	reviewRoute := "/workflow-collections/" + job.ID + "/inputs/" + input.ID + "/exchange-source"
	curl(reviewRoute, "", nil, 403)
	reviewWire := sender(reviewRoute, "", nil, 200)
	selectors := []string{"--dsn-file", f.runtimePath, "--tenant", f.scope.Tenant, "--partner", f.scope.Partner, "--storage", f.storagePath}
	reviewArgs := append([]string{"workflow-collection-exchange-source", "--collection-id", job.ID, "--collection-input-id", input.ID}, selectors...)
	if output, reviewErr := exec.CommandContext(f.ctx, binary, append(reviewArgs, "--token-file", token)...).Output(); reviewErr == nil || len(output) != 0 {
		t.Fatal("recipient gained the sender's collected-source metadata")
	}
	reviewRaw, err := exec.CommandContext(f.ctx, binary, append(reviewArgs, "--token-file", f.tokenPath)...).Output()
	_, manifestHash, _ := digest(manifest)
	var source CollectedExchangeSource
	if err != nil || json.Unmarshal(reviewRaw, &source) != nil || source.Profile != CollectedExchangeSourceProfile ||
		source.StorageVerification != "not-checked" || source.State != "source-review-only" ||
		source.Origin.CollectionID != job.ID || source.Origin.FirstCollectionID != job.ID || source.Origin.DefinitionHash != job.Hash ||
		source.Origin.Workflow != selection.Workflow || source.Origin.ManifestHash != manifestHash || source.Origin.ProducerBatch != manifest.Batch ||
		source.Origin.InputID != input.ID || source.Origin.InputIdentity != input.Identity || source.Artifact.ID != *input.FileID ||
		source.Artifact.ID == sourceFileID || source.Artifact.Size != int64(len(body)) || source.Artifact.SHA256 != secure.Digest(body) ||
		bytes.Contains(reviewRaw, []byte("one.csv")) || bytes.Contains(reviewRaw, []byte(service.Disk.Identity())) {
		t.Fatalf("source review lost or over-disclosed collected evidence; output_sha256=%s; error=%v", secure.Digest(reviewRaw), err)
	}
	if readStockExchangeJSON[CollectedExchangeSource](t, reviewWire) != source ||
		bytes.Contains(reviewWire, []byte("one.csv")) || bytes.Contains(reviewWire, []byte(service.Disk.Identity())) {
		t.Fatal("HTTPS and CLI source review differ or disclose private references")
	}
	if err = f.admin.QueryRow(f.ctx, `SELECT count(*) FROM events`).Scan(&afterReview); err != nil || afterReview != beforeReview || (contacts != nil && contacts() != 1) {
		t.Fatal("source review generated a domain event or contacted the producer", err)
	}
	request := store.ExchangeRequest{Schema: 1, Artifact: source.Artifact, Endpoint: store.ExchangeEndpointReference{
		ID: endpoint.Endpoint.ID, Revision: endpoint.Endpoint.Revision, Hash: endpoint.Endpoint.Hash,
	}, ExpiresAt: time.Now().UTC().Add(2 * time.Minute).Truncate(time.Microsecond), Receipt: "availability-only-v1"}
	curl("/exchanges", "receive-does-not-authorize-offer", request, 403)
	const offerKey = "collected-artifact-offer"
	offer := readStockExchangeJSON[store.ArtifactExchangeResult](t, sender("/exchanges", offerKey, request, 201))
	replay := readStockExchangeJSON[store.ArtifactExchangeResult](t, sender("/exchanges", offerKey, request, 200))
	if offer.Replayed || !replay.Replayed || replay.Exchange.ID != offer.Exchange.ID || replay.Exchange.EventID != offer.Exchange.EventID {
		t.Fatal("HTTPS offer retry replaced the original view")
	}
	incoming := "/exchange-endpoints/" + endpoint.Endpoint.ID + "/incoming"
	page := readStockExchangeJSON[store.ArtifactExchangePage](t, curl(incoming+"?limit=1", "", nil, 200))
	if len(page.Exchanges) != 1 || page.Exchanges[0].ID != offer.Exchange.ID {
		t.Fatal("stock recipient did not discover the exact allowed view")
	}
	receive := "/exchanges/" + offer.Exchange.ID + "/file"
	if actual := curl(receive, "", nil, 200); !bytes.Equal(actual, body) || secure.Digest(actual) != source.Artifact.SHA256 {
		t.Fatal("stock recipient saved different bytes")
	}
	curl("/files/"+source.Artifact.ID, "", nil, 404)
	trace := readStockExchangeJSON[store.ExchangeTrace](t, curl("/exchange-traces/previews", "", store.ExchangeTraceRequest{ID: offer.Exchange.ID, Direction: "incoming"}, 200))
	if trace.Artifact == nil || *trace.Artifact != source.Artifact || trace.RequestHash != offer.Exchange.RequestHash ||
		len(trace.Events) != 2 || trace.Events[0].Kind != "custody-acceptance" || trace.Events[0].Resource != source.Artifact.ID ||
		trace.Events[1].Kind != "availability-offer" || trace.Events[1].ID != offer.Exchange.EventID ||
		trace.Retrieval != "unknown" || trace.ReceiverPersistence != "unknown" || trace.BusinessProcessing != "unknown" {
		t.Fatal("availability receipt overstated its evidence")
	}

	copyRequest := store.ExchangeCopyRequest{ExchangeCopyOrigin: store.ExchangeCopyOrigin{
		ExchangeID: offer.Exchange.ID, RequestHash: offer.Exchange.RequestHash, Artifact: source.Artifact,
	}, Path: "/agent-owned.csv"}
	copyJSON := filepath.Join(t.TempDir(), "copy.request.json")
	copyRaw, err := json.Marshal(copyRequest)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(copyJSON, copyRaw, 0600); err != nil {
		t.Fatal(err)
	}
	const copyKey = "copy-for-separate-custody"
	copyArgs := append([]string{"exchange-copy", "--request-file", copyJSON,
		"--idempotency-key", copyKey, "--token-file", token}, selectors...)
	copyArtifact := func() custody.ExchangeCopyResult {
		t.Helper()
		output, err := exec.CommandContext(f.ctx, binary, copyArgs...).Output()
		var copied custody.ExchangeCopyResult
		if err != nil || json.Unmarshal(output, &copied) != nil {
			t.Fatalf("stock CLI copy did not return a receipt; output_sha256=%s; error=%v", secure.Digest(output), err)
		}
		return copied
	}
	owned := readStockExchangeJSON[custody.ExchangeCopyResult](t, curl("/exchange-copies", copyKey, copyRequest, 201))
	if owned.Replayed || owned.Artifact.ID == source.Artifact.ID || owned.Artifact.ID == sourceFileID ||
		owned.Artifact.SHA256 != source.Artifact.SHA256 || owned.Artifact.Size != source.Artifact.Size || owned.Source != copyRequest.ExchangeCopyOrigin {
		t.Fatal("recipient-owned copy missed the exact received source")
	}
	var rawOrigin []byte
	err = f.admin.QueryRow(f.ctx, `SELECT payload->'exchange_copy' FROM events
		WHERE tenant_id=$1 AND partner_id=$2 AND actor_id=$3 AND event_id=$4 AND resource_id=$5 AND kind='FileAccepted'`,
		f.scope.Tenant, f.scope.Partner, account.ID, owned.EventID, owned.Artifact.ID).Scan(&rawOrigin)
	var recordedOrigin store.ExchangeCopyOrigin
	if err != nil || json.Unmarshal(rawOrigin, &recordedOrigin) != nil || recordedOrigin != owned.Source {
		t.Fatal("owned copy receipt has no exact committed origin", err)
	}
	changedCopy := copyRequest
	changedCopy.Path = "/different-agent-copy.csv"
	conflict := readStockExchangeJSON[map[string]string](t, curl("/exchange-copies", copyKey, changedCopy, 409))
	if conflict["error"] != "idempotency_conflict" {
		t.Fatal("HTTPS copy reuse with a changed destination lost its operation conflict")
	}

	grant := store.AccountCommand{Operation: "update", ID: account.ID, ExpectedRevision: 1,
		Policy: &store.AccountPolicy{Label: "Receiving and sending agent", Root: "/", Permissions: []string{
			"read", "list", "write", "deliver", "workflow_manage", "workflow_approve", "workflow_execute",
		}}}
	if _, err = service.DB.ChangeAccount(f.ctx, f.scope, "explicit-onward-execution-grant", grant); err != nil {
		t.Fatal(err)
	}
	curl(receive, "", nil, 404)
	curl(reviewRoute, "", nil, 404)
	agentFixture := *f
	agentFixture.scope = agent
	stock := newMixedStockReceiver(t, f)
	provisioned, control := provisionStockRoute(t, f, binary, sender, curl, agent, account.ID, stock)
	ownedReplay := copyArtifact()
	if !ownedReplay.Replayed || ownedReplay.Artifact != owned.Artifact || ownedReplay.EventID != owned.EventID {
		t.Fatal("recovering owned copy reopened or replaced the original view")
	}
	queued := requireAgentStockOnward(t, &agentFixture, curl, stock, provisioned.Connection, source.Artifact, owned.Artifact)
	beforeRevoke := stock.sessions(t)
	revoke := ConnectionProvisionCommand{Operation: "revoke", Connection: &provisioned.Connection, ProvisionEvent: provisioned.EventID}
	curl("/connections/provisioning/commands", "recipient-cannot-revoke-provision", revoke, 403)
	revoked, first := control("revoke-agent-route", revoke)
	if first.Replayed || revoked.State != "revoked" || revoked.Revision != 2 || revoked.Connection != provisioned.Connection || revoked.ProvisionEvent != provisioned.EventID {
		t.Fatal("operator revoke did not preserve the original route binding")
	}
	repeat, again := control("revoke-agent-route", revoke)
	if !again.Replayed || repeat != revoked {
		t.Fatal("operator revoke retry changed the original receipt")
	}
	curl("/onward/work", "work-after-provision-revoked", queued, 409)
	if stock.sessions(t) != beforeRevoke {
		t.Fatal("revoked route permitted queued work or receiver contact")
	}
	after, err := service.DB.Identity(f.ctx, agent)
	if err != nil || after.AuthorityRevision != provisioned.RecipientAuthority || slices.Contains(after.Permissions, "admin") || slices.Contains(after.Permissions, "connections_manage") {
		t.Fatal("connection provisioning changed agent authority", err)
	}

	if contacts != nil && contacts() != 1 {
		t.Fatal("review, receipt recovery or onward delivery contacted the producer")
	}
}

func readStockExchangeJSON[T any](t *testing.T, raw []byte) T {
	t.Helper()
	var value T
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatalf("stock HTTPS response did not match its typed contract; response_sha256=%s", secure.Digest(raw))
	}
	return value
}

type stockExchangeRequest func(route, key string, body any, status int) []byte

func captureCollectionOverHTTPS(t *testing.T, sender stockExchangeRequest, selection CollectionSelection, contacts func() int64) CollectionAction {
	t.Helper()
	const route = "/workflow-collections"
	preview := readStockExchangeJSON[CollectionPreview](t, sender(route+"/preview", "", selection, 200))
	if preview.ExternalContact || !preview.ApprovalRequired || preview.Definition.Workflow != selection.Workflow {
		t.Fatal("HTTPS preview lost the exact approved source or contacted it")
	}
	start := CollectionStartRequest{Selection: selection, Hash: preview.Hash}
	const startKey = "exchange-source-start"
	queued := readStockExchangeJSON[Result](t, sender(route, startKey, start, 200))
	queueReplay := readStockExchangeJSON[Result](t, sender(route, startKey, start, 200))
	job := readStockExchangeJSON[CollectionAction](t, queued.Resource)
	if queued.Replayed || !queueReplay.Replayed || !bytes.Equal(queueReplay.Resource, queued.Resource) ||
		!store.ValidID(job.ID) || job.Hash != preview.Hash || job.State != "queued" || (contacts != nil && contacts() != 0) {
		t.Fatal("HTTPS queue changed the original receipt or contacted the producer")
	}
	workRoute := route + "/" + job.ID + "/work"
	work := CollectionWorkRequest{Hash: job.Hash}
	const workKey = "exchange-source-capture"
	worked := readStockExchangeJSON[Result](t, sender(workRoute, workKey, work, 200))
	workReplay := readStockExchangeJSON[Result](t, sender(workRoute, workKey, work, 200))
	captured := readStockExchangeJSON[CollectionAction](t, worked.Resource)
	if worked.Replayed || !workReplay.Replayed || !bytes.Equal(workReplay.Resource, worked.Resource) ||
		captured.ID != job.ID || captured.Hash != job.Hash || captured.State != "captured" || (contacts != nil && contacts() != 1) {
		t.Fatal("HTTPS capture retry changed the original receipt or repeated source contact")
	}
	return job
}

func collectedExchangeStockClient(t *testing.T, f *fixture, binary string) func(string) stockExchangeRequest {
	t.Helper()
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "localhost.crt"), filepath.Join(dir, "localhost.key")
	if err := secure.DevCertificate(cert, key); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	log, err := os.OpenFile(filepath.Join(dir, "https.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	daemon := exec.CommandContext(f.ctx, binary, "serve", "--dsn-file", f.runtimePath, "--storage", f.storagePath,
		"--listen", address, "--cert", cert, "--key", key, "--ai-enabled=false", "--exchange-max-lifetime", "1h")
	daemon.Stdout, daemon.Stderr = log, log
	if err = daemon.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = daemon.Process.Kill()
		_ = daemon.Wait()
		_ = log.Close()
	})
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("task-owned HTTPS listener unavailable")
		}
		time.Sleep(25 * time.Millisecond)
	}
	prefix := "https://" + address + "/v1/tenants/" + f.scope.Tenant + "/partners/" + f.scope.Partner
	return func(token string) stockExchangeRequest {
		t.Helper()
		secret, err := secure.ReadSecret(token, 64)
		if err != nil {
			t.Fatal(err)
		}
		const bearer = "Authorization: Bearer "
		value := secure.ProtectBytes(make([]byte, len(bearer)+len(secret.Bytes)+1))
		copy(value.Bytes, bearer)
		copy(value.Bytes[len(bearer):], secret.Bytes)
		value.Bytes[len(value.Bytes)-1] = '\n'
		secret.Close()
		header := filepath.Join(t.TempDir(), "request.headers")
		err = os.WriteFile(header, value.Bytes, 0600)
		value.Close()
		if err != nil {
			t.Fatal(err)
		}
		return func(route, key string, body any, status int) []byte {
			t.Helper()
			output := filepath.Join(t.TempDir(), "response")
			if err := os.WriteFile(output, nil, 0600); err != nil {
				t.Fatal(err)
			}
			// The listener requires TLS 1.3. Some stock curl TLS backends
			// negotiate it without an explicit client-side version override.
			args := []string{"--disable", "--silent", "--show-error", "--noproxy", "*",
				"--proto", "=https", "--cacert", cert, "--max-time", "10", "--header", "@" + header,
				"--max-filesize", "32768", "--output", output, "--write-out", "%{http_code} %{ssl_verify_result}"}
			var raw []byte
			if body != nil {
				var err error
				raw, err = json.Marshal(body)
				if err != nil {
					t.Fatal(err)
				}
				args = append(args, "--header", "Content-Type: application/json", "--data-binary", "@-")
			}
			if key != "" {
				args = append(args, "--header", "Idempotency-Key: "+key)
			}
			command := exec.CommandContext(f.ctx, "curl", append(args, prefix+route)...)
			command.Stdin = bytes.NewReader(raw)
			data, err := command.CombinedOutput()
			if err != nil || string(data) != strconv.Itoa(status)+" 0" {
				var got, verified int
				_, _ = fmt.Sscanf(string(data), "%d %d", &got, &verified)
				t.Fatalf("stock HTTPS %s expected %d, got %d; tls_result=%d; output_sha256=%s; error=%v",
					route, status, got, verified, secure.Digest(data), err)
			}
			response, err := os.ReadFile(output)
			if err != nil || len(response) > 32768 {
				t.Fatal("stock HTTPS response unavailable or outside its bound", err)
			}
			return response
		}
	}
}

type stockOnwardAction struct {
	Start      OnwardStart `json:"start"`
	ReceiptKey string      `json:"receipt_key"`
	RunID      string      `json:"run_id"`
}

type stockOnwardWorkResult struct {
	RunID               string                 `json:"run_id"`
	Artifact            store.ExchangeArtifact `json:"artifact"`
	ObservedState       string                 `json:"observed_state"`
	ReceiverPersistence string                 `json:"receiver_persistence"`
	BusinessProcessing  string                 `json:"business_processing"`
	Replayed            bool                   `json:"replayed"`
	SelectedDeliveryID  string                 `json:"selected_delivery_id"`
	Steps               []struct {
		DeliveryID string `json:"delivery_id"`
		State      string `json:"state"`
	} `json:"steps"`
}

func requireAgentStockOnward(t *testing.T, agent *fixture, curl stockExchangeRequest, stock *mixedStockReceiver, connection Reference, original, owned store.ExchangeArtifact) stockOnwardAction {
	t.Helper()
	scope := agent.scope
	definition := Definition{Schema: 1, Name: "Send separately approved owned artifact", Steps: []Step{{
		ID: "send", Kind: "sftp.deliver", Connection: connection, Filename: "agent-owned.csv",
	}}}
	configuration := agent.approved(t, definition)
	request := OnwardRequest{Schema: 1, Profile: OnwardProfile,
		Workflow: Reference{ID: configuration.ID, Version: configuration.Version, Hash: configuration.Hash}, Artifact: original}
	curl("/onward/previews", "", request, 404)
	request.Artifact = owned
	review := readStockExchangeJSON[OnwardReview](t, curl("/onward/previews", "", request, 200))
	if review.Request != request || review.ExternalContact || len(review.Effects) != 1 || review.Effects[0].Connection != connection || stock.sessions(t) != 0 {
		t.Fatal("approved exact owned copy review contacted the receiver or selected another route")
	}
	start := OnwardStart{Request: request, ReviewHash: review.ReviewHash}
	const startKey = "approve-and-queue-owned-onward"
	result := readStockExchangeJSON[Result](t, curl("/onward/runs", startKey, start, 200))
	run := readStockExchangeJSON[OnwardRunReceipt](t, result.Resource)
	if result.Replayed || run.Profile != OnwardProfile || run.ReviewHash != review.ReviewHash || run.FileID != owned.ID || run.State != "queued" || stock.sessions(t) != 0 {
		t.Fatal("only the separately approved owned revision should queue")
	}
	action := stockOnwardAction{Start: start, RunID: run.ID, ReceiptKey: startKey}
	const workKey = "execute-owned-onward"
	worked := readStockExchangeJSON[stockOnwardWorkResult](t, curl("/onward/work", workKey, action, 200))
	if worked.Replayed || worked.RunID != run.ID || worked.Artifact != owned || worked.ObservedState != "succeeded" ||
		worked.ReceiverPersistence != "unknown" || worked.BusinessProcessing != "unknown" ||
		len(worked.Steps) != 1 || worked.Steps[0].DeliveryID != worked.SelectedDeliveryID {
		t.Fatal("approved stock onward workflow returned a different or overstated receipt")
	}
	resultingDelivery, err := (&delivery.Service{Custody: agent.s.Custody}).Status(agent.ctx, scope, worked.SelectedDeliveryID)
	var observation struct {
		SHA256             string `json:"sha256"`
		FsyncAcknowledged  bool   `json:"file_fsync_acknowledged"`
		BusinessAcceptance string `json:"business_acceptance"`
	}
	if err != nil || resultingDelivery.FileID != owned.ID || resultingDelivery.Attempts != 1 || resultingDelivery.Fence != 1 ||
		json.Unmarshal(resultingDelivery.Observation, &observation) != nil || observation.SHA256 != owned.SHA256 ||
		!observation.FsyncAcknowledged || observation.BusinessAcceptance != "unknown" {
		t.Fatal("stock onward receipt lost the exact owned revision or inflated the outcome", err)
	}
	contacts := stock.sessions(t)
	lookup := OnwardLookup{Start: start, ReceiptKey: startKey}
	replay := readStockExchangeJSON[Result](t, curl("/onward/receipts", "", lookup, 200))
	restart := readStockExchangeJSON[Result](t, curl("/onward/runs", startKey, start, 200))
	if !replay.Replayed || !restart.Replayed || !bytes.Equal(replay.Resource, result.Resource) ||
		!bytes.Equal(restart.Resource, result.Resource) || stock.sessions(t) != contacts {
		t.Fatal("original onward receipt recovery repeated the external effect")
	}
	again := readStockExchangeJSON[stockOnwardWorkResult](t, curl("/onward/work", workKey, action, 200))
	worked.Replayed = true
	if !reflect.DeepEqual(again, worked) || stock.sessions(t) != contacts {
		t.Fatal("original worker key changed the result or resent bytes to the receiver")
	}
	stock.requireBytes(t, agent, resultingDelivery.ID+"-agent-owned.csv")
	const pendingKey = "queued-before-operator-revoke"
	waiting := readStockExchangeJSON[Result](t, curl("/onward/runs", pendingKey, start, 200))
	pending := readStockExchangeJSON[OnwardRunReceipt](t, waiting.Resource)
	if waiting.Replayed || pending.ID == run.ID || pending.State != "queued" {
		t.Fatal("could not leave one ordinary intent queued for the revocation check")
	}
	return stockOnwardAction{Start: start, RunID: pending.ID, ReceiptKey: pendingKey}
}
