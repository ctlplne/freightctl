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

			proveFTPSCollectionAgentOnward(t, x, binary, body, original, manifest, x.listener.contacts.Load)
			if !bytes.Equal(readReceiverBytes(t, x.producer, "/inbox/one.csv"), body) {
				t.Fatal("read-only collection changed the producer bytes")
			}
		})
	}
}

func proveFTPSCollectionAgentOnward(t *testing.T, x ftpsCollectionSetup, binary string, body []byte, original *store.File, manifest *CollectionManifest, contacts func() int64) {
	t.Helper()
	f, service := x.f, x.f.s.Custody
	service.Exchanges = custody.ExchangeSettings{MaxLifetime: time.Hour, MaxSenders: 16, MaxOpenViews: 16, MaxEndpoints: 16}
	job, _ := startCollection(t, f, x.selection, "exchange-source-start")
	if contacts != nil && contacts() != 0 {
		t.Fatal("approval and queue contacted producer")
	}
	workRequest := CollectionWorkRequest{Hash: job.Hash}
	worked, err := f.s.WorkCollection(f.ctx, f.scope, job.ID, "exchange-source-capture", workRequest)
	if err != nil || worked.Replayed {
		t.Fatal("capture of the exact FTPS source failed", err)
	}
	captured := requireCollectedFTPSBytes(t, x, job.ID, body)
	input := captured.Inputs[0]
	if (contacts != nil && contacts() != 1) || captured.Job.Attempts != 1 || captured.Job.Fence != 1 || input.RunID != nil {
		t.Fatal("capture made extra producer contacts or staged a run")
	}
	captureReplay, err := f.s.WorkCollection(f.ctx, f.scope, job.ID, "exchange-source-capture", workRequest)
	if err != nil || !captureReplay.Replayed || !bytes.Equal(captureReplay.Resource, worked.Resource) || (contacts != nil && contacts() != 1) {
		t.Fatal("capture retry changed the original receipt or contacted the producer", err)
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
	header := filepath.Join(t.TempDir(), "agent.headers")
	err = os.WriteFile(header, []byte("Authorization: Bearer "+string(secret.Bytes)+"\n"), 0600)
	secret.Close()
	if err != nil {
		t.Fatal(err)
	}
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
	limits, maxEndpoints, err := service.ExchangeLimits()
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := service.DB.RegisterExchangeEndpoint(f.ctx, f.scope, "register-collection-recipient", store.ExchangeEndpointCommand{
		Operation: "create", ID: secure.NewID(), Definition: &store.ExchangeEndpointDefinition{
			Schema: 1, Profile: "custody-https-poll-v1", Recipient: participant(agent), Senders: []store.ExchangeParticipant{participant(f.scope)},
		}}, limits, maxEndpoints)
	if err != nil {
		t.Fatal(err)
	}

	// The sender reviews an exact captured input through the ordinary CLI.
	// A receiver token cannot see the actor-private collection source.
	var beforeReview, afterReview int
	if err = f.admin.QueryRow(f.ctx, `SELECT count(*) FROM events`).Scan(&beforeReview); err != nil {
		t.Fatal(err)
	}
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
		source.Origin.Workflow != x.workflow || source.Origin.ManifestHash != manifestHash || source.Origin.ProducerBatch != manifest.Batch ||
		source.Origin.InputID != input.ID || source.Origin.InputIdentity != input.Identity || source.Artifact.ID != *input.FileID ||
		source.Artifact.ID == original.ID || source.Artifact.Size != original.Size || source.Artifact.SHA256 != original.SHA256 ||
		bytes.Contains(reviewRaw, []byte("one.csv")) || bytes.Contains(reviewRaw, []byte(service.Disk.Identity())) {
		t.Fatalf("source review lost or over-disclosed collected evidence; output_sha256=%s; error=%v", secure.Digest(reviewRaw), err)
	}
	if err = f.admin.QueryRow(f.ctx, `SELECT count(*) FROM events`).Scan(&afterReview); err != nil || afterReview != beforeReview || (contacts != nil && contacts() != 1) {
		t.Fatal("source review generated a domain event or contacted the producer", err)
	}
	request := store.ExchangeRequest{Schema: 1, Artifact: source.Artifact, Endpoint: store.ExchangeEndpointReference{
		ID: endpoint.Endpoint.ID, Revision: endpoint.Endpoint.Revision, Hash: endpoint.Endpoint.Hash,
	}, ExpiresAt: time.Now().UTC().Add(2 * time.Minute).Truncate(time.Microsecond), Receipt: "availability-only-v1"}
	if _, err = service.OfferExchange(f.ctx, agent, "receive-does-not-authorize-offer", request); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("receiving identity gained delivery authority", err)
	}
	offer, err := service.OfferExchange(f.ctx, f.scope, "collected-artifact-offer", request)
	if err != nil || offer.Replayed {
		t.Fatal("separately registered receive offer failed", err)
	}
	replay, err := service.OfferExchange(f.ctx, f.scope, "collected-artifact-offer", request)
	if err != nil || !replay.Replayed || replay.Exchange.ID != offer.Exchange.ID || replay.Exchange.EventID != offer.Exchange.EventID {
		t.Fatal("offer retry replaced the original view", err)
	}
	curl := collectedExchangeStockClient(t, f, binary, header)
	prefix := "/v1/tenants/" + f.scope.Tenant + "/partners/" + f.scope.Partner
	incoming := prefix + "/exchange-endpoints/" + endpoint.Endpoint.ID + "/incoming"
	var page store.ArtifactExchangePage
	if err = json.Unmarshal(curl(incoming+"?limit=1", 200), &page); err != nil || len(page.Exchanges) != 1 || page.Exchanges[0].ID != offer.Exchange.ID {
		t.Fatal("stock recipient did not discover the exact allowed view", err)
	}
	receive := prefix + "/exchanges/" + offer.Exchange.ID + "/file"
	if actual := curl(receive, 200); !bytes.Equal(actual, body) || secure.Digest(actual) != source.Artifact.SHA256 {
		t.Fatal("stock recipient saved different bytes")
	}
	curl(prefix+"/files/"+source.Artifact.ID, 404)
	trace, err := service.TraceExchange(f.ctx, agent, store.ExchangeTraceRequest{ID: offer.Exchange.ID, Direction: "incoming"})
	if err != nil || trace.Artifact == nil || *trace.Artifact != source.Artifact || trace.RequestHash != offer.Exchange.RequestHash ||
		len(trace.Events) != 2 || trace.Events[0].Kind != "custody-acceptance" || trace.Events[0].Resource != source.Artifact.ID ||
		trace.Events[1].Kind != "availability-offer" || trace.Events[1].ID != offer.Exchange.EventID ||
		trace.Retrieval != "unknown" || trace.ReceiverPersistence != "unknown" || trace.BusinessProcessing != "unknown" {
		t.Fatal("availability receipt overstated its evidence", err)
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
	copyArgs := append([]string{"exchange-copy", "--request-file", copyJSON,
		"--idempotency-key", "copy-for-separate-custody", "--token-file", token}, selectors...)
	copyArtifact := func() custody.ExchangeCopyResult {
		t.Helper()
		output, err := exec.CommandContext(f.ctx, binary, copyArgs...).Output()
		var copied custody.ExchangeCopyResult
		if err != nil || json.Unmarshal(output, &copied) != nil {
			t.Fatalf("stock CLI copy did not return a receipt; output_sha256=%s; error=%v", secure.Digest(output), err)
		}
		return copied
	}
	owned := copyArtifact()
	if owned.Replayed || owned.Artifact.ID == source.Artifact.ID || owned.Artifact.ID == original.ID ||
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

	grant := store.AccountCommand{Operation: "update", ID: account.ID, ExpectedRevision: 1,
		Policy: &store.AccountPolicy{Label: "Receiving and sending agent", Root: "/", Permissions: []string{
			"read", "list", "write", "deliver", "workflow_manage", "workflow_approve", "workflow_execute",
		}}}
	if _, err = service.DB.ChangeAccount(f.ctx, f.scope, "explicit-onward-execution-grant", grant); err != nil {
		t.Fatal(err)
	}
	curl(receive, 404)
	agentFixture := *f
	agentFixture.scope = agent
	stock := newMixedStockReceiver(t, f)
	provisioned, control := provisionStockRoute(t, f, binary, agent, account.ID, stock)
	ownedReplay := copyArtifact()
	if !ownedReplay.Replayed || ownedReplay.Artifact != owned.Artifact || ownedReplay.EventID != owned.EventID {
		t.Fatal("recovering owned copy reopened or replaced the original view")
	}
	queued := requireAgentStockOnward(t, &agentFixture, stock, provisioned.Connection, source.Artifact, owned.Artifact)
	beforeRevoke := stock.sessions(t)
	revoke := ConnectionProvisionCommand{Operation: "revoke", Connection: &provisioned.Connection, ProvisionEvent: provisioned.EventID}
	revoked, first := control("revoke-agent-route", revoke)
	if first.Replayed || revoked.State != "revoked" || revoked.Revision != 2 || revoked.Connection != provisioned.Connection || revoked.ProvisionEvent != provisioned.EventID {
		t.Fatal("operator revoke did not preserve the original route binding")
	}
	repeat, again := control("revoke-agent-route", revoke)
	if !again.Replayed || repeat != revoked {
		t.Fatal("operator revoke retry changed the original receipt")
	}
	if _, err = f.s.Work(f.ctx, agent, queued, "work-after-provision-revoked"); !errors.Is(err, store.ErrState) || stock.sessions(t) != beforeRevoke {
		t.Fatal("revoked route permitted queued work or receiver contact", err)
	}
	after, err := service.DB.Identity(f.ctx, agent)
	if err != nil || after.AuthorityRevision != provisioned.RecipientAuthority || slices.Contains(after.Permissions, "admin") || slices.Contains(after.Permissions, "connections_manage") {
		t.Fatal("connection provisioning changed agent authority", err)
	}

	if contacts != nil && contacts() != 1 {
		t.Fatal("review, receipt recovery or onward delivery contacted the producer")
	}
}

func collectedExchangeStockClient(t *testing.T, f *fixture, binary, header string) func(string, int) []byte {
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
	return func(route string, status int) []byte {
		t.Helper()
		output := filepath.Join(t.TempDir(), "response")
		if err := os.WriteFile(output, nil, 0600); err != nil {
			t.Fatal(err)
		}
		// The product listener requires TLS 1.3. Some stock curl TLS backends
		// negotiate it but cannot set an explicit client-side version override.
		command := exec.CommandContext(f.ctx, "curl", "--disable", "--silent", "--show-error", "--noproxy", "*",
			"--proto", "=https", "--cacert", cert, "--max-time", "10", "--header", "@"+header,
			"--max-filesize", "32768", "--output", output, "--write-out", "%{http_code} %{ssl_verify_result}", "https://"+address+route)
		data, err := command.CombinedOutput()
		if err != nil || string(data) != strconv.Itoa(status)+" 0" {
			t.Fatalf("stock HTTPS status or certificate verification differs; expected %d; output_sha256=%s; error=%v", status, secure.Digest(data), err)
		}
		body, err := os.ReadFile(output)
		if err != nil || len(body) > 32768 {
			t.Fatal("stock HTTPS response unavailable or outside its bound", err)
		}
		return body
	}
}

func requireAgentStockOnward(t *testing.T, agent *fixture, stock *mixedStockReceiver, connection Reference, original, owned store.ExchangeArtifact) string {
	t.Helper()
	scope := agent.scope
	definition := Definition{Schema: 1, Name: "Send separately approved owned artifact", Steps: []Step{{
		ID: "send", Kind: "sftp.deliver", Connection: connection, Filename: "agent-owned.csv",
	}}}
	configuration := agent.approved(t, definition)
	request := OnwardRequest{Schema: 1, Profile: OnwardProfile,
		Workflow: Reference{ID: configuration.ID, Version: configuration.Version, Hash: configuration.Hash}, Artifact: original}
	if _, err := agent.s.PrepareOnward(agent.ctx, scope, request); !errors.Is(err, store.ErrNotFound) && !errors.Is(err, store.ErrForbidden) {
		t.Fatal("onward preparation could directly reuse a received artifact", err)
	}
	request.Artifact = owned
	review, err := agent.s.PrepareOnward(agent.ctx, scope, request)
	if err != nil || review.ExternalContact || len(review.Effects) != 1 || review.Effects[0].Connection != connection || stock.sessions(t) != 0 {
		t.Fatal("approved exact owned copy review contacted the receiver or selected another route", err)
	}
	start := OnwardStart{Request: request, ReviewHash: review.ReviewHash}
	result, err := agent.s.StartOnward(agent.ctx, scope, "approve-and-queue-owned-onward", start)
	var run OnwardRunReceipt
	if err != nil || result.Replayed || json.Unmarshal(result.Resource, &run) != nil || run.FileID != owned.ID || stock.sessions(t) != 0 {
		t.Fatal("only the separately approved owned revision should queue", err)
	}
	worked, err := agent.s.Work(agent.ctx, scope, run.ID, "execute-owned-onward")
	if err != nil || worked.Status.ObservedState != "succeeded" || len(worked.Status.Steps) != 1 {
		t.Fatal("approved stock onward workflow failed", err)
	}
	resultingDelivery, err := (&delivery.Service{Custody: agent.s.Custody}).Status(agent.ctx, scope, worked.Status.Steps[0].DeliveryID)
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
	replay, err := agent.s.StartOnward(agent.ctx, scope, "approve-and-queue-owned-onward", start)
	if err != nil || !replay.Replayed || !bytes.Equal(replay.Resource, result.Resource) || stock.sessions(t) != contacts {
		t.Fatal("original onward receipt recovery repeated the external effect", err)
	}
	again, err := agent.s.Work(agent.ctx, scope, run.ID, "execute-owned-onward")
	if err != nil || !again.Replayed || again.Dispatch != worked.Dispatch || stock.sessions(t) != contacts {
		t.Fatal("original worker key resent bytes to the receiver", err)
	}
	stock.requireBytes(t, agent, resultingDelivery.ID+"-agent-owned.csv")
	waiting, err := agent.s.StartOnward(agent.ctx, scope, "queued-before-operator-revoke", start)
	var pending OnwardRunReceipt
	if err != nil || json.Unmarshal(waiting.Resource, &pending) != nil || pending.ID == run.ID || pending.State != "queued" {
		t.Fatal("could not leave one ordinary intent queued for the revocation check", err)
	}
	return pending.ID
}
