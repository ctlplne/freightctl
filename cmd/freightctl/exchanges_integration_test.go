//go:build integration

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
	"github.com/jackc/pgx/v5"
)

func TestArtifactExchangeCLIUsesOrdinaryAuthorityAndPublishesVerifiedDownload(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	adminRef, runtimeRef := os.Getenv("FREIGHTCTL_TEST_ADMIN_FILE"), os.Getenv("FREIGHTCTL_TEST_RUNTIME_FILE")
	if adminRef == "" || runtimeRef == "" {
		t.Fatal("actual task-owned PostgreSQL references required")
	}
	secret, err := secure.ReadSecret(adminRef, 4096)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := pgx.Connect(ctx, string(secret.Bytes))
	secret.Close()
	if err != nil {
		t.Fatal("fixture administration connection failed")
	}
	database := "freightctl_cli_exchange_" + strings.ReplaceAll(secure.NewID(), "-", "")
	if _, err = admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{database}.Sanitize()); err != nil {
		admin.Close(ctx)
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+pgx.Identifier{database}.Sanitize()+" WITH (FORCE)"); err != nil {
			t.Error(err)
		}
		admin.Close(cleanup)
	})
	refs := []string{}
	for _, original := range []string{adminRef, runtimeRef} {
		value, err := secure.ReadSecret(original, 4096)
		if err != nil {
			t.Fatal(err)
		}
		dsn, err := url.Parse(string(value.Bytes))
		value.Close()
		if err != nil {
			t.Fatal("fixture reference parse failed")
		}
		dsn.Path = "/" + database
		path := filepath.Join(t.TempDir(), "database.dsn")
		if err = os.WriteFile(path, []byte(dsn.String()), 0600); err != nil {
			t.Fatal(err)
		}
		refs = append(refs, path)
	}
	if err = store.Migrate(ctx, refs[0], filepath.Join(filepath.Dir(adminRef), "pg-runtime-password")); err != nil {
		t.Fatal(err)
	}
	adminToken := filepath.Join(t.TempDir(), "admin.token")
	if err = secure.WriteToken(adminToken); err != nil {
		t.Fatal(err)
	}
	scope := store.Scope{Tenant: secure.NewID(), Partner: secure.NewID()}
	if err = store.Provision(ctx, refs[0], scope.Tenant, scope.Partner, adminToken); err != nil {
		t.Fatal(err)
	}
	value, err := secure.ReadSecret(adminToken, 64)
	if err != nil {
		t.Fatal(err)
	}
	scope.TokenHash = secure.Digest(value.Bytes)
	value.Close()
	db, err := store.Open(ctx, refs[1])
	if err != nil {
		t.Fatal(err)
	}
	defer db.Pool.Close()
	storage := filepath.Join(t.TempDir(), "custody")
	disk, err := custody.Open(storage)
	if err != nil {
		t.Fatal(err)
	}
	defer disk.Close()
	service := &custody.Service{DB: db, Disk: disk, MaxFile: 1 << 20, MaxStored: 16 << 20}
	participant := func(permissions []string) (string, store.Scope, store.ExchangeParticipant) {
		path := filepath.Join(t.TempDir(), "participant.token")
		if err := secure.WriteToken(path); err != nil {
			t.Fatal(err)
		}
		credential, err := secure.ReadSecret(path, 64)
		if err != nil {
			t.Fatal(err)
		}
		proof := secure.Digest(credential.Bytes)
		credential.Close()
		id := secure.NewID()
		_, err = db.ChangeAccount(ctx, scope, "create-"+id, store.AccountCommand{Operation: "create", ID: id, CredentialHash: proof, Policy: &store.AccountPolicy{Label: "CLI participant", Root: "/", Permissions: permissions}})
		if err != nil {
			t.Fatal(err)
		}
		s := store.Scope{Tenant: scope.Tenant, Partner: scope.Partner, TokenHash: proof}
		identity, err := db.Identity(ctx, s)
		if err != nil {
			t.Fatal(err)
		}
		return path, s, store.ExchangeParticipant{Tenant: s.Tenant, Partner: s.Partner, Actor: identity.Actor, AuthorityRevision: identity.AuthorityRevision, RootPolicyDigest: identity.RootPolicyDigest}
	}
	a, sourceScope, actorA := participant([]string{"read", "write", "list", "deliver"})
	b, _, actorB := participant([]string{"read", "list"})
	other, _, _ := participant([]string{"read", "list"})
	command := func(token, name string, extra ...string) ([]byte, error) {
		t.Helper()
		output, err := os.CreateTemp(t.TempDir(), "command-output-*")
		if err != nil {
			t.Fatal(err)
		}
		previous := os.Stdout
		os.Stdout = output
		defer func() { os.Stdout = previous; output.Close() }()
		args := []string{name, "-dsn-file", refs[1], "-token-file", token, "-tenant", scope.Tenant, "-partner", scope.Partner, "-storage", storage, "-max-file-bytes", "1048576", "-exchange-max-lifetime", "1h", "-exchange-max-endpoints", "16"}
		err = run(append(args, extra...))
		if _, e := output.Seek(0, 0); e != nil {
			t.Fatal(e)
		}
		body, e := io.ReadAll(io.LimitReader(output, (32<<10)+1))
		if e != nil || len(body) > 32<<10 {
			t.Fatal("CLI result exceeded contract")
		}
		return body, err
	}
	requestFile := func(body any) string {
		t.Helper()
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "request.json")
		if err = os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	endpointCommand := store.ExchangeEndpointCommand{Operation: "create", ID: secure.NewID(), Definition: &store.ExchangeEndpointDefinition{Schema: 1, Profile: "custody-https-poll-v1", Recipient: actorB, Senders: []store.ExchangeParticipant{actorA}}}
	input := requestFile(endpointCommand)
	if _, err = command(a, "exchange-endpoint-command", "-request-file", input, "-idempotency-key", "register"); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("sender registered receive permissions", err)
	}
	body, err := command(adminToken, "exchange-endpoint-command", "-request-file", input, "-idempotency-key", "register")
	var endpoint store.ExchangeEndpointResult
	if err != nil || json.Unmarshal(body, &endpoint) != nil || endpoint.Endpoint.ID != endpointCommand.ID {
		t.Fatal("CLI registration failed", err)
	}
	body, err = command(b, "exchange-endpoint-list", "-exchange-limit", "1")
	var directory store.ExchangeEndpointPage
	if err != nil || json.Unmarshal(body, &directory) != nil || len(directory.Endpoints) != 1 || directory.Endpoints[0].ID != endpointCommand.ID {
		t.Fatal("CLI endpoint directory", err)
	}
	if _, err = command(b, "exchange-endpoint-inspect", "-exchange-endpoint-id", endpointCommand.ID); err != nil {
		t.Fatal("CLI current endpoint", err)
	}
	if _, err = command(other, "exchange-endpoint-inspect", "-exchange-endpoint-id", endpointCommand.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("unrelated CLI endpoint lookup", err)
	}
	data := []byte("exact inert CLI artifact\n")
	ingressRequest := custody.IngressDescriptorRequest{Size: int64(len(data)), SHA256: secure.Digest(data), Key: "cli-source"}
	ingressRaw, err := command(a, "exchange-ingress-descriptor", "-request-file", requestFile(ingressRequest))
	var ingress custody.IngressDescriptor
	if err != nil || json.Unmarshal(ingressRaw, &ingress) != nil || ingress.Request != ingressRequest || ingress.Path != "/v1/tenants/"+scope.Tenant+"/partners/"+scope.Partner+"/files" || ingress.State != "metadata-only" || ingress.Availability != "not-checked" {
		t.Fatal("CLI metadata upload descriptor changed meaning or claimed acceptance", err)
	}
	file, _, err := service.Accept(ctx, sourceScope, "cli-source", int64(len(data)), secure.Digest(data), bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	request := store.ExchangeRequest{Schema: 1, Artifact: store.ExchangeArtifact{ID: file.ID, Size: file.Size, SHA256: file.SHA256, Policy: file.Policy}, Endpoint: store.ExchangeEndpointReference{ID: endpoint.Endpoint.ID, Revision: endpoint.Endpoint.Revision, Hash: endpoint.Endpoint.Hash}, ExpiresAt: time.Now().UTC().Add(2 * time.Minute).Truncate(time.Microsecond), Receipt: "availability-only-v1"}
	body, err = command(a, "exchange-source-inspect", "-exchange-id", file.ID)
	var source store.ExchangeArtifact
	if err != nil || json.Unmarshal(body, &source) != nil || source != request.Artifact {
		t.Fatal("CLI source review metadata", err)
	}
	if _, err = command(b, "exchange-source-inspect", "-exchange-id", file.ID); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("CLI receive-only role gained source review", err)
	}
	input = requestFile(request)
	// Discard the first command result; the original key must recover it.
	if _, err = command(a, "exchange-offer", "-request-file", input, "-idempotency-key", "offer"); err != nil {
		t.Fatal(err)
	}
	body, err = command(a, "exchange-offer", "-request-file", input, "-idempotency-key", "offer")
	var offered store.ArtifactExchangeResult
	if err != nil || json.Unmarshal(body, &offered) != nil || !offered.Replayed {
		t.Fatal("CLI original-key recovery failed", err)
	}
	body, err = command(a, "exchange-outgoing", "-exchange-limit", "1")
	var sentPage store.OutgoingExchangePage
	if err != nil || json.Unmarshal(body, &sentPage) != nil || len(sentPage.Exchanges) != 1 || sentPage.Exchanges[0].Exchange.ID != offered.Exchange.ID || sentPage.Exchanges[0].State != "offered" {
		t.Fatal("CLI sender history", err)
	}
	if _, err = command(b, "exchange-outgoing-inspect", "-exchange-id", offered.Exchange.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("recipient read sender history", err)
	}
	changed := request
	changed.Artifact.Size++
	if _, err = command(a, "exchange-offer", "-request-file", requestFile(changed), "-idempotency-key", "offer"); !errors.Is(err, store.ErrConflict) {
		t.Fatal("CLI accepted changed meaning", err)
	}
	body, err = command(b, "exchange-incoming", "-exchange-endpoint-id", endpoint.Endpoint.ID, "-exchange-limit", "1")
	var page store.ArtifactExchangePage
	if err != nil || json.Unmarshal(body, &page) != nil || len(page.Exchanges) != 1 || page.Exchanges[0].ID != offered.Exchange.ID {
		t.Fatal("CLI receive discovery failed", err)
	}
	if _, err = command(other, "exchange-inspect", "-exchange-id", offered.Exchange.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("unrelated CLI actor inspected exchange", err)
	}
	body, err = command(b, "exchange-inspect", "-exchange-id", offered.Exchange.ID)
	var incoming store.IncomingExchange
	if err != nil || json.Unmarshal(body, &incoming) != nil || incoming.State != "offered" {
		t.Fatal("CLI inspection failed", err)
	}
	traceInput := requestFile(store.ExchangeTraceRequest{ID: offered.Exchange.ID, Direction: "incoming"})
	traceRaw, err := command(b, "exchange-trace", "-request-file", traceInput)
	var trace store.ExchangeTrace
	if err != nil || json.Unmarshal(traceRaw, &trace) != nil || trace.Direction != "incoming" || trace.Artifact == nil || *trace.Artifact != request.Artifact || trace.RequestHash != offered.Exchange.RequestHash || len(trace.Events) != 2 || trace.Events[0].ID != file.EventID || trace.Events[1].ID != offered.Exchange.EventID || trace.ReceiverPersistence != "unknown" {
		t.Fatal("CLI evidence changed source/offer/receipt meaning", err)
	}
	if _, err = command(other, "exchange-trace", "-request-file", traceInput); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("unrelated CLI caller read evidence", err)
	}
	outputDirectory := t.TempDir()
	if err = os.Chmod(outputDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(outputDirectory, "received")
	if _, err = command(other, "exchange-download", "-exchange-id", offered.Exchange.ID, "-output", destination); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("unrelated CLI actor retrieved exchange", err)
	}
	if _, err = os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unauthorized retrieval left output", err)
	}
	body, err = command(b, "exchange-download", "-exchange-id", offered.Exchange.ID, "-output", destination)
	if err != nil || !bytes.Contains(body, []byte(`"evidence":"local-file-verified-and-synced"`)) {
		t.Fatal("CLI verified output failed", err)
	}
	received, err := os.ReadFile(destination)
	if err != nil || !bytes.Equal(received, data) {
		t.Fatal("CLI output differs", err)
	}
	if _, err = command(b, "exchange-download", "-exchange-id", offered.Exchange.ID, "-output", destination); err == nil {
		t.Fatal("CLI replaced existing output")
	}
	if _, err = command(b, "exchange-offer", "-request-file", input, "-idempotency-key", "forward"); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("receive authority granted forwarding", err)
	}
	closure := store.ExchangeClosureCommand{Schema: 1, ID: offered.Exchange.ID, RequestHash: offered.Exchange.RequestHash, Operation: "cancel"}
	closureFile := requestFile(closure)
	if _, err = command(b, "exchange-close", "-request-file", closureFile, "-idempotency-key", "wrong-cancel"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("CLI wrong-role cancellation", err)
	}
	body, err = command(a, "exchange-close", "-request-file", closureFile, "-idempotency-key", "cancel")
	var closed store.ExchangeClosureResult
	if err != nil || json.Unmarshal(body, &closed) != nil || closed.State != "canceled" || closed.Replayed {
		t.Fatal("CLI cancellation receipt", err)
	}
	body, err = command(a, "exchange-close", "-request-file", closureFile, "-idempotency-key", "cancel")
	var recovered store.ExchangeClosureResult
	if err != nil || json.Unmarshal(body, &recovered) != nil || !recovered.Replayed || recovered.EventID != closed.EventID {
		t.Fatal("CLI cancellation response recovery", err)
	}
	traceRaw, err = command(a, "exchange-trace", "-request-file", requestFile(store.ExchangeTraceRequest{ID: offered.Exchange.ID, Direction: "outgoing"}))
	if err != nil || json.Unmarshal(traceRaw, &trace) != nil || trace.State != "canceled" || len(trace.Events) != 3 || trace.Events[2].ID != closed.EventID || trace.Events[2].Kind != "view-canceled" {
		t.Fatal("CLI lost authorized historical closure evidence", err)
	}
	body, err = command(a, "exchange-outgoing-inspect", "-exchange-id", offered.Exchange.ID)
	var history store.OutgoingExchange
	if err != nil || json.Unmarshal(body, &history) != nil || history.State != "canceled" || history.ClosureEvent != closed.EventID || history.Retrieval != "unknown" {
		t.Fatal("CLI historical closure evidence", err)
	}
	if _, err = command(b, "exchange-download", "-exchange-id", offered.Exchange.ID, "-output", filepath.Join(outputDirectory, "must-not-exist")); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("CLI cancellation failed to stop retrieval", err)
	}
	if _, err = os.Lstat(filepath.Join(outputDirectory, "must-not-exist")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("closed view left a download file", err)
	}
	// Continue the original native CLI journey through the separately reviewed
	// ordered onward profile. It stages ordinary intents,not peer contact.
	onwardDirectory := t.TempDir()
	host, hostPub := filepath.Join(onwardDirectory, "host"), filepath.Join(onwardDirectory, "host.pub")
	key, keyPub := filepath.Join(onwardDirectory, "key"), filepath.Join(onwardDirectory, "key.pub")
	if err = secure.GenerateSSHHostIdentity(host, hostPub); err != nil {
		t.Fatal(err)
	}
	if err = secure.GenerateSSHHostIdentity(key, keyPub); err != nil {
		t.Fatal(err)
	}
	workflows := &workflow.Service{Custody: service}
	registered, err := workflows.RegisterConnection(ctx, scope, "cli-onward-connection", workflow.ConnectionRequest{Address: "127.0.0.1:9", User: "receiver", Directory: "/inbox", HostPublicFile: hostPub, KeyFile: key, KeyPublicFile: keyPub})
	if err != nil {
		t.Fatal(err)
	}
	var connection workflow.ConnectionView
	if json.Unmarshal(registered.Resource, &connection) != nil {
		t.Fatal("connection response")
	}
	draft := workflow.DraftRequest{Definition: workflow.Definition{Schema: 1, Name: "CLI onward", Steps: []workflow.Step{{ID: "send", Kind: "sftp.deliver", Connection: workflow.Reference{ID: connection.ID, Version: connection.Version, Hash: connection.Hash}, Filename: "onward.bin"}}}}
	raw, err := command(adminToken, "workflow-draft", "-request-file", requestFile(draft), "-idempotency-key", "cli-onward-draft")
	if err != nil {
		t.Fatal(err)
	}
	var draftResult workflow.Result
	var configuration store.Configuration
	if json.Unmarshal(raw, &draftResult) != nil || json.Unmarshal(draftResult.Resource, &configuration) != nil {
		t.Fatal("draft response")
	}
	if _, err = workflows.Decide(ctx, scope, configuration.ID, configuration.Version, "cli-onward-approve", "approve", workflow.Decision{Hash: configuration.Hash, Revision: configuration.Revision}); err != nil {
		t.Fatal(err)
	}
	onwardFile, _, err := service.Accept(ctx, scope, "cli-onward-source", 3, secure.Digest([]byte("new")), bytes.NewReader([]byte("new")))
	if err != nil {
		t.Fatal(err)
	}
	onward := workflow.OnwardRequest{Schema: 1, Profile: workflow.OnwardProfile, Workflow: workflow.Reference{ID: configuration.ID, Version: configuration.Version, Hash: configuration.Hash}, Artifact: store.ExchangeArtifact{ID: onwardFile.ID, Size: onwardFile.Size, SHA256: onwardFile.SHA256, Policy: onwardFile.Policy}}
	raw, err = command(adminToken, "onward-preview", "-request-file", requestFile(onward))
	if err != nil {
		t.Fatal(err)
	}
	var review workflow.OnwardReview
	if json.Unmarshal(raw, &review) != nil || review.ExternalContact || review.State != "review-only" {
		t.Fatal("CLI onward review claimed contact")
	}
	start := workflow.OnwardStart{Request: onward, ReviewHash: review.ReviewHash}
	startFile := requestFile(start)
	raw, err = command(adminToken, "onward-start", "-request-file", startFile, "-idempotency-key", "cli-onward-original")
	if err != nil {
		t.Fatal(err)
	}
	var started workflow.Result
	if json.Unmarshal(raw, &started) != nil || started.Replayed {
		t.Fatal("CLI onward start")
	}
	raw, err = command(adminToken, "onward-receipt", "-request-file", requestFile(workflow.OnwardLookup{Start: start, ReceiptKey: "cli-onward-original"}))
	if err != nil {
		t.Fatal(err)
	}
	var lookedUp workflow.Result
	if json.Unmarshal(raw, &lookedUp) != nil || !lookedUp.Replayed || string(lookedUp.Resource) != string(started.Resource) {
		t.Fatal("CLI onward lookup changed original receipt")
	}
	raw, err = command(adminToken, "onward-start", "-request-file", startFile, "-idempotency-key", "cli-onward-original")
	if err != nil {
		t.Fatal(err)
	}
	var replayedOnward workflow.Result
	if json.Unmarshal(raw, &replayedOnward) != nil || !replayedOnward.Replayed || string(replayedOnward.Resource) != string(started.Resource) {
		t.Fatal("CLI onward replay changed original run")
	}
	copyToken, copyScope, copyActor := participant([]string{"read", "write", "list"})
	copyEndpointCommand := store.ExchangeEndpointCommand{Operation: "create", ID: secure.NewID(), Definition: &store.ExchangeEndpointDefinition{Schema: 1, Profile: "custody-https-poll-v1", Recipient: copyActor, Senders: []store.ExchangeParticipant{actorA}}}
	raw, err = command(adminToken, "exchange-endpoint-command", "-request-file", requestFile(copyEndpointCommand), "-idempotency-key", "cli-copy-endpoint")
	var copyEndpoint store.ExchangeEndpointResult
	if err != nil || json.Unmarshal(raw, &copyEndpoint) != nil {
		t.Fatal("CLI copy endpoint", err)
	}
	copyOfferRequest := request
	copyOfferRequest.Endpoint = store.ExchangeEndpointReference{ID: copyEndpoint.Endpoint.ID, Revision: copyEndpoint.Endpoint.Revision, Hash: copyEndpoint.Endpoint.Hash}
	copyOfferRequest.ExpiresAt = time.Now().UTC().Add(time.Minute).Truncate(time.Microsecond)
	raw, err = command(a, "exchange-offer", "-request-file", requestFile(copyOfferRequest), "-idempotency-key", "cli-copy-offer")
	var copyOffer store.ArtifactExchangeResult
	if err != nil || json.Unmarshal(raw, &copyOffer) != nil {
		t.Fatal("CLI copy offer", err)
	}
	copyRequest := store.ExchangeCopyRequest{ExchangeCopyOrigin: store.ExchangeCopyOrigin{ExchangeID: copyOffer.Exchange.ID, RequestHash: copyOffer.Exchange.RequestHash, Artifact: copyOfferRequest.Artifact}, Path: "/cli-owned-copy.dat"}
	copyInput := requestFile(copyRequest)
	if _, err = command(b, "exchange-copy", "-request-file", copyInput, "-idempotency-key", "read-is-not-write"); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("CLI receiving granted write", err)
	}
	raw, err = command(copyToken, "exchange-copy", "-request-file", copyInput, "-idempotency-key", "cli-copy-original")
	var copied custody.ExchangeCopyResult
	if err != nil || json.Unmarshal(raw, &copied) != nil || copied.Replayed || copied.Artifact.ID == file.ID || copied.Artifact.SHA256 != file.SHA256 || copied.Source != copyRequest.ExchangeCopyOrigin {
		t.Fatal("CLI exact owned copy", err)
	}
	_, copyReader, err := service.OpenFileReader(ctx, copyScope, copied.Artifact.ID)
	if err != nil {
		t.Fatal(err)
	}
	copyBytes, err := io.ReadAll(io.NewSectionReader(copyReader, 0, copied.Artifact.Size))
	copyReader.Close()
	if err != nil || !bytes.Equal(copyBytes, data) {
		t.Fatal("CLI copy independently observed bytes differ", err)
	}
	if _, err = command(a, "exchange-close", "-request-file", requestFile(store.ExchangeClosureCommand{Schema: 1, ID: copyOffer.Exchange.ID, RequestHash: copyOffer.Exchange.RequestHash, Operation: "cancel"}), "-idempotency-key", "cli-copy-close"); err != nil {
		t.Fatal(err)
	}
	raw, err = command(copyToken, "exchange-copy", "-request-file", copyInput, "-idempotency-key", "cli-copy-original")
	var copiedReplay custody.ExchangeCopyResult
	if err != nil || json.Unmarshal(raw, &copiedReplay) != nil || !copiedReplay.Replayed || copiedReplay.Artifact != copied.Artifact || copiedReplay.EventID != copied.EventID {
		t.Fatal("CLI copy receipt recovery reopened source", err)
	}
	qualifyExchangeProcessRecovery(t, ctx, exchangeProcessFixture{DB: db, Administrator: scope, DSN: refs[1], Storage: storage, SenderToken: a, RecipientToken: b, OtherToken: other, AdminToken: adminToken, SenderActor: actorA.Actor, Recipient: actorB.Actor, Request: request, Payload: data})
	historyInput := requestFile(store.AuditHistoryRequest{Resource: file.ID, Kinds: []string{"FileAccepted"}, Limit: 1})
	raw, err = command(adminToken, "audit-history", "-request-file", historyInput)
	var auditPage store.AuditHistoryPage
	if err != nil || json.Unmarshal(raw, &auditPage) != nil || len(auditPage.Events) != 1 || auditPage.Events[0].ID != file.EventID || auditPage.Events[0].Resource != file.ID || auditPage.Payloads != "omitted" || auditPage.Next != "" {
		t.Fatal("CLI audit metadata changed original accepted revision", err)
	}
	if _, err = command(a, "audit-history", "-request-file", historyInput); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("ordinary sender gained audit authority", err)
	}
	namespaceCopyWriter, namespaceCopyScope, _ := participant([]string{"read", "write", "list"})
	namespaceCopyReader, _, _ := participant([]string{"read", "list"})
	qualifyNamespaceCopyCLI(t, ctx, service, scope, namespaceCopyScope, namespaceCopyWriter, namespaceCopyReader, command, requestFile)
	namespaceCopyManager, namespaceManagerScope, _ := participant([]string{"read", "write", "list", "manage_paths"})
	qualifyNamespaceCopyOverwriteCLI(t, ctx, service, scope, namespaceManagerScope, namespaceCopyManager, namespaceCopyWriter, command, requestFile)
	qualifyJSONIntakeCLI(t, ctx, service, scope, adminToken, b, command, requestFile)
	qualifyLocalCollectionCLI(t, ctx, service, scope, adminToken, b, command, requestFile)
}
