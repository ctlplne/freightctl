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
	if _, err = command(b, "exchange-download", "-exchange-id", offered.Exchange.ID, "-output", filepath.Join(outputDirectory, "must-not-exist")); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("CLI cancellation failed to stop retrieval", err)
	}
	if _, err = os.Lstat(filepath.Join(outputDirectory, "must-not-exist")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("closed view left a download file", err)
	}
}
