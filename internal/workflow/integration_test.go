//go:build integration

package workflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/delivery"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type fixture struct {
	ctx         context.Context
	admin       *pgxpool.Pool
	adminPath   string
	runtimePath string
	tokenPath   string
	storagePath string
	s           *Service
	scope       store.Scope
	file        *store.File
	connection  ConnectionView
	request     ConnectionRequest
}

func setup(t *testing.T) *fixture {
	t.Helper()
	adminRef, runtimeRef := os.Getenv("FREIGHTCTL_TEST_ADMIN_FILE"), os.Getenv("FREIGHTCTL_TEST_RUNTIME_FILE")
	if adminRef == "" || runtimeRef == "" {
		t.Fatal("real PostgreSQL references required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	open := func(ref string) *pgxpool.Pool {
		t.Helper()
		secret, err := secure.ReadSecret(ref, 4096)
		if err != nil {
			t.Fatal(err)
		}
		defer secret.Close()
		pool, err := pgxpool.New(ctx, string(secret.Bytes))
		if err != nil {
			t.Fatal(err)
		}
		return pool
	}
	admin := open(adminRef)
	t.Cleanup(admin.Close)
	name := "freightctl_workflow_" + strings.ReplaceAll(secure.NewID(), "-", "")
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(context.Background(), "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)"); err != nil {
			t.Error(err)
		}
	})
	paths := []string{}
	for _, ref := range []string{adminRef, runtimeRef} {
		secret, err := secure.ReadSecret(ref, 4096)
		if err != nil {
			t.Fatal(err)
		}
		u, err := url.Parse(string(secret.Bytes))
		secret.Close()
		if err != nil {
			t.Fatal(err)
		}
		u.Path = "/" + name
		dest := filepath.Join(t.TempDir(), "database.dsn")
		if err = os.WriteFile(dest, []byte(u.String()), 0600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, dest)
	}
	if err := store.Migrate(ctx, paths[0], filepath.Join(filepath.Dir(adminRef), "pg-runtime-password")); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(ctx, paths[1])
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Pool.Close)
	storagePath := filepath.Join(t.TempDir(), "custody")
	disk, err := custody.Open(storagePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { disk.Close() })
	a := open(paths[0])
	t.Cleanup(a.Close)
	f := &fixture{ctx: ctx, admin: a, adminPath: paths[0], s: &Service{Custody: &custody.Service{DB: db, Disk: disk, MaxFile: 8 << 20, MaxStored: 64 << 20}}, scope: store.Scope{Tenant: secure.NewID(), Partner: secure.NewID()}}
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err = secure.WriteToken(tokenPath); err != nil {
		t.Fatal(err)
	}
	if err = store.Provision(ctx, paths[0], f.scope.Tenant, f.scope.Partner, tokenPath); err != nil {
		t.Fatal(err)
	}
	secret, err := secure.ReadSecret(tokenPath, 64)
	if err != nil {
		t.Fatal(err)
	}
	f.scope.TokenHash = secure.Digest(secret.Bytes)
	secret.Close()
	f.runtimePath, f.tokenPath = paths[1], tokenPath
	f.storagePath = storagePath
	f.file, _, err = f.s.Custody.Accept(ctx, f.scope, "source", 3, secure.Digest([]byte("abc")), bytes.NewReader([]byte("abc")))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	host, hostPub := filepath.Join(dir, "host"), filepath.Join(dir, "host.pub")
	client, clientPub := filepath.Join(dir, "client"), filepath.Join(dir, "client.pub")
	if err = secure.GenerateSSHHostIdentity(host, hostPub); err != nil {
		t.Fatal(err)
	}
	if err = secure.GenerateSSHHostIdentity(client, clientPub); err != nil {
		t.Fatal(err)
	}
	f.request = ConnectionRequest{Address: "127.0.0.1:9", User: "receiver", Directory: "/inbox", HostPublicFile: hostPub, KeyFile: client, KeyPublicFile: clientPub}
	registered, err := f.s.RegisterConnection(ctx, f.scope, "register", f.request)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(registered.Resource, &f.connection); err != nil {
		t.Fatal(err)
	}
	return f
}
func (f *fixture) definition() Definition {
	return Definition{Schema: 1, Name: "settlement", Steps: []Step{{ID: "first", Kind: "sftp.deliver", Connection: Reference{ID: f.connection.ID, Version: f.connection.Version, Hash: f.connection.Hash}, Filename: "first.csv"}, {ID: "second", Kind: "sftp.deliver", Connection: Reference{ID: f.connection.ID, Version: f.connection.Version, Hash: f.connection.Hash}, Filename: "second.csv"}}}
}
func (f *fixture) approved(t *testing.T, d Definition) *store.Configuration {
	t.Helper()
	r, err := f.s.Draft(f.ctx, f.scope, secure.NewID(), DraftRequest{Definition: d})
	if err != nil {
		t.Fatal(err)
	}
	var c store.Configuration
	if err = json.Unmarshal(r.Resource, &c); err != nil {
		t.Fatal(err)
	}
	r, err = f.s.Decide(f.ctx, f.scope, c.ID, c.Version, secure.NewID(), "approve", Decision{Hash: c.Hash, Revision: c.Revision})
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(r.Resource, &c); err != nil {
		t.Fatal(err)
	}
	return &c
}
func TestWorkflowAtomicRunBindingsAndRevocation(t *testing.T) {
	f := setup(t)
	d := f.definition()
	var before, after int
	if err := f.admin.QueryRow(f.ctx, `SELECT count(*) FROM events`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	preview, err := f.s.Validate(f.ctx, f.scope, PreviewRequest{Definition: d, FileID: f.file.ID})
	if err != nil {
		t.Fatal(err)
	}
	if preview.ExternalContact || !preview.ApprovalRequired || preview.Source.ID != f.file.ID || len(preview.Effects) != 2 {
		t.Fatal("preview effects", preview)
	}
	if err = f.admin.QueryRow(f.ctx, `SELECT count(*) FROM events`).Scan(&after); err != nil || before != after {
		t.Fatal("preview mutated domain events", before, after, err)
	}
	wf := f.approved(t, d)
	request := RunRequest{Workflow: Reference{ID: wf.ID, Version: wf.Version, Hash: wf.Hash}, FileID: f.file.ID}
	started, err := f.s.Run(f.ctx, f.scope, "run", request)
	if err != nil {
		t.Fatal(err)
	}
	var run store.WorkflowRun
	if err = json.Unmarshal(started.Resource, &run); err != nil {
		t.Fatal(err)
	}
	replayed, err := f.s.Run(f.ctx, f.scope, "run", request)
	var replayRun store.WorkflowRun
	if err == nil {
		err = json.Unmarshal(replayed.Resource, &replayRun)
	}
	if err != nil || !replayed.Replayed || !reflect.DeepEqual(replayRun, run) {
		t.Fatal("run retry changed intents", err)
	}
	status, err := f.s.Status(f.ctx, f.scope, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(status.Steps) != 2 {
		t.Fatal(status)
	}
	if status.ObservedState != "queued" || status.ObservedReason != "awaiting_worker" {
		t.Fatal("unattempted run claimed running", status.ObservedState, status.ObservedReason)
	}
	// Matching journal text still cannot turn unfinished intents into run success.
	tx, err := f.s.Custody.DB.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	forged := run
	forged.State = "succeeded"
	forged.Reason = "all_integrity_receipts_observed"
	forged.Revision++
	err = tx.SaveWorkflowRun(f.ctx, &forged, run.Revision)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
		t.Fatal("unfinished run accepted success", err)
	}
	_ = tx.Tx.Rollback(f.ctx)
	sender := &delivery.Service{Custody: f.s.Custody}
	if _, _, err = sender.Claim(f.ctx, f.scope, status.Steps[1].DeliveryID, secure.NewID()); !errors.Is(err, store.ErrState) {
		t.Fatal("dependency bypass accepted", err)
	}
	// New connection/workflow versions cannot mutate an already approved run.
	next := f.request
	next.ID = f.connection.ID
	next.ExpectedVersion = 1
	next.Directory = "/new-inbox"
	if _, err = f.s.RegisterConnection(f.ctx, f.scope, "connection-v2", next); err != nil {
		t.Fatal(err)
	}
	d.Name = "new draft"
	d.Steps[0].Filename = "changed.csv"
	if _, err = f.s.Draft(f.ctx, f.scope, "workflow-v2", DraftRequest{ID: wf.ID, ExpectedVersion: 1, Definition: d}); err != nil {
		t.Fatal(err)
	}
	intent, err := sender.Status(f.ctx, f.scope, status.Steps[0].DeliveryID)
	if err != nil {
		t.Fatal(err)
	}
	var frozen delivery.Definition
	if err = json.Unmarshal(intent.Definition, &frozen); err != nil {
		t.Fatal(err)
	}
	if frozen.Directory != "/inbox" || frozen.Filename != "first.csv" || frozen.Binding.ConnectionVersion != 1 || frozen.Binding.WorkflowVersion != 1 {
		t.Fatal("run silently followed latest configuration", frozen)
	}
	if _, err = f.s.Decide(f.ctx, f.scope, wf.ID, wf.Version, "revoke", "revoke", Decision{Hash: wf.Hash, Revision: wf.Revision}); err != nil {
		t.Fatal(err)
	}
	if _, _, err = sender.Claim(f.ctx, f.scope, status.Steps[0].DeliveryID, secure.NewID()); !errors.Is(err, store.ErrState) {
		t.Fatal("revoked workflow still claimable", err)
	}
	if _, err = f.s.Work(f.ctx, f.scope, run.ID, "work"); !errors.Is(err, store.ErrState) {
		t.Fatal("revoked workflow executed", err)
	}
	observed, err := f.s.Status(f.ctx, f.scope, run.ID)
	if err != nil || observed.ObservedReason != "workflow_not_approved" {
		t.Fatal("revocation not visible", observed, err)
	}
}

func TestWorkflowActorPrivacyAndImmutableDefinitions(t *testing.T) {
	f := setup(t)
	wf := f.approved(t, f.definition())
	tx, err := f.s.Custody.DB.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	changed := *wf
	changed.Definition = json.RawMessage(`{"schema_version":1,"name":"tampered","steps":[]}`)
	changed.Hash = secure.Digest(changed.Definition)
	changed.Revision++
	err = tx.SaveConfiguration(f.ctx, false, &changed, wf.Revision)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
		t.Fatal("immutable approved definition changed", err)
	}
	tx.Tx.Rollback(f.ctx)
	path := filepath.Join(t.TempDir(), "other.token")
	if err = secure.WriteToken(path); err != nil {
		t.Fatal(err)
	}
	if err = store.Provision(f.ctx, f.adminPath, f.scope.Tenant, f.scope.Partner, path); err != nil {
		t.Fatal(err)
	}
	secret, err := secure.ReadSecret(path, 64)
	if err != nil {
		t.Fatal(err)
	}
	other := f.scope
	other.TokenHash = secure.Digest(secret.Bytes)
	secret.Close()
	if _, err = f.s.Configuration(f.ctx, other, wf.ID, wf.Version); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("other actor saw workflow", err)
	}
	if _, err = f.s.Connection(f.ctx, other, f.connection.ID, f.connection.Version); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("other actor saw connection", err)
	}
	tx, err = f.s.Custody.DB.Begin(f.ctx, other)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Tx.Rollback(f.ctx)
	for _, table := range []string{"connection_revisions", "workflow_revisions", "workflow_runs", "workflow_steps", "workflow_receipts"} {
		var count int
		if err = tx.Tx.QueryRow(f.ctx, `SELECT count(*) FROM `+table).Scan(&count); err != nil || count != 0 {
			t.Fatal("private workflow relation leaked", table, count, err)
		}
	}
}
func TestWorkflowRunRollsBackAllIntentsWhenBindingFails(t *testing.T) {
	f := setup(t)
	wf := f.approved(t, f.definition())
	if _, err := f.admin.Exec(f.ctx, `CREATE FUNCTION freightctl_test_fail_step() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.ordinal=2 THEN RAISE EXCEPTION 'task-owned step binding failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER freightctl_test_fail_step BEFORE INSERT ON workflow_steps FOR EACH ROW EXECUTE FUNCTION freightctl_test_fail_step()`); err != nil {
		t.Fatal(err)
	}
	counts := func() []int {
		t.Helper()
		v := []int{}
		for _, table := range []string{"events", "delivery_intents", "workflow_runs", "workflow_steps", "workflow_receipts"} {
			var n int
			if err := f.admin.QueryRow(f.ctx, `SELECT count(*) FROM `+table).Scan(&n); err != nil {
				t.Fatal(err)
			}
			v = append(v, n)
		}
		return v
	}
	before := counts()
	if _, err := f.s.Run(f.ctx, f.scope, "failed-run", RunRequest{Workflow: Reference{ID: wf.ID, Version: wf.Version, Hash: wf.Hash}, FileID: f.file.ID}); err == nil {
		t.Fatal("injected binding failure ignored")
	}
	after := counts()
	for i, n := range before {
		if after[i] != n {
			t.Fatal("partial run was committed", before, after)
		}
	}
}
