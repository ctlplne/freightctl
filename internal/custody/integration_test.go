//go:build integration

package custody_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type fixture struct {
	ctx     context.Context
	admin   *pgxpool.Pool
	db      *store.Store
	service *custody.Service
	root    string
	a, b, c store.Scope
}

func setup(t *testing.T) *fixture {
	t.Helper()
	adminPath := os.Getenv("FREIGHTCTL_TEST_ADMIN_FILE")
	runtimePath := os.Getenv("FREIGHTCTL_TEST_RUNTIME_FILE")
	if adminPath == "" || runtimePath == "" {
		t.Fatal("real PostgreSQL required: set FREIGHTCTL_TEST_ADMIN_FILE and FREIGHTCTL_TEST_RUNTIME_FILE; see docs/development.md")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	secret, err := secure.ReadSecret(adminPath, 4096)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := pgxpool.New(ctx, string(secret.Bytes))
	secret.Close()
	if err != nil {
		t.Fatal("open test administrator reference")
	}
	t.Cleanup(admin.Close)
	db, err := store.Open(ctx, runtimePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Pool.Close)
	root := filepath.Join(t.TempDir(), "custody")
	disk, err := custody.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = disk.Close() })
	enroll := func(tenant, partner string) store.Scope {
		path := filepath.Join(t.TempDir(), "token")
		if err := secure.WriteToken(path); err != nil {
			t.Fatal(err)
		}
		if err := store.Provision(ctx, adminPath, tenant, partner, path); err != nil {
			t.Fatal(err)
		}
		token, err := secure.ReadSecret(path, 64)
		if err != nil {
			t.Fatal(err)
		}
		defer token.Close()
		return store.Scope{Tenant: tenant, Partner: partner, TokenHash: secure.Digest(token.Bytes)}
	}
	a := enroll(secure.NewID(), secure.NewID())
	b := enroll(a.Tenant, secure.NewID())
	c := enroll(secure.NewID(), a.Partner)
	return &fixture{ctx: ctx, admin: admin, db: db, root: root, a: a, b: b, c: c, service: &custody.Service{DB: db, Disk: disk, MaxFile: 1 << 20, MaxStored: 4 << 20}}
}

func accept(t *testing.T, f *fixture, key string, data []byte) *store.File {
	t.Helper()
	file, replayed, err := f.service.Accept(f.ctx, f.a, key, int64(len(data)), secure.Digest(data), bytes.NewReader(data))
	if err != nil || replayed {
		t.Fatal("first acceptance", replayed, err)
	}
	return file
}
func sqlState(t *testing.T, err error, want string) {
	t.Helper()
	var pg *pgconn.PgError
	if !errors.As(err, &pg) || pg.Code != want {
		t.Fatalf("expected SQLSTATE %s; got %v", want, err)
	}
}
func count(t *testing.T, f *fixture, table string) int {
	t.Helper()
	tx, err := f.db.Begin(f.ctx, f.a)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Tx.Rollback(f.ctx)
	var n int
	if err = tx.Tx.QueryRow(f.ctx, "SELECT count(*) FROM "+pgx.Identifier{table}.Sanitize()).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestRuntimeRoleAndScope(t *testing.T) {
	f := setup(t)
	if db, err := store.Open(f.ctx, os.Getenv("FREIGHTCTL_TEST_ADMIN_FILE")); err == nil {
		db.Pool.Close()
		t.Fatal("owner/superuser runtime accepted")
	}
	var n int
	err := f.admin.QueryRow(f.ctx, `SELECT count(*) FROM pg_class WHERE relnamespace='public'::regnamespace AND relname=ANY($1) AND relrowsecurity AND relforcerowsecurity AND relowner<>(SELECT oid FROM pg_roles WHERE rolname='freightctl_runtime')`, []string{"tenants", "partners", "credentials", "events", "files", "idempotency"}).Scan(&n)
	if err != nil || n != 6 {
		t.Fatal("forced non-owner policies", n, err)
	}
	file := accept(t, f, "scope-check", []byte("synthetic isolated bytes"))
	for _, other := range []store.Scope{f.b, f.c} {
		if _, data, err := f.service.Download(f.ctx, other, file.ID); !errors.Is(err, store.ErrNotFound) {
			if data != nil {
				data.Close()
			}
			t.Fatal("foreign file disclosed", err)
		}
		events, err := f.db.Events(f.ctx, other)
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range events {
			if event.ResourceID == file.ID {
				t.Fatal("foreign event disclosed")
			}
		}
	}
	for _, statement := range []string{`UPDATE events SET kind='forged'`, `DELETE FROM events`, `TRUNCATE events`, `UPDATE files SET sha256=repeat('0',64)`, `DELETE FROM idempotency`, `UPDATE credentials SET revoked_at=NULL`} {
		tx, err := f.db.Begin(f.ctx, f.a)
		if err != nil {
			t.Fatal(err)
		}
		_, err = tx.Tx.Exec(f.ctx, statement)
		sqlState(t, err, "42501")
		_ = tx.Tx.Rollback(f.ctx)
	}
	tx, err := f.db.Begin(f.ctx, f.a)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Tx.Exec(f.ctx, `INSERT INTO events(tenant_id,partner_id,event_id,actor_id,kind,resource_id,payload) VALUES($1,$2,$3,$4,'forged',$3,'{}')`, f.c.Tenant, f.c.Partner, secure.NewID(), tx.Actor)
	sqlState(t, err, "42501")
	_ = tx.Tx.Rollback(f.ctx)
	// Without a transaction-local scope the same runtime pool must see no domain rows.
	if err = f.db.Pool.QueryRow(f.ctx, `SELECT count(*) FROM files`).Scan(&n); err != nil || n != 0 {
		t.Fatal("pool leaked scope", n, err)
	}
	wrong := f.a
	wrong.TokenHash = secure.Digest([]byte("wrong"))
	if tx, err := f.db.Begin(f.ctx, wrong); !errors.Is(err, store.ErrUnauthorized) {
		if tx != nil {
			_ = tx.Tx.Rollback(f.ctx)
		}
		t.Fatal("wrong credential accepted", err)
	}
}

func TestConcurrentIdempotencyAndRestart(t *testing.T) {
	f := setup(t)
	data := bytes.Repeat([]byte("synthetic settlement,00001,10.01\n"), 128)
	const workers = 8
	ids := make(chan string, workers)
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			file, _, err := f.service.Accept(f.ctx, f.a, "concurrent", int64(len(data)), secure.Digest(data), bytes.NewReader(data))
			if err != nil {
				errs <- err
				return
			}
			ids <- file.ID
		}()
	}
	wg.Wait()
	close(ids)
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	var id string
	for candidate := range ids {
		if id != "" && candidate != id {
			t.Fatal("duplicate revisions")
		}
		id = candidate
	}
	if id == "" || count(t, f, "files") != 1 || count(t, f, "idempotency") != 1 || count(t, f, "events") != 2 {
		t.Fatal("acceptance did not commit exactly one event/index/key")
	}
	_, _, err := f.service.Accept(f.ctx, f.a, "concurrent", 1, secure.Digest([]byte("x")), bytes.NewReader([]byte("x")))
	if !errors.Is(err, store.ErrConflict) {
		t.Fatal("changed key meaning accepted", err)
	}
	// New SQL connections and storage descriptors must find the acknowledged immutable revision.
	db, err := store.Open(f.ctx, os.Getenv("FREIGHTCTL_TEST_RUNTIME_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Pool.Close()
	disk, err := custody.Open(f.root)
	if err != nil {
		t.Fatal(err)
	}
	defer disk.Close()
	restarted := &custody.Service{DB: db, Disk: disk, MaxFile: 1 << 20, MaxStored: 4 << 20}
	file, stream, err := restarted.Download(f.ctx, f.a, id)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(stream)
	stream.Close()
	if err != nil || file.SHA256 != secure.Digest(got) || !bytes.Equal(got, data) {
		t.Fatal("acknowledged bytes changed after restart", err)
	}
}

func TestFailedAcceptanceRollsBackAndCountsOrphans(t *testing.T) {
	f := setup(t)
	data := []byte("valid bytes")
	_, _, err := f.service.Accept(f.ctx, f.a, "bad-digest", int64(len(data)), secure.Digest([]byte("other")), bytes.NewReader(data))
	if !errors.Is(err, custody.ErrIntegrity) {
		t.Fatal("wrong digest accepted", err)
	}
	if count(t, f, "files") != 0 || count(t, f, "idempotency") != 0 || count(t, f, "events") != 1 {
		t.Fatal("failed validation changed SQL state")
	}
	entries, err := os.ReadDir(f.root)
	if err != nil || len(entries) != 0 {
		t.Fatal("partial bytes remained", err)
	}
	tx, err := f.db.Begin(f.ctx, f.a)
	if err != nil {
		t.Fatal(err)
	}
	file := &store.File{ID: secure.NewID(), Size: int64(len(data)), SHA256: secure.Digest(data), Policy: "integrity-only-v1"}
	if err = f.service.Disk.Stage(custody.Name(f.a.Tenant, f.a.Partner, file.ID), bytes.NewReader(data), file.Size, file.SHA256); err != nil {
		t.Fatal(err)
	}
	// Force a real SQL constraint failure after the event and file insert.
	err = tx.Accept(f.ctx, "", store.Meaning(file.Size, file.SHA256), file)
	sqlState(t, err, "23514")
	_ = tx.Tx.Rollback(f.ctx)
	if count(t, f, "files") != 0 || count(t, f, "idempotency") != 0 || count(t, f, "events") != 1 {
		t.Fatal("rollback left a partial journal/index/key")
	}
	if err = f.service.Disk.Capacity(1, int64(len(data))); !errors.Is(err, custody.ErrCapacity) {
		t.Fatal("orphan omitted from quota", err)
	}
	if _, stream, err := f.service.Download(f.ctx, f.a, file.ID); !errors.Is(err, store.ErrNotFound) {
		if stream != nil {
			stream.Close()
		}
		t.Fatal("orphan published", err)
	}
}

type revokingReader struct {
	body   *bytes.Reader
	once   sync.Once
	revoke func()
}

func (r *revokingReader) Read(p []byte) (int, error) { r.once.Do(r.revoke); return r.body.Read(p) }
func TestRevocationDuringStagingAndTamper(t *testing.T) {
	f := setup(t)
	file := accept(t, f, "before-revocation", []byte("original bytes"))
	path := filepath.Join(f.root, custody.Name(f.a.Tenant, f.a.Partner, file.ID))
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("modified bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, stream, err := f.service.Download(f.ctx, f.a, file.ID); !errors.Is(err, custody.ErrIntegrity) {
		if stream != nil {
			stream.Close()
		}
		t.Fatal("corrupt bytes published", err)
	}
	data := []byte("revoke while receiving")
	r := &revokingReader{body: bytes.NewReader(data), revoke: func() {
		// Administrative fixture mutation models authority changing during the stream.
		_, err := f.admin.Exec(f.ctx, `UPDATE credentials SET revoked_at=clock_timestamp() WHERE tenant_id=$1 AND partner_id=$2`, f.a.Tenant, f.a.Partner)
		if err != nil {
			t.Fatal(err)
		}
	}}
	_, _, err := f.service.Accept(f.ctx, f.a, "revoked-during-stream", int64(len(data)), secure.Digest(data), r)
	if !errors.Is(err, store.ErrUnauthorized) {
		t.Fatal("stale authority accepted bytes", err)
	}
	var files int
	if err = f.admin.QueryRow(f.ctx, `SELECT count(*) FROM files WHERE tenant_id=$1 AND partner_id=$2`, f.a.Tenant, f.a.Partner).Scan(&files); err != nil || files != 1 {
		t.Fatal("revoked acceptance committed", files, err)
	}
}

func TestProjectionRequiresExactJournalEvent(t *testing.T) {
	f := setup(t)
	file := accept(t, f, "journal-binding", []byte("bound bytes"))
	events, err := f.db.Events(f.ctx, f.a)
	if err != nil {
		t.Fatal(err)
	}
	var enrollment string
	for _, e := range events {
		if e.Kind == "ServiceIdentityEnrolled" {
			enrollment = e.ID
		}
	}
	for _, test := range []struct {
		name, query string
		args        []any
	}{
		{"wrong-event-kind", `INSERT INTO files VALUES($1,$2,$3,1,$4,'integrity-only-v1',$5)`, []any{f.a.Tenant, f.a.Partner, secure.NewID(), secure.Digest([]byte("x")), enrollment}},
		{"wrong-revision", `INSERT INTO files VALUES($1,$2,$3,$4,$5,$6,$7)`, []any{f.a.Tenant, f.a.Partner, secure.NewID(), file.Size, file.SHA256, file.Policy, file.EventID}},
		{"forged-key", `INSERT INTO idempotency VALUES($1,$2,'forged-key',$3,$4)`, []any{f.a.Tenant, f.a.Partner, store.Meaning(file.Size, file.SHA256), file.ID}},
	} {
		t.Run(test.name, func(t *testing.T) {
			tx, err := f.db.Begin(f.ctx, f.a)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Tx.Rollback(f.ctx)
			_, err = tx.Tx.Exec(f.ctx, test.query, test.args...)
			sqlState(t, err, "23514")
		})
	}
}

func TestStartupRejectsDisabledRLS(t *testing.T) {
	f := setup(t)
	if _, err := f.admin.Exec(f.ctx, `ALTER TABLE files DISABLE ROW LEVEL SECURITY`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := f.admin.Exec(context.Background(), `ALTER TABLE files ENABLE ROW LEVEL SECURITY`); err != nil {
			t.Error(err)
		}
	})
	if db, err := store.Open(f.ctx, os.Getenv("FREIGHTCTL_TEST_RUNTIME_FILE")); err == nil {
		db.Pool.Close()
		t.Fatal("runtime started with disabled file isolation")
	}
}

func TestReplayRechecksRevocationAfterLock(t *testing.T) {
	f := setup(t)
	data := []byte("previously accepted")
	accept(t, f, "waited-replay", data)
	blocker, err := f.admin.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(f.ctx)
	lock := f.a.Tenant + ":" + f.a.Partner + ":waited-replay"
	if _, err = blocker.Exec(f.ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, lock); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, _, err := f.service.Accept(f.ctx, f.a, "waited-replay", int64(len(data)), secure.Digest(data), bytes.NewReader(data))
		result <- err
	}()
	deadline := time.Now().Add(3 * time.Second)
	for {
		var waiting bool
		if err = f.admin.QueryRow(f.ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND NOT granted)`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("replay did not reach database lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err = f.admin.Exec(f.ctx, `UPDATE credentials SET revoked_at=clock_timestamp() WHERE tenant_id=$1 AND partner_id=$2`, f.a.Tenant, f.a.Partner); err != nil {
		t.Fatal(err)
	}
	if err = blocker.Rollback(f.ctx); err != nil {
		t.Fatal(err)
	}
	if err = <-result; !errors.Is(err, store.ErrUnauthorized) {
		t.Fatal("revoked identity received a waited replay result", err)
	}
}

func TestReconciliationIsScopedAndReadOnly(t *testing.T) {
	f := setup(t)
	good := accept(t, f, "reconcile-good", []byte("unchanged bytes"))
	bad := accept(t, f, "reconcile-bad", []byte("changed later"))
	missing := accept(t, f, "reconcile-missing", []byte("removed later"))
	path := func(id string) string { return filepath.Join(f.root, custody.Name(f.a.Tenant, f.a.Partner, id)) }
	if err := os.Chmod(path(bad.ID), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path(bad.ID), bytes.Repeat([]byte("x"), int(bad.Size)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path(missing.ID)); err != nil {
		t.Fatal(err)
	}
	orphan := secure.NewID()
	if err := f.service.Disk.Stage(custody.Name(f.a.Tenant, f.a.Partner, orphan), bytes.NewReader([]byte("orphan")), 6, secure.Digest([]byte("orphan"))); err != nil {
		t.Fatal(err)
	}
	foreign := secure.NewID()
	if err := f.service.Disk.Stage(custody.Name(f.b.Tenant, f.b.Partner, foreign), bytes.NewReader([]byte("foreign")), 7, secure.Digest([]byte("foreign"))); err != nil {
		t.Fatal(err)
	}
	link := secure.NewID()
	if err := os.Symlink(path(good.ID), path(link)); err != nil {
		t.Fatal(err)
	}
	unsafe := filepath.Join(f.root, f.a.Tenant+"_"+f.a.Partner+"_unexpected-name")
	if err := os.WriteFile(unsafe, []byte("unknown"), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadDir(f.root)
	if err != nil {
		t.Fatal(err)
	}
	eventsBefore := count(t, f, "events")
	report, err := f.service.Reconcile(f.ctx, f.a)
	if err != nil {
		t.Fatal(err)
	}
	if report.Consistent || report.Counts["verified"] != 1 || report.Counts["integrity_mismatch"] != 1 || report.Counts["missing_bytes"] != 1 || report.Counts["unreferenced_bytes"] != 1 || report.Counts["unsafe_entry"] != 2 {
		t.Fatalf("wrong reconciliation: %+v", report)
	}
	if report.HashedBytes != good.Size+bad.Size || report.VerifiedBytes != good.Size {
		t.Fatal("hash accounting includes unverified success", report)
	}
	for _, entry := range report.Entries {
		if entry.Reference == foreign || entry.Reference == filepath.Base(unsafe) {
			t.Fatal("foreign or unsafe name disclosed")
		}
	}
	after, err := os.ReadDir(f.root)
	if err != nil || len(before) != len(after) {
		t.Fatal("reconciliation changed directory", err)
	}
	for i := range before {
		if before[i].Name() != after[i].Name() {
			t.Fatal("entry renamed or deleted")
		}
	}
	if count(t, f, "events") != eventsBefore || count(t, f, "files") != 3 {
		t.Fatal("observation mutated SQL")
	}
	other, err := f.service.Reconcile(f.ctx, f.b)
	if err != nil || other.Counts["unreferenced_bytes"] != 1 || len(other.Entries) != 1 || other.Entries[0].Reference != foreign {
		t.Fatal("partner boundary", other, err)
	}
	wrong := f.a
	wrong.TokenHash = secure.Digest([]byte("wrong"))
	if _, err = f.service.Reconcile(f.ctx, wrong); !errors.Is(err, store.ErrUnauthorized) {
		t.Fatal("unauthorized reconciliation", err)
	}
}

func TestReconciliationBudgetsAndTruncation(t *testing.T) {
	f := setup(t)
	for i := 0; i < 2; i++ {
		file := accept(t, f, secure.NewID(), []byte("12345678"))
		path := filepath.Join(f.root, custody.Name(f.a.Tenant, f.a.Partner, file.ID))
		if err := os.Chmod(path, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("87654321"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	f.service.ReconcileMaxBytes = 8
	report, err := f.service.Reconcile(f.ctx, f.a)
	if err != nil || report.HashedBytes != 8 || report.VerifiedBytes != 0 || report.Counts["integrity_mismatch"] != 1 || report.Counts["not_checked_budget"] != 1 || report.Consistent {
		t.Fatal("failed hashes escaped the byte budget", report, err)
	}
	for i := 0; i < 201; i++ {
		if err := f.service.Disk.Stage(custody.Name(f.a.Tenant, f.a.Partner, secure.NewID()), bytes.NewReader(nil), 0, secure.Digest(nil)); err != nil {
			t.Fatal(err)
		}
	}
	report, err = f.service.Reconcile(f.ctx, f.a)
	if err != nil || !report.Truncated || len(report.Entries) != 200 || report.Counts["unreferenced_bytes"] != 201 {
		t.Fatal("report bound lost entries or claimed completeness", report, err)
	}
}

type waitingReader struct {
	body             *bytes.Reader
	entered, release chan struct{}
	once             sync.Once
}

func (r *waitingReader) Read(p []byte) (int, error) {
	r.once.Do(func() { close(r.entered); <-r.release })
	return r.body.Read(p)
}
func TestReconciliationWaitsForStagingAndHonorsCancellation(t *testing.T) {
	f := setup(t)
	r := &waitingReader{body: bytes.NewReader([]byte("active")), entered: make(chan struct{}), release: make(chan struct{})}
	result := make(chan error, 1)
	go func() {
		_, _, err := f.service.Accept(f.ctx, f.a, "active-staging", 6, secure.Digest([]byte("active")), r)
		result <- err
	}()
	<-r.entered
	ctx, cancel := context.WithTimeout(f.ctx, 100*time.Millisecond)
	_, err := f.service.Reconcile(ctx, f.a)
	cancel()
	close(r.release)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("reconciliation read live staging or ignored deadline", err)
	}
	if err = <-result; err != nil {
		t.Fatal(err)
	}
	report, err := f.service.Reconcile(f.ctx, f.a)
	if err != nil || !report.Consistent || report.Counts["verified"] != 1 {
		t.Fatal("completed staging was not reconciled", report, err)
	}
}

func TestExistingRuntimeRejectsIsolationChange(t *testing.T) {
	f := setup(t)
	if _, err := f.admin.Exec(f.ctx, `ALTER TABLE events DISABLE ROW LEVEL SECURITY`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := f.admin.Exec(context.Background(), `ALTER TABLE events ENABLE ROW LEVEL SECURITY`); err != nil {
			t.Error(err)
		}
	})
	if _, err := f.db.Events(f.ctx, f.a); !errors.Is(err, store.ErrIsolation) {
		t.Fatal("existing runtime accepted disabled event isolation", err)
	}
}

func TestPolicyChangeWaitsForScopedOperation(t *testing.T) {
	f := setup(t)
	operation, err := f.db.Begin(f.ctx, f.a)
	if err != nil {
		t.Fatal(err)
	}
	defer operation.Tx.Rollback(f.ctx)
	change, err := f.admin.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer change.Rollback(f.ctx)
	if _, err = change.Exec(f.ctx, `SET LOCAL lock_timeout='100ms'`); err != nil {
		t.Fatal(err)
	}
	_, err = change.Exec(f.ctx, `ALTER TABLE events DISABLE ROW LEVEL SECURITY`)
	sqlState(t, err, "55P03")
}

func TestJournalPayloadBoundsInServiceAndDatabase(t *testing.T) {
	f := setup(t)
	tx, err := f.db.Begin(f.ctx, f.a)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Append(f.ctx, "EvidenceObserved", secure.NewID(), map[string]string{"synthetic": string(bytes.Repeat([]byte("x"), 33<<10))}); !errors.Is(err, store.ErrLimit) {
		t.Fatal("application journal bound ignored", err)
	}
	_ = tx.Tx.Rollback(f.ctx)
	for _, kind := range []string{"payload", "kind"} {
		tx, err = f.db.Begin(f.ctx, f.a)
		if err != nil {
			t.Fatal(err)
		}
		query := `INSERT INTO events(tenant_id,partner_id,event_id,actor_id,kind,resource_id,payload) VALUES($1,$2,$3,$4,'EvidenceObserved',$3,to_jsonb(repeat('x',70000)))`
		if kind == "kind" {
			query = `INSERT INTO events(tenant_id,partner_id,event_id,actor_id,kind,resource_id,payload) VALUES($1,$2,$3,$4,repeat('x',129),$3,'{}')`
		}
		_, err = tx.Tx.Exec(f.ctx, query, f.a.Tenant, f.a.Partner, secure.NewID(), tx.Actor)
		sqlState(t, err, "23514")
		_ = tx.Tx.Rollback(f.ctx)
	}
	if count(t, f, "events") != 1 {
		t.Fatal("oversized event persisted")
	}
}
