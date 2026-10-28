//go:build integration

package audit

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type auditFixture struct {
	ctx          context.Context
	db           *store.Store
	admin        *pgxpool.Pool
	scope, other store.Scope
	key          string
}

func fixture(t *testing.T) *auditFixture {
	t.Helper()
	adminPath, runtimePath := os.Getenv("FREIGHTCTL_TEST_ADMIN_FILE"), os.Getenv("FREIGHTCTL_TEST_RUNTIME_FILE")
	if adminPath == "" || runtimePath == "" {
		t.Fatal("real PostgreSQL required; run scripts/integration.sh")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	open := func(path string) *pgxpool.Pool {
		secret, err := secure.ReadSecret(path, 4096)
		if err != nil {
			t.Fatal(err)
		}
		p, err := pgxpool.New(ctx, string(secret.Bytes))
		secret.Close()
		if err != nil {
			t.Fatal("cannot open fixture database reference")
		}
		return p
	}
	control := open(adminPath)
	t.Cleanup(control.Close)
	name := "freightctl_audit_" + strings.ReplaceAll(secure.NewID(), "-", "")
	if _, err := control.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := control.Exec(context.Background(), "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)"); err != nil {
			t.Error(err)
		}
	})
	paths := make([]string, 0, 2)
	for _, source := range []string{adminPath, runtimePath} {
		secret, err := secure.ReadSecret(source, 4096)
		if err != nil {
			t.Fatal(err)
		}
		u, err := url.Parse(string(secret.Bytes))
		secret.Close()
		if err != nil {
			t.Fatal("invalid fixture reference")
		}
		u.Path = "/" + name
		path := filepath.Join(t.TempDir(), "database.dsn")
		if err = os.WriteFile(path, []byte(u.String()), 0600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	if err := store.Migrate(ctx, paths[0], filepath.Join(filepath.Dir(adminPath), "pg-runtime-password")); err != nil {
		t.Fatal(err)
	}
	admin := open(paths[0])
	t.Cleanup(admin.Close)
	db, err := store.Open(ctx, paths[1])
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Pool.Close)
	enroll := func() store.Scope {
		path := filepath.Join(t.TempDir(), "token")
		if err := secure.WriteToken(path); err != nil {
			t.Fatal(err)
		}
		tenant, partner := secure.NewID(), secure.NewID()
		if err := store.Provision(ctx, paths[0], tenant, partner, path); err != nil {
			t.Fatal(err)
		}
		secret, err := secure.ReadSecret(path, 64)
		if err != nil {
			t.Fatal(err)
		}
		defer secret.Close()
		return store.Scope{Tenant: tenant, Partner: partner, TokenHash: secure.Digest(secret.Bytes)}
	}
	key, public := filepath.Join(t.TempDir(), "signing.key"), filepath.Join(t.TempDir(), "signing.pub")
	if err = secure.GenerateAuditIdentity(key, public); err != nil {
		t.Fatal(err)
	}
	return &auditFixture{ctx: ctx, db: db, admin: admin, scope: enroll(), other: enroll(), key: key}
}

func TestScopedSnapshotAndPreparationEvidence(t *testing.T) {
	f := fixture(t)
	envelope, err := (&Service{DB: f.db, KeyFile: f.key}).Export(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	var snapshot store.AuditSnapshot
	if err = json.Unmarshal(envelope.Payload, &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.Tenant != f.scope.Tenant || snapshot.Partner != f.scope.Partner || snapshot.EventCount != 1 || len(snapshot.Events) != 1 || snapshot.Events[0].ActorID == "" {
		t.Fatal("wrong snapshot scope, actor or event count", snapshot)
	}
	events, err := f.db.Events(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	prepared := 0
	for _, event := range events {
		if event.Kind == "AuditSnapshotPrepared" {
			prepared++
			var p struct {
				PayloadHash string `json:"payload_sha256"`
				Count       int    `json:"event_count"`
			}
			if err = json.Unmarshal(event.Payload, &p); err != nil || p.PayloadHash != secure.Digest(envelope.Payload) || p.Count != 1 || event.ResourceID != snapshot.ID {
				t.Fatal("preparation does not bind exact artifact", err)
			}
		}
	}
	if prepared != 1 {
		t.Fatal("missing preparation evidence")
	}
	foreign, err := f.db.Events(f.ctx, f.other)
	if err != nil || len(foreign) != 1 {
		t.Fatal("export crossed tenant boundary", err)
	}
}

func TestExportBoundsAndConfigurationFailClosed(t *testing.T) {
	f := fixture(t)
	if _, err := (&Service{DB: f.db}).Export(f.ctx, f.scope); !errors.Is(err, ErrUnconfigured) {
		t.Fatal("missing signing key accepted", err)
	}
	if _, err := (&Service{DB: f.db, KeyFile: f.key, MaxBytes: 1024}).Export(f.ctx, f.scope); !errors.Is(err, store.ErrLimit) {
		t.Fatal("byte limit ignored", err)
	}
	tx, err := f.db.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Append(f.ctx, "EvidenceObserved", secure.NewID(), map[string]string{"fact": "synthetic"}); err != nil {
		t.Fatal(err)
	}
	if err = tx.Tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = (&Service{DB: f.db, KeyFile: f.key, MaxEvents: 1}).Export(f.ctx, f.scope); !errors.Is(err, store.ErrLimit) {
		t.Fatal("event limit ignored", err)
	}
	wrong := f.scope
	wrong.TokenHash = secure.Digest([]byte("wrong"))
	if _, err = (&Service{DB: f.db, KeyFile: "missing-key-reference"}).Export(f.ctx, wrong); !errors.Is(err, store.ErrUnauthorized) {
		t.Fatal("signing key accessed before authorization", err)
	}
	events, err := f.db.Events(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if event.Kind == "AuditSnapshotPrepared" {
			t.Fatal("failed export recorded as prepared")
		}
	}
}

func TestExportRechecksLiveAuthorityAfterSnapshot(t *testing.T) {
	f := fixture(t)
	service := &Service{DB: f.db, KeyFile: f.key}
	service.sign = func(path string, payload []byte) (*secure.SignedAudit, error) {
		// Real signer plus a deterministic revocation between snapshot and disclosure.
		envelope, err := secure.SignAuditPayload(path, payload)
		if err != nil {
			return nil, err
		}
		_, err = f.admin.Exec(f.ctx, `UPDATE credentials SET revoked_at=clock_timestamp() WHERE tenant_id=$1 AND partner_id=$2`, f.scope.Tenant, f.scope.Partner)
		return envelope, err
	}
	if envelope, err := service.Export(f.ctx, f.scope); envelope != nil || !errors.Is(err, store.ErrUnauthorized) {
		t.Fatal("revoked snapshot disclosed", err)
	}
}

func TestExportRequiresPreparationJournalPersistence(t *testing.T) {
	f := fixture(t)
	service := &Service{DB: f.db, KeyFile: f.key}
	service.sign = func(path string, payload []byte) (*secure.SignedAudit, error) {
		envelope, err := secure.SignAuditPayload(path, payload)
		if err != nil {
			return nil, err
		}
		_, err = f.admin.Exec(f.ctx, `REVOKE INSERT ON events FROM freightctl_runtime`)
		return envelope, err
	}
	if envelope, err := service.Export(f.ctx, f.scope); envelope != nil || err == nil {
		t.Fatal("unrecorded export disclosed", err)
	}
}
