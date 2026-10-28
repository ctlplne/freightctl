//go:build integration

package store

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/jackc/pgx/v5"
)

func migrationDatabase(t *testing.T) (context.Context, string, string, string) {
	t.Helper()
	adminPath, runtimePath := os.Getenv("FREIGHTCTL_TEST_ADMIN_FILE"), os.Getenv("FREIGHTCTL_TEST_RUNTIME_FILE")
	if adminPath == "" || runtimePath == "" {
		t.Fatal("real PostgreSQL references required; run scripts/integration.sh")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	admin, err := connect(ctx, adminPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	name := "freightctl_migration_" + strings.ReplaceAll(secure.NewID(), "-", "")
	if _, err = admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(context.Background(), "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)"); err != nil {
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
			t.Fatal("invalid fixture connection reference")
		}
		u.Path = "/" + name
		path := filepath.Join(t.TempDir(), "database.dsn")
		if err = os.WriteFile(path, []byte(u.String()), 0600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	return ctx, paths[0], paths[1], filepath.Join(filepath.Dir(adminPath), "pg-runtime-password")
}

func TestCleanDatabaseMigrationsAndUnknownVersion(t *testing.T) {
	ctx, adminPath, runtimePath, passwordPath := migrationDatabase(t)
	for i := 0; i < 2; i++ {
		if err := Migrate(ctx, adminPath, passwordPath); err != nil {
			t.Fatal(err)
		}
	}
	db, err := Open(ctx, runtimePath)
	if err != nil {
		t.Fatal(err)
	}
	db.Pool.Close()
	admin, err := connect(ctx, adminPath)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if _, err = admin.Exec(ctx, `INSERT INTO freightctl_schema VALUES(3,'unsupported')`); err != nil {
		t.Fatal(err)
	}
	if err = Migrate(ctx, adminPath, passwordPath); err == nil {
		t.Fatal("older migrator accepted future version")
	}
	if db, err = Open(ctx, runtimePath); err == nil {
		db.Pool.Close()
		t.Fatal("older runtime accepted future version")
	}
}

func TestVersionOneUpgradePreservesReplayAndChecksums(t *testing.T) {
	ctx, adminPath, runtimePath, passwordPath := migrationDatabase(t)
	admin, err := connect(ctx, adminPath)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if _, err = admin.Exec(ctx, `CREATE TABLE freightctl_schema(version integer PRIMARY KEY,digest text NOT NULL); GRANT SELECT ON freightctl_schema TO freightctl_runtime`); err != nil {
		t.Fatal(err)
	}
	if _, err = admin.Exec(ctx, schema); err != nil {
		t.Fatal(err)
	}
	if _, err = admin.Exec(ctx, `INSERT INTO freightctl_schema VALUES(1,$1)`, secure.Digest([]byte(schema))); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err = secure.WriteToken(tokenPath); err != nil {
		t.Fatal(err)
	}
	tenant, partner := secure.NewID(), secure.NewID()
	if err = Provision(ctx, adminPath, tenant, partner, tokenPath); err != nil {
		t.Fatal(err)
	}
	token, err := secure.ReadSecret(tokenPath, 64)
	if err != nil {
		t.Fatal(err)
	}
	scope := Scope{Tenant: tenant, Partner: partner, TokenHash: secure.Digest(token.Bytes)}
	token.Close()
	pool, err := connect(ctx, runtimePath)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	tx, err := (&Store{Pool: pool}).Begin(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Tx.Rollback(ctx)
	file := File{ID: secure.NewID(), Size: 3, SHA256: secure.Digest([]byte("old")), Policy: "integrity-only-v1"}
	file.EventID, err = tx.Append(ctx, "FileAccepted", file.ID, map[string]any{"size_bytes": file.Size, "sha256": file.SHA256, "policy": file.Policy})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Tx.Exec(ctx, `INSERT INTO files VALUES($1,$2,$3,$4,$5,$6,$7)`, tenant, partner, file.ID, file.Size, file.SHA256, file.Policy, file.EventID); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Tx.Exec(ctx, `INSERT INTO idempotency VALUES($1,$2,'legacy-key',$3,$4)`, tenant, partner, Meaning(file.Size, file.SHA256), file.ID); err != nil {
		t.Fatal(err)
	}
	if err = tx.Tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var original json.RawMessage
	if err = admin.QueryRow(ctx, `SELECT payload FROM events WHERE tenant_id=$1 AND event_id=$2`, tenant, file.EventID).Scan(&original); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err = Migrate(ctx, adminPath, passwordPath); err != nil {
			t.Fatal(err)
		}
	}
	db, err := Open(ctx, runtimePath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Pool.Close()
	tx, err = db.Begin(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Tx.Rollback(ctx)
	got, err := tx.Replay(ctx, "legacy-key", Meaning(file.Size, file.SHA256))
	if err != nil || *got != file {
		t.Fatal("upgrade changed replay identity", err)
	}
	var checkpoints int
	if err = tx.Tx.QueryRow(ctx, `SELECT count(*) FROM events WHERE kind='FileIdempotencyCheckpointed'`).Scan(&checkpoints); err != nil || checkpoints != 1 {
		t.Fatal("checkpoint not appended exactly once", checkpoints, err)
	}
	_ = tx.Tx.Rollback(ctx)
	var after json.RawMessage
	if err = admin.QueryRow(ctx, `SELECT payload FROM events WHERE tenant_id=$1 AND event_id=$2`, tenant, file.EventID).Scan(&after); err != nil || string(after) != string(original) {
		t.Fatal("original event was rewritten", err)
	}
	if _, err = admin.Exec(ctx, `UPDATE freightctl_schema SET digest=repeat('0',64) WHERE version=1`); err != nil {
		t.Fatal(err)
	}
	if err = Migrate(ctx, adminPath, passwordPath); err == nil {
		t.Fatal("migrator accepted rewritten source digest")
	}
	if bad, err := Open(ctx, runtimePath); err == nil {
		bad.Pool.Close()
		t.Fatal("runtime accepted rewritten source digest")
	}
}
