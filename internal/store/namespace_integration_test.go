//go:build integration

package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestNamespaceMigrationAndAtomicDirectoryCommands(t *testing.T) {
	ctx, adminPath, runtimePath, passwordPath := migrationDatabase(t)
	if err := Migrate(ctx, adminPath, passwordPath); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := secure.WriteToken(tokenPath); err != nil {
		t.Fatal(err)
	}
	scope := Scope{Tenant: secure.NewID(), Partner: secure.NewID()}
	if err := Provision(ctx, adminPath, scope.Tenant, scope.Partner, tokenPath); err != nil {
		t.Fatal(err)
	}
	token, err := secure.ReadSecret(tokenPath, 64)
	if err != nil {
		t.Fatal(err)
	}
	scope.TokenHash = secure.Digest(token.Bytes)
	token.Close()
	db, err := Open(ctx, runtimePath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Pool.Close()
	apply := func(key string, command PathCommand) *PathResult {
		t.Helper()
		tx, err := db.Begin(ctx, scope)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Tx.Rollback(ctx)
		result, err := tx.ApplyPathCommand(ctx, key, command, 1000)
		if err != nil {
			t.Fatal(command.Operation, err)
		}
		if err = tx.Tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		return result
	}
	created := apply("make-inbox", PathCommand{Operation: "mkdir", Path: "/inbox"})
	if created.Entry.Revision != 1 || created.Entry.Kind != "dir" || created.Replayed {
		t.Fatal("directory result", created)
	}
	replayed := apply("make-inbox", PathCommand{Operation: "mkdir", Path: "/inbox"})
	if !replayed.Replayed || replayed.Entry.ID != created.Entry.ID {
		t.Fatal("directory command repeated effects")
	}
	child := apply("make-child", PathCommand{Operation: "mkdir", Path: "/inbox/nested"})
	moved := apply("move-tree", PathCommand{Operation: "rename", Path: "/inbox", Target: "/archive", ExpectedRevision: &created.Entry.Revision})
	if moved.Changed != 2 || moved.Entry.Path != "/archive" {
		t.Fatal("tree rename", moved)
	}
	tx, err := db.Begin(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Entry(ctx, "/inbox"); !errors.Is(err, ErrNotFound) {
		t.Fatal("old path remained live", err)
	}
	newChild, err := tx.Entry(ctx, "/archive/nested")
	if err != nil || newChild.ID != child.Entry.ID || newChild.Revision != 2 {
		t.Fatal("subtree identity changed", newChild, err)
	}
	_ = tx.Tx.Rollback(ctx)
	removed := apply("remove-child", PathCommand{Operation: "rmdir", Path: "/archive/nested", ExpectedRevision: &newChild.Revision})
	if !removed.Entry.Deleted {
		t.Fatal("removal not explicit")
	}
	_ = apply("remove-archive", PathCommand{Operation: "rmdir", Path: "/archive", ExpectedRevision: &moved.Entry.Revision})
	tx, err = db.Begin(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Tx.Rollback(ctx)
	var live, total int
	if err = tx.Tx.QueryRow(ctx, `SELECT count(*) FILTER(WHERE NOT deleted),count(*) FROM namespace_entries`).Scan(&live, &total); err != nil || live != 0 || total != 2 {
		t.Fatal("deletion lost retained history", live, total, err)
	}
	if _, err = tx.Tx.Exec(ctx, `UPDATE namespace_entries SET mode=0 WHERE entry_id=$1`, created.Entry.ID); err == nil {
		t.Fatal("unjournaled namespace change accepted")
	} else {
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != "23514" {
			t.Fatal(err)
		}
	}
}

func TestNamespacePublicationBindsRevisionAndActorReceipts(t *testing.T) {
	ctx, adminPath, runtimePath, passwordPath := migrationDatabase(t)
	if err := Migrate(ctx, adminPath, passwordPath); err != nil {
		t.Fatal(err)
	}
	tenant, partner := secure.NewID(), secure.NewID()
	scopes := make([]Scope, 0, 2)
	for i := 0; i < 2; i++ {
		path := filepath.Join(t.TempDir(), "token")
		if err := secure.WriteToken(path); err != nil {
			t.Fatal(err)
		}
		if err := Provision(ctx, adminPath, tenant, partner, path); err != nil {
			t.Fatal(err)
		}
		secret, err := secure.ReadSecret(path, 64)
		if err != nil {
			t.Fatal(err)
		}
		scopes = append(scopes, Scope{Tenant: tenant, Partner: partner, TokenHash: secure.Digest(secret.Bytes)})
		secret.Close()
	}
	db, err := Open(ctx, runtimePath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Pool.Close()
	// Metadata-only schema test. Custody tests separately establish real byte durability.
	for _, scope := range scopes {
		tx, err := db.Begin(ctx, scope)
		if err != nil {
			t.Fatal(err)
		}
		file := &File{ID: secure.NewID(), Size: 4, SHA256: secure.Digest([]byte("test")), Policy: "integrity-only-v1"}
		if err = tx.Accept(ctx, "same-key", Meaning(file.Size, file.SHA256), file); err != nil {
			t.Fatal(err)
		}
		result, err := tx.ApplyPathCommand(ctx, "publish-"+file.ID, PathCommand{Operation: "publish", Path: "/" + file.ID, FileID: file.ID}, 1000)
		if err != nil {
			t.Fatal(err)
		}
		var versions int
		if err = tx.Tx.QueryRow(ctx, `SELECT count(*) FROM namespace_revisions WHERE entry_id=$1`, result.Entry.ID).Scan(&versions); err != nil || versions != 1 {
			t.Fatal("publication history missing", versions, err)
		}
		if err = tx.Tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	for _, scope := range scopes {
		tx, err := db.Begin(ctx, scope)
		if err != nil {
			t.Fatal(err)
		}
		var n int
		if err = tx.Tx.QueryRow(ctx, `SELECT count(*) FROM idempotency`).Scan(&n); err != nil || n != 1 {
			t.Fatal("actor receipt isolation", n, err)
		}
		_ = tx.Tx.Rollback(context.Background())
	}
}
