//go:build integration

package store

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/jackc/pgx/v5/pgconn"
)

func uploadSchemaFixture(t *testing.T) (context.Context, *Store, Scope) {
	t.Helper()
	ctx, admin, runtime, password := migrationDatabase(t)
	if err := Migrate(ctx, admin, password); err != nil {
		t.Fatal(err)
	}
	token := filepath.Join(t.TempDir(), "token")
	if err := secure.WriteToken(token); err != nil {
		t.Fatal(err)
	}
	scope := Scope{Tenant: secure.NewID(), Partner: secure.NewID()}
	if err := Provision(ctx, admin, scope.Tenant, scope.Partner, token); err != nil {
		t.Fatal(err)
	}
	secret, err := secure.ReadSecret(token, 64)
	if err != nil {
		t.Fatal(err)
	}
	scope.TokenHash = secure.Digest(secret.Bytes)
	secret.Close()
	db, err := Open(ctx, runtime)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Pool.Close)
	return ctx, db, scope
}
func TestUploadProjectionRequiresContiguousImmutableCheckpoint(t *testing.T) {
	ctx, db, scope := uploadSchemaFixture(t)
	begin := func() *Transaction {
		t.Helper()
		tx, err := db.Begin(ctx, scope)
		if err != nil {
			t.Fatal(err)
		}
		return tx
	}
	tx := begin()
	target := json.RawMessage(`{"Path":"/destination"}`)
	u := &UploadSession{ID: secure.NewID(), StorageID: secure.NewID(), Actor: tx.Actor, Root: tx.Root, Authority: tx.AuthorityRevision, Target: target, ExpectedSize: 131072, ExpectedSHA: secure.Digest([]byte("metadata-only fixture")), State: "open", Revision: 1}
	if err := tx.SaveUpload(ctx, nil, u, "UploadSessionCreated", nil); err != nil {
		t.Fatal(err)
	}
	if err := tx.Tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	// This schema fixture claims metadata binding only; real custody tests sync bytes.
	tx = begin()
	next := *u
	next.Offset = 65536
	next.Chunks = 1
	next.Revision++
	chunk := &UploadChunk{Offset: 0, Size: 65536, ObjectID: secure.NewID(), SHA256: secure.Digest([]byte("metadata chunk"))}
	if err := tx.SaveUpload(ctx, u, &next, "UploadCheckpointed", chunk); err != nil {
		t.Fatal(err)
	}
	if err := tx.Tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	u = &next
	tx = begin()
	_, err := tx.Tx.Exec(ctx, `UPDATE upload_sessions SET committed_offset=committed_offset+1 WHERE upload_id=$1`, u.ID)
	var pg *pgconn.PgError
	if !errors.As(err, &pg) || pg.Code != "23514" {
		t.Fatal("unjournaled head accepted", err)
	}
	_ = tx.Tx.Rollback(ctx)
	tx = begin()
	jump := *u
	jump.Offset = 131072
	jump.Chunks++
	jump.Revision++
	err = tx.SaveUpload(ctx, u, &jump, "UploadCheckpointed", &UploadChunk{Offset: 98304, Size: 32768, ObjectID: secure.NewID(), SHA256: secure.Digest([]byte("gap"))})
	if !errors.As(err, &pg) || pg.Code != "23514" {
		t.Fatal("noncontiguous checkpoint accepted", err)
	}
	_ = tx.Tx.Rollback(ctx)
	tx = begin()
	jump = *u
	jump.Offset = 131072
	jump.Chunks++
	jump.Revision++
	payload := map[string]any{"namespace_root": u.Root, "storage_id": u.StorageID, "authority_revision": u.Authority, "target": u.Target, "expected_size": u.ExpectedSize, "expected_sha256": u.ExpectedSHA, "committed_offset": jump.Offset, "chunk_count": jump.Chunks, "state": "open", "file_id": "", "revision": jump.Revision, "chunk_offset": u.Offset, "chunk_size": 65536, "chunk_object_id": secure.NewID(), "chunk_sha256": secure.Digest([]byte("absent"))}
	event, err := tx.Append(ctx, "UploadCheckpointed", u.ID, payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Tx.Exec(ctx, `UPDATE upload_sessions SET committed_offset=$1,chunk_count=$2,revision=$3,changed_event_id=$4 WHERE upload_id=$5`, jump.Offset, jump.Chunks, jump.Revision, event, u.ID); err != nil {
		t.Fatal(err)
	}
	err = tx.Tx.Commit(ctx)
	if !errors.As(err, &pg) || pg.Code != "23514" {
		t.Fatal("checkpoint without its chunk committed", err)
	}
	tx = begin()
	current, err := tx.Upload(ctx, u.ID)
	if err != nil || current.Offset != 65536 {
		t.Fatal("failed transaction changed head", err)
	}
	_ = tx.Tx.Rollback(ctx)
}
