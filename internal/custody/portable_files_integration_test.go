//go:build integration

package custody_test

import (
	"bytes"
	"errors"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/portability"
	"github.com/ctlplne/freightctl/internal/store"
)

type duringBundleWrite struct {
	bytes.Buffer
	action func()
}

func (w *duringBundleWrite) Write(p []byte) (int, error) {
	if w.action != nil {
		action := w.action
		w.action = nil
		action()
	}
	return w.Buffer.Write(p)
}

func TestPortableFilesDraftRechecksLiveReadAuthority(t *testing.T) {
	f := setup(t)
	data := []byte("portable fixture data")
	mode := uint32(0644)
	revision, _, err := f.service.AcceptAt(f.ctx, f.a, "portable-original", int64(len(data)), secure.Digest(data), bytes.NewReader(data),
		custody.UploadTarget{Path: "/portable.txt", Mode: &mode})
	if err != nil {
		t.Fatal(err)
	}
	selected := []string{revision.ID}
	for _, foreign := range []store.Scope{f.b, f.c} {
		var denied bytes.Buffer
		if _, err = f.service.PreparePortableFiles(f.ctx, foreign, selected, &denied); !errors.Is(err, store.ErrNotFound) || denied.Len() != 0 {
			t.Fatal("foreign selection escaped its scope", err)
		}
	}
	hash := secure.Digest([]byte(secure.NewID()))
	id := secure.NewID()
	account := store.AccountCommand{Operation: "create", ID: id, CredentialHash: hash,
		Policy: &store.AccountPolicy{Label: "Bundle fixture reader", Root: "/", Permissions: []string{"read", "list"}}}
	if _, err = f.db.ChangeAccount(f.ctx, f.a, "portable-create-reader", account); err != nil {
		t.Fatal(err)
	}
	reader := f.a
	reader.TokenHash = hash
	stage := &duringBundleWrite{action: func() {
		if _, err := f.db.ChangeAccount(f.ctx, f.a, "portable-revoke-reader", store.AccountCommand{
			Operation: "revoke", ID: id, ExpectedRevision: 1,
		}); err != nil {
			t.Fatal(err)
		}
	}}
	if report, err := f.service.PreparePortableFiles(f.ctx, reader, selected, stage); !errors.Is(err, store.ErrUnauthorized) || report != nil {
		t.Fatal("revocation after staging began obtained an export receipt", err)
	}
	if verified, err := portability.VerifyFiles(bytes.NewReader(stage.Bytes())); err != nil || len(verified.Manifest.Files) != 1 {
		t.Fatal("test did not stage a complete, correctly hashed archive before the final authority check", err)
	}
	tx, err := f.db.Begin(f.ctx, f.a)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Tx.Rollback(f.ctx)
	var count int
	if err := tx.Tx.QueryRow(f.ctx, "SELECT count(*) FROM events WHERE kind='PortableFilesExportPrepared'").Scan(&count); err != nil || count != 0 {
		t.Fatal("revoked preparation committed an audit event", count, err)
	}
}

func TestPortableRestoreBindsSourceToOrdinaryCreateAndReplay(t *testing.T) {
	f := setup(t)
	source := accept(t, f, "portable-restore-source", []byte("portable restoration"))
	var archive bytes.Buffer
	report, err := f.service.PreparePortableFiles(f.ctx, f.a, []string{source.ID}, &archive)
	if err != nil {
		t.Fatal(err)
	}
	restore := func(key, path string) (*store.File, bool, error) {
		t.Helper()
		member, err := portability.VerifySelectedFile(bytes.NewReader(archive.Bytes()), int64(archive.Len()), report.ArchiveSHA256, source.ID)
		if err != nil {
			t.Fatal(err)
		}
		return f.service.RestorePortableFile(f.ctx, f.b, key, path, member)
	}
	created, replayed, err := restore("original-restore", "/recovered.txt")
	if err != nil || replayed || created.ID == source.ID || created.SHA256 != source.SHA256 || created.Size != source.Size {
		t.Fatal("restore bypassed ordinary distinct file acceptance", err)
	}
	replay, replayed, err := restore("original-restore", "/recovered.txt")
	if err != nil || !replayed || *created != *replay {
		t.Fatal("original restoration receipt changed", err)
	}
	if _, _, err := restore("original-restore", "/changed.txt"); !errors.Is(err, store.ErrConflict) {
		t.Fatal("original operation key accepted a changed target", err)
	}
	if _, _, err := restore("another-restore", "/recovered.txt"); !errors.Is(err, store.ErrRevision) {
		t.Fatal("fresh restore key could overwrite the destination", err)
	}
	tx, err := f.db.Begin(f.ctx, f.b)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Tx.Rollback(f.ctx)
	var count int
	if err := tx.Tx.QueryRow(f.ctx, `SELECT count(*) FROM events WHERE kind='PortableFileRecovered' AND resource_id=$1
		AND payload->'source'->>'source_tenant_id'=$2 AND payload->'source'->>'archive_sha256'=$3
		AND payload->'source'->'source_revision'->>'id'=$4`,
		created.ID, f.a.Tenant, report.ArchiveSHA256, source.ID).Scan(&count); err != nil || count != 1 {
		t.Fatal("restore acceptance lacked one exact immutable origin", count, err)
	}
}
