//go:build integration

package custody_test

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestTreeCopyVerifiesEveryImmutableFileAndConfinesMounts(t *testing.T) {
	f := setup(t)
	shared := uint32(0770)
	pathCommand(t, f, "tree-copy-mount", store.PathCommand{Operation: "mkdir", Path: "/mount", Mode: &shared})
	source := pathCommand(t, f, "tree-copy-source", store.PathCommand{Operation: "mkdir", Path: "/mount/source"})
	data := []byte("exact original tree bytes\n")
	file, _, err := f.service.AcceptAt(f.ctx, f.a, "tree-copy-file", int64(len(data)), secure.Digest(data), bytes.NewReader(data), custody.UploadTarget{Path: "/mount/source/data.dat"})
	if err != nil {
		t.Fatal(err)
	}
	identity := restrictedIdentity(t, f, []string{"read", "list", "write"}, "/mount")
	command := store.PathCommand{Operation: "copy_tree", Path: "/source", Target: "/target", ExpectedEntryID: source.Entry.ID, ExpectedRevision: &source.Entry.Revision}
	path := filepath.Join(f.root, custody.Name(f.a.Tenant, f.a.Partner, file.ID))
	if err = os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, bytes.Repeat([]byte("x"), len(data)), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(path, 0400); err != nil {
		t.Fatal(err)
	}
	if _, err = f.service.PathCommand(f.ctx, identity, "tree-copy-original", command); !errors.Is(err, custody.ErrIntegrity) {
		t.Fatal("tree copy published corrupt source custody", err)
	}
	if _, err = f.service.StatPath(f.ctx, f.a, "/mount/target"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("integrity refusal left a partial destination", err)
	}
	if err = os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(path, 0400); err != nil {
		t.Fatal(err)
	}
	result, err := f.service.PathCommand(f.ctx, identity, "tree-copy-original", command)
	if err != nil || result.Replayed || result.Changed != 2 || result.Entry.Path != "/target" || result.Entry.ID == source.Entry.ID {
		t.Fatal("exact original copy did not recover after custody repair", err)
	}
	for _, candidate := range []struct {
		scope store.Scope
		path  string
	}{{identity, "/target/data.dat"}, {f.a, "/mount/source/data.dat"}} {
		actual, reader, err := f.service.DownloadPath(f.ctx, candidate.scope, candidate.path)
		if err != nil {
			t.Fatal(err)
		}
		received, err := io.ReadAll(reader)
		reader.Close()
		if err != nil || actual.ID != file.ID || !bytes.Equal(received, data) {
			t.Fatal("source/copy independent bytes differ", err)
		}
	}
	if _, err = f.service.StatPath(f.ctx, f.a, "/target"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("mounted copy escaped its declared root", err)
	}
	tx, err := f.service.DB.Begin(f.ctx, identity)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Tx.Rollback(f.ctx)
	var receipts, created, published, intents int
	if err = tx.Tx.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM namespace_commands WHERE request_key='tree-copy-original'),(SELECT count(*) FROM events WHERE actor_id=$1 AND kind='PathCreated'),(SELECT count(*) FROM events WHERE actor_id=$1 AND kind='PathPublished'),(SELECT count(*) FROM delivery_intents)`, tx.Actor).Scan(&receipts, &created, &published, &intents); err != nil || receipts != 1 || created != 1 || published != 1 || intents != 0 {
		t.Fatal("failed integrity attempt left effects or copy was not atomic", receipts, created, published, intents, err)
	}
}
