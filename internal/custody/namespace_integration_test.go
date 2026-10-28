//go:build integration

package custody_test

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
)

func restrictedIdentity(t *testing.T, f *fixture, permissions []string, root string) store.Scope {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	if err := secure.WriteToken(path); err != nil {
		t.Fatal(err)
	}
	if err := store.ProvisionPolicy(f.ctx, os.Getenv("FREIGHTCTL_TEST_ADMIN_FILE"), f.a.Tenant, f.a.Partner, path, permissions, root); err != nil {
		t.Fatal(err)
	}
	secret, err := secure.ReadSecret(path, 64)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Close()
	return store.Scope{Tenant: f.a.Tenant, Partner: f.a.Partner, TokenHash: secure.Digest(secret.Bytes)}
}

func TestEquivalentUnicodeAndTimestampUploadRetries(t *testing.T) {
	f := setup(t)
	data := []byte("canonical retry")
	firstTime := time.Date(2026, 10, 28, 12, 0, 0, 123456789, time.FixedZone("local", -4*3600))
	otherTime := firstTime.UTC().Truncate(time.Microsecond)
	first, replayed, err := f.service.AcceptAt(f.ctx, f.a, "unicode-retry", int64(len(data)), secure.Digest(data), bytes.NewReader(data), custody.UploadTarget{Path: "/cafe\u0301.csv", Modified: &firstTime})
	if err != nil || replayed {
		t.Fatal(replayed, err)
	}
	again, replayed, err := f.service.AcceptAt(f.ctx, f.a, "unicode-retry", int64(len(data)), secure.Digest(data), bytes.NewReader(data), custody.UploadTarget{Path: "/café.csv", Modified: &otherTime})
	if err != nil || !replayed || first.ID != again.ID {
		t.Fatal("equivalent retry did not return its original result", err)
	}
}
func pathCommand(t *testing.T, f *fixture, key string, c store.PathCommand) *store.PathResult {
	t.Helper()
	result, err := f.service.PathCommand(f.ctx, f.a, key, c)
	if err != nil {
		t.Fatal(c.Operation, err)
	}
	return result
}
func TestVirtualRootPermissionAndDirectIDIsolation(t *testing.T) {
	f := setup(t)
	shared := uint32(0770)
	pathCommand(t, f, "make-inbox", store.PathCommand{Operation: "mkdir", Path: "/inbox", Mode: &shared})
	pathCommand(t, f, "make-private", store.PathCommand{Operation: "mkdir", Path: "/private"})
	data := []byte("shared immutable bytes")
	file, replayed, err := f.service.AcceptAt(f.ctx, f.a, "upload-shared", int64(len(data)), secure.Digest(data), bytes.NewReader(data), custody.UploadTarget{Path: "/inbox/file.csv"})
	if err != nil || replayed {
		t.Fatal(err)
	}
	other, _, err := f.service.AcceptAt(f.ctx, f.a, "upload-private", int64(len(data)), secure.Digest(data), bytes.NewReader(data), custody.UploadTarget{Path: "/private/file.csv"})
	if err != nil {
		t.Fatal(err)
	}
	reader := restrictedIdentity(t, f, []string{"read", "list"}, "/inbox")
	page, err := f.service.ListPath(f.ctx, reader, "/", "", 10)
	if err != nil || len(page.Entries) != 1 || page.Entries[0].Path != "/file.csv" {
		t.Fatal("mount leaked parent namespace", page, err)
	}
	for _, scope := range []store.Scope{reader, f.a} {
		_, stream, err := f.service.Download(f.ctx, scope, file.ID)
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(stream)
		stream.Close()
		if err != nil || !bytes.Equal(got, data) {
			t.Fatal("shared bytes", err)
		}
	}
	if _, stream, err := f.service.Download(f.ctx, reader, other.ID); !errors.Is(err, store.ErrNotFound) {
		if stream != nil {
			stream.Close()
		}
		t.Fatal("direct file ID bypassed mount", err)
	}
	if _, err = f.service.PathCommand(f.ctx, reader, "no-write", store.PathCommand{Operation: "mkdir", Path: "/new"}); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("read-only mutation accepted", err)
	}
	if _, _, err = f.service.Accept(f.ctx, reader, "raw-upload", int64(len(data)), secure.Digest(data), bytes.NewReader(data)); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("read-only raw upload accepted", err)
	}
	writer := restrictedIdentity(t, f, []string{"read", "write", "list", "manage_paths", "inspect", "audit_read"}, "/inbox")
	created, _, err := f.service.AcceptAt(f.ctx, writer, "mounted-upload", int64(len(data)), secure.Digest(data), bytes.NewReader(data), custody.UploadTarget{Path: "/own.csv"})
	if err != nil {
		t.Fatal(err)
	}
	if _, stream, err := f.service.DownloadPath(f.ctx, writer, "/own.csv"); err != nil {
		t.Fatal(err)
	} else {
		stream.Close()
	}
	if _, err = f.service.Reconcile(f.ctx, writer); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("mount escaped through global custody inspection", err)
	}
	if _, err = f.db.Events(f.ctx, writer); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("mount escaped through audit history", err)
	}
	stat, err := f.service.StatPath(f.ctx, writer, "/own.csv")
	if err != nil {
		t.Fatal(err)
	}
	zero := uint32(0)
	if _, err = f.service.PathCommand(f.ctx, writer, "close-mode", store.PathCommand{Operation: "setstat", Path: "/own.csv", ExpectedRevision: &stat.Revision, Mode: &zero}); err != nil {
		t.Fatal(err)
	}
	if _, stream, err := f.service.Download(f.ctx, writer, created.ID); !errors.Is(err, store.ErrNotFound) {
		if stream != nil {
			stream.Close()
		}
		t.Fatal("direct ID bypassed changed mode", err)
	}
}

func TestNamespacePublicationAndReplayAreAtomic(t *testing.T) {
	f := setup(t)
	pathCommand(t, f, "dir", store.PathCommand{Operation: "mkdir", Path: "/inbox"})
	first := []byte("revision one")
	file, _, err := f.service.AcceptAt(f.ctx, f.a, "upload", int64(len(first)), secure.Digest(first), bytes.NewReader(first), custody.UploadTarget{Path: "/inbox/data"})
	if err != nil {
		t.Fatal(err)
	}
	prior, replayed, err := f.service.AcceptAt(f.ctx, f.a, "upload", int64(len(first)), secure.Digest(first), bytes.NewReader(first), custody.UploadTarget{Path: "/inbox/data"})
	if err != nil || !replayed || prior.ID != file.ID {
		t.Fatal("replayed path upload", err)
	}
	if _, _, err = f.service.AcceptAt(f.ctx, f.a, "upload", int64(len(first)), secure.Digest(first), bytes.NewReader(first), custody.UploadTarget{Path: "/inbox/other"}); !errors.Is(err, store.ErrConflict) {
		t.Fatal("same key changed destination", err)
	}
	entry, err := f.service.StatPath(f.ctx, f.a, "/inbox/data")
	if err != nil {
		t.Fatal(err)
	}
	second := []byte("revision two")
	latest, _, err := f.service.AcceptAt(f.ctx, f.a, "replace", int64(len(second)), secure.Digest(second), bytes.NewReader(second), custody.UploadTarget{Path: "/inbox/data", ExpectedRevision: &entry.Revision})
	if err != nil || latest.ID == file.ID {
		t.Fatal("overwrite mutated revision identity", err)
	}
	if _, _, err = f.service.AcceptAt(f.ctx, f.a, "stale", int64(len(first)), secure.Digest(first), bytes.NewReader(first), custody.UploadTarget{Path: "/inbox/data", ExpectedRevision: &entry.Revision}); !errors.Is(err, store.ErrRevision) {
		t.Fatal("stale overwrite accepted", err)
	}
	current, err := f.service.StatPath(f.ctx, f.a, "/inbox/data")
	if err != nil || current.ID != entry.ID || current.Revision != 2 {
		t.Fatal("path revision", current, err)
	}
	for _, id := range []string{file.ID, latest.ID} {
		_, stream, err := f.service.Download(f.ctx, f.a, id)
		if err != nil {
			t.Fatal(err)
		}
		stream.Close()
	}
	pathCommand(t, f, "rename", store.PathCommand{Operation: "rename", Path: "/inbox", Target: "/archive", ExpectedRevision: func() *int64 { v := int64(1); return &v }()})
	if _, _, err = f.service.DownloadPath(f.ctx, f.b, "/archive/data"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("partner saw namespace", err)
	}
}
