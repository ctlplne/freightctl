//go:build integration

package custody_test

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestDurableUploadCheckpointResumeAndPrivatePublication(t *testing.T) {
	f := setup(t)
	data := bytes.Repeat([]byte("a"), 128<<10)
	digest := secure.Digest(data)
	created, err := f.service.CreateUpload(f.ctx, f.a, "create", custody.CreateUpload{Path: "/resumed", Size: int64(len(data)), SHA256: digest})
	if err != nil {
		t.Fatal(err)
	}
	again, err := f.service.CreateUpload(f.ctx, f.a, "create", custody.CreateUpload{Path: "/resumed", Size: int64(len(data)), SHA256: digest})
	if err != nil || !again.Replayed || again.Upload.ID != created.Upload.ID {
		t.Fatal("creation retry", err)
	}
	id := created.Upload.ID
	half := data[:64<<10]
	first, err := f.service.AppendUpload(f.ctx, f.a, id, "first", 0, int64(len(half)), secure.Digest(half), bytes.NewReader(half))
	if err != nil || first.Upload.Offset != int64(len(half)) {
		t.Fatal("checkpoint", err)
	}
	for _, scope := range []store.Scope{f.b, f.c} {
		if _, err = f.service.UploadStatus(f.ctx, scope, id); !errors.Is(err, store.ErrNotFound) {
			t.Fatal("foreign checkpoint disclosed", err)
		}
	}
	if _, err = f.service.StatPath(f.ctx, f.a, "/resumed"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("partial published", err)
	}
	report, err := f.service.Reconcile(f.ctx, f.a)
	if err != nil || !report.Consistent || report.Counts["verified_checkpoint"] != 1 {
		t.Fatal("checkpoint treated as orphan", report, err)
	}
	objects := payloadEntries(t, f.root)
	if len(objects) != 1 {
		t.Fatal("checkpoint payload count", len(objects))
	}
	chunkID := objects[0].Name()[len(f.a.Tenant)+len(f.a.Partner)+2:]
	if _, stream, err := f.service.Download(f.ctx, f.a, chunkID); !errors.Is(err, store.ErrNotFound) {
		if stream != nil {
			stream.Close()
		}
		t.Fatal("raw chunk ID disclosed bytes", err)
	}
	// Reopen service and storage, using only durable records to find progress.
	disk, err := custody.OpenExisting(f.root)
	if err != nil {
		t.Fatal(err)
	}
	defer disk.Close()
	resumed := &custody.Service{DB: f.db, Disk: disk, MaxFile: 1 << 20, MaxStored: 4 << 20, UploadCheckpointBytes: 64 << 10}
	status, err := resumed.UploadStatus(f.ctx, f.a, id)
	if err != nil || status.Offset != 64<<10 {
		t.Fatal(err)
	}
	repeat, err := resumed.AppendUpload(f.ctx, f.a, id, "first", 0, int64(len(half)), secure.Digest(half), bytes.NewReader(half))
	if err != nil || !repeat.Replayed || repeat.Upload.Offset != first.Upload.Offset {
		t.Fatal("checkpoint retry", err)
	}
	if _, err = resumed.AppendUpload(f.ctx, f.a, id, "wrong-offset", 0, int64(len(half)), secure.Digest(half), bytes.NewReader(half)); !errors.Is(err, store.ErrRevision) {
		t.Fatal("stale offset accepted", err)
	}
	if _, err = resumed.AppendUpload(f.ctx, f.a, id, "second", 64<<10, int64(len(half)), secure.Digest(half), bytes.NewReader(half)); err != nil {
		t.Fatal(err)
	}
	completed, err := resumed.CompleteUpload(f.ctx, f.a, id, "finish")
	if err != nil || completed.Upload.State != "completed" {
		t.Fatal(err)
	}
	retried, err := resumed.CompleteUpload(f.ctx, f.a, id, "finish")
	if err != nil || !retried.Replayed || retried.File.ID != completed.File.ID {
		t.Fatal("completion retry changed file", err)
	}
	_, stream, err := resumed.DownloadPath(f.ctx, f.a, "/resumed")
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(stream)
	stream.Close()
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("resumed bytes", err)
	}
	if _, err = resumed.AbortUpload(f.ctx, f.a, id, "abort-completed"); !errors.Is(err, store.ErrState) {
		t.Fatal("abort removed accepted revision", err)
	}
}

func TestOwnedUploadDiscoveryIsBoundedPrivateAndCursorStable(t *testing.T) {
	f := setup(t)
	for _, name := range []string{"first", "second", "third"} {
		if _, err := f.service.CreateUpload(f.ctx, f.a, "list-"+name, custody.CreateUpload{Path: "/" + name, Size: 1, SHA256: secure.Digest([]byte("x"))}); err != nil {
			t.Fatal(err)
		}
	}
	first, err := f.service.ListUploads(f.ctx, f.a, "", 2)
	if err != nil || len(first.Uploads) != 2 || first.Next == "" {
		t.Fatal("first page", err)
	}
	last, err := f.service.ListUploads(f.ctx, f.a, first.Next, 2)
	if err != nil || len(last.Uploads) != 1 || last.Next != "" {
		t.Fatal("last page", err)
	}
	for _, u := range first.Uploads {
		if u.ID == last.Uploads[0].ID {
			t.Fatal("cursor duplicated upload")
		}
	}
	for _, scope := range []store.Scope{f.b, f.c} {
		page, err := f.service.ListUploads(f.ctx, scope, "", 2)
		if err != nil || len(page.Uploads) != 0 || page.BlockedByAccessChange {
			t.Fatal("foreign discovery disclosed upload metadata", err)
		}
	}
	for _, limit := range []int{0, 101} {
		if _, err := f.service.ListUploads(f.ctx, f.a, "", limit); !errors.Is(err, custody.ErrInput) {
			t.Fatal("unbounded page", err)
		}
	}
	if _, err := f.service.ListUploads(f.ctx, f.a, "invalid", 2); !errors.Is(err, custody.ErrInput) {
		t.Fatal("invalid cursor", err)
	}
}
func TestUploadMismatchConcurrencyAndAbort(t *testing.T) {
	f := setup(t)
	data := bytes.Repeat([]byte("a"), 64<<10)
	created, err := f.service.CreateUpload(f.ctx, f.a, "create-bad", custody.CreateUpload{Path: "/bad", Size: int64(len(data)), SHA256: secure.Digest(bytes.Repeat([]byte("b"), len(data)))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.service.AppendUpload(f.ctx, f.a, created.Upload.ID, "body", 0, int64(len(data)), secure.Digest(data), bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	if _, err = f.service.CompleteUpload(f.ctx, f.a, created.Upload.ID, "reject"); !errors.Is(err, custody.ErrIntegrity) {
		t.Fatal("wrong original digest published", err)
	}
	repeated, err := f.service.CompleteUpload(f.ctx, f.a, created.Upload.ID, "reject")
	if !errors.Is(err, custody.ErrIntegrity) || !repeated.Replayed {
		t.Fatal("rejected completion lost idempotency", err)
	}
	if _, err = f.service.StatPath(f.ctx, f.a, "/bad"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	created, err = f.service.CreateUpload(f.ctx, f.a, "create-concurrent", custody.CreateUpload{Path: "/one-winner", Size: 128 << 10, SHA256: secure.Digest(bytes.Repeat([]byte("a"), 128<<10))})
	if err != nil {
		t.Fatal(err)
	}
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, key := range []string{"one", "two"} {
		wg.Add(1)
		go func(key string) {
			defer wg.Done()
			_, err := f.service.AppendUpload(f.ctx, f.a, created.Upload.ID, key, 0, int64(len(data)), secure.Digest(data), bytes.NewReader(data))
			errs <- err
		}(key)
	}
	wg.Wait()
	close(errs)
	success, stale := 0, 0
	for err := range errs {
		if err == nil {
			success++
		} else if errors.Is(err, store.ErrRevision) {
			stale++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || stale != 1 {
		t.Fatal("checkpoint ownership", success, stale)
	}
	if _, err = f.service.AbortUpload(f.ctx, f.a, created.Upload.ID, "abort"); err != nil {
		t.Fatal(err)
	}
	if _, err = f.service.AppendUpload(f.ctx, f.a, created.Upload.ID, "after-abort", 64<<10, int64(len(data)), secure.Digest(data), bytes.NewReader(data)); !errors.Is(err, store.ErrState) {
		t.Fatal("aborted upload resumed", err)
	}
	// Existing checkpoint bytes remain sealed for auditable recovery/retention.
	entries, err := os.ReadDir(f.root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		st, err := os.Stat(filepath.Join(f.root, entry.Name()))
		if err != nil || st.Mode().Perm() != 0400 {
			t.Fatal("checkpoint not sealed", err)
		}
	}
}

func TestUploadRejectsDifferentStorage(t *testing.T) {
	f := setup(t)
	data := bytes.Repeat([]byte("a"), 64<<10)
	created, err := f.service.CreateUpload(f.ctx, f.a, "store-bound", custody.CreateUpload{Path: "/store-bound", Size: 128 << 10, SHA256: secure.Digest(bytes.Repeat([]byte("a"), 128<<10))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.service.AppendUpload(f.ctx, f.a, created.Upload.ID, "first", 0, int64(len(data)), secure.Digest(data), bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	other, err := custody.Open(filepath.Join(t.TempDir(), "other-custody"))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	wrong := &custody.Service{DB: f.db, Disk: other, MaxFile: 1 << 20, MaxStored: 4 << 20}
	if _, err = wrong.AppendUpload(f.ctx, f.a, created.Upload.ID, "second", 64<<10, int64(len(data)), secure.Digest(data), bytes.NewReader(data)); err == nil {
		t.Fatal("checkpoint accepted into a different storage root")
	}
}

func payloadEntries(t *testing.T, path string) []os.DirEntry {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	result := make([]os.DirEntry, 0, len(entries))
	marker := false
	for _, entry := range entries {
		if entry.Name() == custody.StorageIdentityName {
			marker = true
			st, err := entry.Info()
			if err != nil || st.Size() != 36 || st.Mode().Perm() != 0400 {
				t.Fatal("invalid storage identity", err)
			}
			continue
		}
		result = append(result, entry)
	}
	if !marker {
		t.Fatal("missing storage identity")
	}
	return result
}

func TestUploadRechecksDestinationAndCheckpointIntegrity(t *testing.T) {
	f := setup(t)
	data := bytes.Repeat([]byte("a"), 64<<10)
	create := func(key, path string) *custody.UploadResult {
		t.Helper()
		u, err := f.service.CreateUpload(f.ctx, f.a, key, custody.CreateUpload{Path: path, Size: int64(len(data)), SHA256: secure.Digest(data)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.service.AppendUpload(f.ctx, f.a, u.Upload.ID, key+"-chunk", 0, int64(len(data)), secure.Digest(data), bytes.NewReader(data)); err != nil {
			t.Fatal(err)
		}
		return u
	}
	u := create("target", "/target")
	old, _, err := f.service.AcceptAt(f.ctx, f.a, "other-publication", 3, secure.Digest([]byte("old")), bytes.NewReader([]byte("old")), custody.UploadTarget{Path: "/target"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.service.CompleteUpload(f.ctx, f.a, u.Upload.ID, "finish-stale"); !errors.Is(err, store.ErrRevision) {
		t.Fatal("ticket overwrote a changed destination", err)
	}
	stat, err := f.service.StatPath(f.ctx, f.a, "/target")
	if err != nil || stat.FileID != old.ID {
		t.Fatal("changed destination lost", err)
	}
	before := payloadEntries(t, f.root)
	seen := map[string]bool{}
	for _, entry := range before {
		seen[entry.Name()] = true
	}
	u = create("corrupt", "/corrupt")
	entries := payloadEntries(t, f.root)
	var checkpoint string
	for _, entry := range entries {
		if !seen[entry.Name()] {
			checkpoint = filepath.Join(f.root, entry.Name())
		}
	}
	if checkpoint == "" {
		t.Fatal("checkpoint missing")
	}
	if err = os.Chmod(checkpoint, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(checkpoint, bytes.Repeat([]byte("z"), len(data)), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(checkpoint, 0400); err != nil {
		t.Fatal(err)
	}
	if _, err = f.service.CompleteUpload(f.ctx, f.a, u.Upload.ID, "finish-corrupt"); !errors.Is(err, custody.ErrIntegrity) {
		t.Fatal("changed checkpoint published", err)
	}
	if _, err = f.service.StatPath(f.ctx, f.a, "/corrupt"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("corrupt bytes became visible", err)
	}
	report, err := f.service.Reconcile(f.ctx, f.a)
	if err != nil || report.Consistent || report.Counts["checkpoint_integrity_mismatch"] != 1 {
		t.Fatal("checkpoint corruption hidden", report, err)
	}
}

func TestUploadStopsCheckpointAfterFolderPermissionRevocation(t *testing.T) {
	f := setup(t)
	shared := uint32(0770)
	folder := pathCommand(t, f, "shared-folder", store.PathCommand{Operation: "mkdir", Path: "/inbox", Mode: &shared})
	writer := restrictedIdentity(t, f, []string{"write", "read", "list", "manage_paths"}, "/inbox")
	data := bytes.Repeat([]byte("x"), 64<<10)
	upload, err := f.service.CreateUpload(f.ctx, writer, "create-before-revoke", custody.CreateUpload{Path: "/file", Size: int64(len(data)), SHA256: secure.Digest(data)})
	if err != nil {
		t.Fatal(err)
	}
	zero := uint32(0)
	pathCommand(t, f, "revoke-folder", store.PathCommand{Operation: "setstat", Path: "/inbox", ExpectedRevision: &folder.Entry.Revision, Mode: &zero})
	if _, err = f.service.AppendUpload(f.ctx, writer, upload.Upload.ID, "after-revoke", 0, int64(len(data)), secure.Digest(data), bytes.NewReader(data)); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("new checkpoint ignored revoked folder permission", err)
	}
}
