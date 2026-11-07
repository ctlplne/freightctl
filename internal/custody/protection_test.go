package custody

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/protectedfs"
)

func TestExactDigestDoesNotMakeWritableStagingReadableAsImmutableCustody(t *testing.T) {
	disk, err := Open(filepath.Join(t.TempDir(), "custody"))
	if err != nil {
		t.Fatal(err)
	}
	defer disk.Close()
	name := Name(secure.NewID(), secure.NewID(), secure.NewID())
	body := []byte("synthetic reserved artifact\n")
	file, err := protectedfs.CreateAt(disk.root, name)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err = file.Write(body); err != nil {
		t.Fatal(err)
	}
	if err = file.Sync(); err != nil {
		t.Fatal(err)
	}
	state, err := disk.GeneratedSlotState(t.Context(), name)
	if err != nil || state != "partial" {
		t.Fatal("writable reserved object is not partial", state, err)
	}
	if opened, err := disk.Verified(name, int64(len(body)), secure.Digest(body)); !errors.Is(err, ErrIntegrity) {
		if opened != nil {
			opened.Close()
		}
		t.Fatal("exact hash admitted writable staging as immutable custody", err)
	}
	if err = disk.VerifyGenerated(t.Context(), name, int64(len(body)), secure.Digest(body)); !errors.Is(err, ErrIntegrity) {
		t.Fatal("partial object adopted", err)
	}
	if err = protectedfs.SealReadOnly(file); err != nil {
		t.Fatal(err)
	}
	if err = file.Sync(); err != nil {
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	if err = disk.sync(); err != nil {
		t.Fatal(err)
	}
	state, err = disk.GeneratedSlotState(t.Context(), name)
	if err != nil || state != "sealed" {
		t.Fatal("sealed object misclassified", state, err)
	}
	if err = disk.VerifyGenerated(t.Context(), name, int64(len(body)), secure.Digest(body)); err != nil {
		t.Fatal("original recovery cannot establish persistence", err)
	}
	opened, err := disk.Verified(name, int64(len(body)), secure.Digest(body))
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	got, err := io.ReadAll(opened)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatal("sealed exact bytes changed", err)
	}
}

func requireObjectProtectionForTest(t testing.TB, path string, want protectedfs.ProtectionState) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	got, err := protectedfs.Protection(f)
	if err != nil || got != want {
		t.Fatal("actual held-object protection differs", got, want, err)
	}
}
