package workflow

import (
	"os"
	"path/filepath"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/protectedfs"
)

// Go's testing temporary subdirectory is not a private-key custody contract.
// Create a separate owner-only child, then verify it before a peer can mount it.
// Keep the independent peer's own non-symlink/0700 checks intact.
func privatePeerDirectory(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "freightctl-private-peer-"+secure.NewID())
	handle, err := protectedfs.CreateDirectoryExclusive(dir)
	if err != nil {
		t.Fatal("private independent peer directory unavailable", err)
	}
	defer handle.Close()
	st, err := os.Lstat(dir)
	if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		t.Fatal("independent peer directory violates private custody", err)
	}
	if err = protectedfs.ValidateDirectory(handle); err != nil {
		t.Fatal("independent peer directory violates native private custody", err)
	}
	return dir
}

func TestIndependentPeerDirectoryUsesActualPrivateFilesystemPermissions(t *testing.T) {
	first, second := privatePeerDirectory(t), privatePeerDirectory(t)
	if first == second {
		t.Fatal("independent peers shared a directory")
	}
	for _, dir := range []string{first, second} {
		st, err := os.Lstat(dir)
		if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			t.Fatal("peer directory is not private", err)
		}
		file := filepath.Join(dir, "synthetic-key-input")
		f, err := protectedfs.CreateExclusive(file)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.Write([]byte("synthetic fixture; no key material")); err != nil {
			f.Close()
			t.Fatal(err)
		}
		state, err := protectedfs.Protection(f)
		closeErr := f.Close()
		if err != nil || closeErr != nil || state != protectedfs.PrivateWritable {
			t.Fatal("private fixture file permission differs", err, closeErr)
		}
	}
}
