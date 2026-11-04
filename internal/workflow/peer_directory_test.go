package workflow

import (
	"os"
	"path/filepath"
	"testing"
)

// Go's testing temporary subdirectory is not a private-key custody contract.
// Create a separate owner-only child, then verify it before a peer can mount it.
// Keep the independent peer's own non-symlink/0700 checks intact.
func privatePeerDirectory(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp(t.TempDir(), "freightctl-private-peer-")
	if err != nil {
		t.Fatal("private independent peer directory unavailable", err)
	}
	st, err := os.Lstat(dir)
	if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0077 != 0 {
		t.Fatal("independent peer directory violates private custody", err)
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
		if err != nil || st.Mode().Perm() != 0700 || st.Mode()&os.ModeSymlink != 0 {
			t.Fatal("peer directory is not private", err)
		}
		file := filepath.Join(dir, "synthetic-key-input")
		if err = os.WriteFile(file, []byte("synthetic fixture; no key material"), 0600); err != nil {
			t.Fatal(err)
		}
		st, err = os.Lstat(file)
		if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 {
			t.Fatal("private fixture file permission differs", err)
		}
	}
}
