//go:build !windows

package custody

import (
	"os"
	"testing"
)

func setCustodyAccessForTest(t testing.TB, path string, writable bool) {
	t.Helper()
	mode := os.FileMode(0400)
	if writable {
		mode = 0600
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func makeBroadRootForTest(t testing.TB, path string) {
	t.Helper()
	if err := os.Chmod(path, 0755); err != nil {
		t.Fatal(err)
	}
}

func rootProtectionSnapshotForTest(t testing.TB, path string) string {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return st.Mode().String()
}
