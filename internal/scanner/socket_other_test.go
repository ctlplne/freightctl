//go:build !windows

package scanner

import (
	"os"
	"testing"
)

func setScannerFixtureSocketPrivacy(t *testing.T, path string, broad bool) {
	t.Helper()
	mode := os.FileMode(0600)
	if broad {
		mode = 0666
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}
