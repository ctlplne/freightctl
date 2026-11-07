//go:build !windows

package crypto

import (
	"os"
	"testing"
)

func broadenPrivateFileForTest(t *testing.T, path string) {
	t.Helper()
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
}
