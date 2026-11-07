//go:build !windows

package crypto

import (
	"os"
	"testing"
)

func broadenPrivateFileForTest(t *testing.T, path string) {
	setReferenceAccessForTest(t, path, 0644)
}

func setReferenceAccessForTest(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}
