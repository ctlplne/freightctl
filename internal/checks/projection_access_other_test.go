//go:build !windows

package checks

import (
	"os"
	"testing"
)

func rewriteSealedProjectionForTest(t testing.TB, path string, body []byte) {
	t.Helper()
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0400); err != nil {
		t.Fatal(err)
	}
}
