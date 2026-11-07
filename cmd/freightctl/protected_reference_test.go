package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/ctlplne/freightctl/internal/protectedfs"
)

func privateCLIDirectory(t testing.TB) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "freightctl-private-cli")
	f, err := protectedfs.CreateDirectoryExclusive(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeProtectedCLIReference(t testing.TB, path string, data []byte) {
	t.Helper()
	f, err := protectedfs.CreateExclusive(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err = f.Write(data); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
}

func requireSealedCLIOutput(t testing.TB, path string) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	state, err := protectedfs.Protection(f)
	if err != nil || state != protectedfs.PrivateSealed {
		t.Fatal("output is not private and read-only", err)
	}
}

func TestCLIArtifactRemainsPrivateSealedAndNeverOverwritesAnExistingReview(t *testing.T) {
	dir := privateCLIDirectory(t)
	path := filepath.Join(dir, "review.json")
	if err := writeArtifact(path, map[string]string{"review": "synthetic"}); err != nil {
		t.Fatal(err)
	}
	requireSealedCLIOutput(t, path)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = writeArtifact(path, map[string]string{"review": "changed"}); err == nil {
		t.Fatal("existing review overwritten")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(original, after) {
		t.Fatal("failed publication changed the original", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != "review.json" {
		t.Fatal("artifact staging leaked", err)
	}
}
