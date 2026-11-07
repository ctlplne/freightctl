//go:build windows

package protectedfs

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestWindowsSealedFileRefusesANewDataWriteHandle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sealed-object")
	f, err := CreateExclusive(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	want := []byte("original immutable bytes")
	if _, err = f.Write(want); err != nil {
		t.Fatal(err)
	}
	if err = SealReadOnly(f); err != nil {
		t.Fatal(err)
	}
	if err = f.Sync(); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	if writer, err := os.OpenFile(path, os.O_WRONLY, 0); err == nil {
		writer.Close()
		t.Fatal("sealed object granted a new data-write handle")
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("refused write changed sealed bytes", err)
	}
}
