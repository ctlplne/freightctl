package durablefs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSyncDirectoryKeepsOriginalHandleOwnedByCaller(t *testing.T) {
	path := filepath.Join(t.TempDir(), "freightctl-directory")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	directory, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	if err = SyncDirectory(directory); err != nil {
		t.Fatal(err)
	}
	if _, err = directory.Stat(); err != nil {
		t.Fatal("directory sync consumed its caller's handle", err)
	}
}

func TestSyncDirectoryRefusesNilRegularAndClosedInputs(t *testing.T) {
	if !errors.Is(SyncDirectory(nil), os.ErrInvalid) {
		t.Fatal("nil directory accepted")
	}
	file, err := os.Create(filepath.Join(t.TempDir(), "freightctl-regular"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { file.Close() })
	if !errors.Is(SyncDirectory(file), ErrDirectoryIdentity) {
		t.Fatal("regular file accepted as directory")
	}
	if _, err := file.Stat(); err != nil {
		t.Fatal("refusal consumed caller's regular file handle", err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(SyncDirectory(file), os.ErrClosed) {
		t.Fatal("closed file accepted")
	}
}
