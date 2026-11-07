package protectedfs

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateCreationUsesHeldRootAfterRenameAndNeverOverwrites(t *testing.T) {
	base := t.TempDir()
	path, moved := filepath.Join(base, "original"), filepath.Join(base, "moved")
	directory, err := CreateDirectoryExclusive(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = ValidateDirectory(directory); err != nil {
		t.Fatal(err)
	}
	if err = directory.Close(); err != nil {
		t.Fatal(err)
	}
	if another, err := CreateDirectoryExclusive(path); !errors.Is(err, os.ErrExist) {
		if another != nil {
			another.Close()
		}
		t.Fatal("existing directory adopted or changed", err)
	}
	// Root.OpenRoot uses handle-relative opening. On Windows this permits the
	// deliberate rename,whereas os.OpenRoot pins the name without share-delete.
	parent, err := os.OpenRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	root, err := parent.OpenRoot("original")
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err = os.Rename(path, moved); err != nil {
		t.Fatal(err)
	}
	replacement, err := CreateDirectoryExclusive(path)
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	f, err := CreateAt(root, "private-object")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err = ValidateFile(f); err != nil {
		t.Fatal("new object was not private before its first byte", err)
	}
	want := []byte("exact task-owned private object")
	if _, err = f.Write(want); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	if another, err := CreateAt(root, "private-object"); !errors.Is(err, os.ErrExist) {
		if another != nil {
			another.Close()
		}
		t.Fatal("existing private object overwritten", err)
	}
	got, err := os.ReadFile(filepath.Join(moved, "private-object"))
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("held-root creation lost original destination or bytes", err)
	}
	if _, err := os.Lstat(filepath.Join(path, "private-object")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("creation followed replacement root pathname", err)
	}
}

func TestPrivateCreationRejectsEscapingOrAliasedLeafNamesBeforeOpeningRoot(t *testing.T) {
	for _, name := range []string{"", ".", "..", "../escape", "/absolute", `nested\leaf`, "alternate:stream", "trailing.", "NUL", "con.txt", "COM1", "lpt9.dat", "non-ascii-☃"} {
		if privateLeaf(name) {
			t.Fatal("unsafe custody leaf accepted")
		}
		if f, err := CreateAt(nil, name); err == nil || f != nil {
			t.Fatal("unsafe creation opened a root")
		}
	}
	for _, name := range []string{".freightctl-storage-id", "11111111-1111-4111-8111-111111111111_object", "private-object"} {
		if !privateLeaf(name) {
			t.Fatal("valid service-owned leaf refused")
		}
	}
}

func TestPrivateDirectorySupportsOwnerPathsWithSpacesAndUnicode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private directory-☃")
	f, err := CreateDirectoryExclusive(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err = ValidateDirectory(f); err != nil {
		t.Fatal(err)
	}
}
