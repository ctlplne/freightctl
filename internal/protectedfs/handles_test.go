package protectedfs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateHandleCreationIsExclusiveAndCannotValidateAClosedOrWrongObject(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private-reference")
	f, err := CreateExclusive(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err = ValidateFile(f); err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write([]byte("bounded private fixture")); err != nil {
		t.Fatal(err)
	}
	if another, err := CreateExclusive(path); err == nil {
		another.Close()
		t.Fatal("existing secret overwritten")
	}
	if ValidateDirectory(f) == nil {
		t.Fatal("regular file accepted as private directory")
	}
	if ValidateFile(nil) == nil {
		t.Fatal("missing handle accepted")
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	if ValidateFile(f) == nil {
		t.Fatal("closed handle accepted")
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != "bounded private fixture" {
		t.Fatal("exclusive creation changed original bytes", err)
	}
}
