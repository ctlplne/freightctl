//go:build !windows

package protectedfs

import (
	"errors"
	"os"
	"testing"
)

func setSocketFixturePrivacy(t *testing.T, path string, broad bool) {
	t.Helper()
	mode := os.FileMode(0600)
	if broad {
		mode = 0666
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func TestPrivateSocketReferenceRefusesRenamedPathReplacement(t *testing.T) {
	path := socketFixture(t)
	ref, err := OpenPrivateSocket(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ref.Close()
	if err = os.Rename(path, path+"-retained"); err != nil {
		t.Fatal(err)
	}
	f, err := CreateExclusive(path)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err = ref.Validate(); !errors.Is(err, ErrPrivacy) {
		t.Fatal("replacement inherited the original socket's qualification", err)
	}
}
