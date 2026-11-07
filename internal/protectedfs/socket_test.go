package protectedfs

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func socketFixture(t *testing.T) string {
	t.Helper()
	parent, err := os.MkdirTemp("", "freightctl-socket-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(parent) })
	dir := filepath.Join(parent, "private")
	f, err := CreateDirectoryExclusive(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "s")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	setSocketFixturePrivacy(t, path, false)
	return path
}

func TestPrivateSocketReferenceRequiresActualPrivacyAndRefusesRegularFiles(t *testing.T) {
	path := socketFixture(t)
	ref, err := OpenPrivateSocket(path)
	if err != nil {
		t.Fatal("private native socket refused", err)
	}
	defer ref.Close()
	if err = ref.Validate(); err != nil {
		t.Fatal(err)
	}
	setSocketFixturePrivacy(t, path, true)
	if err = ref.Validate(); !errors.Is(err, ErrPrivacy) {
		t.Fatal("held socket accepted broad access", err)
	}
	if broad, err := OpenPrivateSocket(path); err == nil {
		broad.Close()
		t.Fatal("new socket reference accepted broad access")
	}
	setSocketFixturePrivacy(t, path, false)
	if err = ref.Validate(); err != nil {
		t.Fatal("restored exact owned socket refused", err)
	}
	if err = ref.Close(); err != nil || !errors.Is(ref.Validate(), os.ErrClosed) {
		t.Fatal("closed reference remained usable", err)
	}
	regular := filepath.Join(filepath.Dir(path), "ordinary")
	f, err := CreateExclusive(regular)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	if mistaken, err := OpenPrivateSocket(regular); !errors.Is(err, ErrPrivacy) {
		if mistaken != nil {
			mistaken.Close()
		}
		t.Fatal("private regular file became a socket", err)
	}
}
