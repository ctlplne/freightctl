package custody

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
)

func TestDurableExactRevision(t *testing.T) {
	root := filepath.Join(t.TempDir(), "custody")
	d, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	name := Name(secure.NewID(), secure.NewID(), secure.NewID())
	data := []byte("synthetic payroll,000123,20.01\n")
	hash := secure.Digest(data)
	if err = d.Stage(name, bytes.NewReader(data), int64(len(data)), hash); err != nil {
		t.Fatal(err)
	}
	if err = d.Stage(name, bytes.NewReader(data), int64(len(data)), hash); err == nil {
		t.Fatal("immutable revision overwritten")
	}
	st, err := os.Stat(filepath.Join(root, name))
	if err != nil || st.Mode().Perm() != 0400 {
		t.Fatal("sealed mode", st, err)
	}
	f, err := d.Verified(name, int64(len(data)), hash)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(f)
	f.Close()
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("wrong bytes")
	}
	if err = os.Chmod(filepath.Join(root, name), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, name), bytes.Repeat([]byte("x"), len(data)), 0600); err != nil {
		t.Fatal(err)
	}
	if f, err = d.Verified(name, int64(len(data)), hash); !errors.Is(err, ErrIntegrity) {
		if f != nil {
			f.Close()
		}
		t.Fatal("replacement was not rejected", err)
	}
}

type brokenReader struct{}

func (brokenReader) Read([]byte) (int, error) { return 0, errors.New("source disconnected") }
func TestRejectIncompleteAndEscape(t *testing.T) {
	root := filepath.Join(t.TempDir(), "custody")
	d, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	for _, body := range []io.Reader{strings.NewReader("short"), strings.NewReader("too many bytes"), brokenReader{}} {
		name := Name(secure.NewID(), secure.NewID(), secure.NewID())
		err = d.Stage(name, body, 6, secure.Digest([]byte("123456")))
		if err == nil {
			t.Fatal("bad source accepted")
		}
		if _, err = os.Stat(filepath.Join(root, name)); !os.IsNotExist(err) {
			t.Fatal("partial bytes retained", err)
		}
	}
	if err = d.Stage("../../escaped", strings.NewReader(""), 0, secure.Digest(nil)); err == nil {
		t.Fatal("escaped custody root")
	}
	if err = d.Capacity(11, 10); !errors.Is(err, ErrCapacity) {
		t.Fatal("quota ignored", err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err = os.WriteFile(outside, []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	name := Name(secure.NewID(), secure.NewID(), secure.NewID())
	if err = os.Symlink(outside, filepath.Join(root, name)); err != nil {
		t.Fatal(err)
	}
	if err = d.Stage(name, strings.NewReader("bad"), 3, secure.Digest([]byte("bad"))); err == nil {
		t.Fatal("followed existing symlink")
	}
	if f, err := d.Verified(name, 7, secure.Digest([]byte("outside"))); err == nil {
		f.Close()
		t.Fatal("download escaped through symlink")
	}
}
func TestPrivateRootRequired(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	if d, err := Open(root); err == nil {
		d.Close()
		t.Fatal("insecure existing root accepted")
	}
	st, err := os.Stat(root)
	if err != nil || st.Mode().Perm() != 0755 {
		t.Fatal("existing permissions were silently changed", err)
	}
}
func TestObservationDoesNotCreateRoot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing")
	if d, err := OpenExisting(path); err == nil {
		d.Close()
		t.Fatal("missing root accepted")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("read-only open created a directory", err)
	}
}
func FuzzCustodyName(f *testing.F) {
	f.Add("../../etc/passwd")
	f.Add(Name(secure.NewID(), secure.NewID(), secure.NewID()))
	f.Fuzz(func(t *testing.T, name string) {
		if validName(name) && (strings.ContainsAny(name, "/\\\x00") || len(name) != 110) {
			t.Fatal("unsafe accepted name")
		}
	})
}

func TestStableStorageIdentityAndCorruption(t *testing.T) {
	root := filepath.Join(t.TempDir(), "custody")
	d, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	again, err := OpenExisting(root)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if d.Identity() == "" || d.Identity() != again.Identity() {
		t.Fatal("storage identity changed across reopen")
	}
	other, err := Open(filepath.Join(t.TempDir(), "other"))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if other.Identity() == d.Identity() {
		t.Fatal("different stores share identity")
	}
	marker := filepath.Join(root, StorageIdentityName)
	if err = os.Chmod(marker, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(marker, []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(marker, 0400); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(d.CheckIdentity(), ErrStorageIdentity) {
		t.Fatal("changed storage identity accepted")
	}
	if opened, err := Open(root); err == nil {
		opened.Close()
		t.Fatal("invalid identity silently replaced")
	}
	got, err := os.ReadFile(marker)
	if err != nil || string(got) != "invalid" {
		t.Fatal("corrupt identity overwritten", err)
	}
}

func TestObservationDoesNotInventStorageIdentity(t *testing.T) {
	root := t.TempDir()
	if disk, err := OpenExisting(root); err == nil {
		disk.Close()
		t.Fatal("read-only open initialized storage")
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatal("read-only open changed directory", err)
	}
}

func TestConcurrentStorageInitializationPublishesOneIdentity(t *testing.T) {
	root := filepath.Join(t.TempDir(), "custody")
	ids := make(chan string, 8)
	errs := make(chan error, 8)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			disk, err := Open(root)
			if err != nil {
				errs <- err
				return
			}
			ids <- disk.Identity()
			disk.Close()
		}()
	}
	wg.Wait()
	close(ids)
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	id := ""
	for next := range ids {
		if id == "" {
			id = next
		} else if next != id {
			t.Fatal("racing storage identities")
		}
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 1 || entries[0].Name() != StorageIdentityName {
		t.Fatal("initialization left staging metadata", err)
	}
}
