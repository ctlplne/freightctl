package custody

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
)

func TestGeneratedArtifactRefusesOverflowCancellationAndIncompleteGeneration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "custody")
	disk, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer disk.Close()
	for _, kind := range []string{"overflow", "canceled", "callback"} {
		ctx, cancel := context.WithCancel(context.Background())
		name := Name(secure.NewID(), secure.NewID(), secure.NewID())
		_, _, err := disk.StageGenerated(ctx, name, 4, func(w io.Writer) error {
			if _, err := w.Write([]byte("123")); err != nil {
				return err
			}
			if kind == "canceled" {
				cancel()
			}
			if kind == "callback" {
				return io.ErrUnexpectedEOF
			}
			_, err := w.Write([]byte("45"))
			return err
		})
		cancel()
		if err == nil {
			t.Fatal("invalid generation sealed", kind)
		}
		if _, err = os.Stat(filepath.Join(path, name)); !os.IsNotExist(err) {
			t.Fatal("new partial artifact retained", kind, err)
		}
	}
	name := Name(secure.NewID(), secure.NewID(), secure.NewID())
	size, hash, err := disk.StageGenerated(context.Background(), name, 4, func(w io.Writer) error { _, err := w.Write([]byte("1234")); return err })
	if err != nil || size != 4 || hash != secure.Digest([]byte("1234")) {
		t.Fatal(size, hash, err)
	}
	st, err := os.Stat(filepath.Join(path, name))
	if err != nil || st.Mode().Perm() != 0400 {
		t.Fatal(st, err)
	}
	if err = disk.Capacity(1, 4); !errors.Is(err, ErrCapacity) {
		t.Fatal("unaccepted sealed artifact escaped quota", err)
	}
}
