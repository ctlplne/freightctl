//go:build darwin || linux

package delivery

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/protectedfs"
)

func TestLocalCollectionPeerRefusesSymlinksAndRootReplacement(t *testing.T) {
	directory, identity := localSourceFixture(t)
	body := bytes.Repeat([]byte("synthetic held local input\n"), 3000)
	outside := filepath.Join(filepath.Dir(directory), "outside.csv")
	localSourceWrite(t, outside, body)
	alias := filepath.Join(directory, "linked.csv")
	if err := os.Symlink(outside, alias); err != nil {
		t.Fatal(err)
	}
	check := func() error { return nil }
	p, err := OpenLocalCollectionPeer(t.Context(), directory, identity, check)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	var refused bytes.Buffer
	if err = p.CopyVerified(t.Context(), "linked.csv", int64(len(body)), secure.Digest(body), &refused, check); !errors.Is(err, ErrLocalSource) || refused.Len() != 0 {
		t.Fatal("symlink escaped reviewed source", err)
	}
	if _, err = p.ReadManifest(t.Context(), "linked.csv", check); !errors.Is(err, ErrLocalSource) {
		t.Fatal("symlink became a manifest", err)
	}
	rootAlias := directory + "-alias"
	if err = os.Symlink(directory, rootAlias); err != nil {
		t.Fatal(err)
	}
	if mistaken, err := OpenLocalCollectionPeer(t.Context(), rootAlias, identity, check); !errors.Is(err, ErrLocalSource) {
		if mistaken != nil {
			mistaken.Close()
		}
		t.Fatal("root symlink adopted approved physical identity", err)
	}
	localSourceWrite(t, filepath.Join(directory, "data.csv"), body)
	retained := directory + "-retained"
	writer := &localSourceObservedWriter{after: func() {
		if err := os.Rename(directory, retained); err != nil {
			t.Fatal(err)
		}
		if err := protectedfs.EnsureDirectory(directory); err != nil {
			t.Fatal(err)
		}
		localSourceWrite(t, filepath.Join(directory, "data.csv"), []byte("foreign replacement"))
	}}
	if err = p.CopyVerified(t.Context(), "data.csv", int64(len(body)), secure.Digest(body), writer, check); !errors.Is(err, ErrLocalSource) || writer.Len() != 32<<10 {
		t.Fatal("replaced root became a complete local input", err, writer.Len())
	}
	for path, want := range map[string][]byte{filepath.Join(retained, "data.csv"): body, filepath.Join(directory, "data.csv"): []byte("foreign replacement")} {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("refusal changed producer or foreign bytes", err)
		}
	}
}
