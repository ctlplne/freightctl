package delivery

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/protectedfs"
)

func localSourceFixture(t *testing.T) (string, string) {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "producer")
	if err := protectedfs.EnsureDirectory(directory); err != nil {
		t.Fatal(err)
	}
	identity, err := InspectLocalCollectionRoot(t.Context(), directory, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	return directory, identity
}

func localSourceWrite(t *testing.T, path string, body []byte) {
	t.Helper()
	f, err := protectedfs.CreateExclusive(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err = f.Write(body); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestLocalCollectionPeerCopiesExactPrivateBytesWithoutMutatingProducer(t *testing.T) {
	directory, identity := localSourceFixture(t)
	other, otherID := localSourceFixture(t)
	if identity == otherID {
		t.Fatal("different physical roots share an identity")
	}
	if p, err := OpenLocalCollectionPeer(t.Context(), other, identity, func() error { return nil }); !errors.Is(err, ErrLocalSource) {
		if p != nil {
			p.Close()
		}
		t.Fatal("foreign physical root adopted reviewed identity", err)
	}
	manifest := []byte(`{"schema_version":1,"untrusted_producer_claim":"not permission"}`)
	body := bytes.Repeat([]byte("synthetic private producer record\n"), 3000)
	localSourceWrite(t, filepath.Join(directory, "batch.ready.json"), manifest)
	localSourceWrite(t, filepath.Join(directory, "data.csv"), body)
	checks := 0
	check := func() error { checks++; return nil }
	p, err := OpenLocalCollectionPeer(t.Context(), directory, identity, check)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	got, err := p.ReadManifest(t.Context(), "batch.ready.json", check)
	if err != nil || !bytes.Equal(got, manifest) {
		t.Fatal("exact bounded manifest changed", err)
	}
	var staged bytes.Buffer
	if err = p.CopyVerified(t.Context(), "data.csv", int64(len(body)), secure.Digest(body), &staged, check); err != nil || !bytes.Equal(staged.Bytes(), body) || checks < 6 {
		t.Fatal("exact read/copy or current authority guard missing", err)
	}
	for name, want := range map[string][]byte{"batch.ready.json": manifest, "data.csv": body} {
		actual, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil || !bytes.Equal(actual, want) {
			t.Fatal("producer changed", err)
		}
	}
	if entries, err := os.ReadDir(directory); err != nil || len(entries) != 2 {
		t.Fatal("adapter wrote extra producer state", err)
	}
}

type localSourceObservedWriter struct {
	bytes.Buffer
	after func()
}

func (w *localSourceObservedWriter) Write(b []byte) (int, error) {
	n, err := w.Buffer.Write(b)
	if w.after != nil {
		fn := w.after
		w.after = nil
		fn()
	}
	return n, err
}

func TestLocalCollectionPeerRevocationAndPhysicalReplacementRefuseFurtherAcceptance(t *testing.T) {
	for _, mode := range []string{"revoked", "replaced"} {
		t.Run(mode, func(t *testing.T) {
			directory, identity := localSourceFixture(t)
			body := bytes.Repeat([]byte("x"), 64<<10)
			path := filepath.Join(directory, "data.csv")
			localSourceWrite(t, path, body)
			denied := errors.New("synthetic current authority revoked")
			revoked := false
			check := func() error {
				if revoked {
					return denied
				}
				return nil
			}
			p, err := OpenLocalCollectionPeer(t.Context(), directory, identity, check)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			writer := &localSourceObservedWriter{after: func() {
				if mode == "revoked" {
					revoked = true
					return
				}
				if err := os.Rename(path, path+"-retained"); err != nil {
					t.Fatal(err)
				}
				localSourceWrite(t, path, body)
			}}
			err = p.CopyVerified(t.Context(), "data.csv", int64(len(body)), secure.Digest(body), writer, check)
			wanted := error(ErrLocalSource)
			if mode == "revoked" {
				wanted = denied
			}
			if !errors.Is(err, wanted) || writer.Len() != 32<<10 {
				t.Fatal("revoked/replaced source became complete", err, writer.Len())
			}
		})
	}
}

func TestLocalCollectionPeerRejectsUnsafeNamesSizesHashesAndAbsentAuthority(t *testing.T) {
	directory, identity := localSourceFixture(t)
	body := []byte("exact")
	localSourceWrite(t, filepath.Join(directory, "data.csv"), body)
	localSourceWrite(t, filepath.Join(directory, "large.ready.json"), bytes.Repeat([]byte("x"), (32<<10)+1))
	check := func() error { return nil }
	if p, err := OpenLocalCollectionPeer(t.Context(), directory, identity, nil); err == nil {
		p.Close()
		t.Fatal("missing authority guard accepted")
	}
	p, err := OpenLocalCollectionPeer(t.Context(), directory, identity, check)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	for _, name := range []string{"../data.csv", "data/child", `data\child`, "data:stream", "data.", "NUL", "CON.txt", "COM1", "LPT9.log"} {
		var output bytes.Buffer
		if err = p.CopyVerified(t.Context(), name, 5, secure.Digest(body), &output, check); !errors.Is(err, ErrLocalSource) || output.Len() != 0 {
			t.Fatal("unsafe name read source", name, err)
		}
	}
	for _, size := range []int64{-1, 4, 6, 1<<30 + 1} {
		var output bytes.Buffer
		if err = p.CopyVerified(t.Context(), "data.csv", size, secure.Digest(body), &output, check); !errors.Is(err, ErrLocalSource) || output.Len() != 0 {
			t.Fatal("wrong size became source bytes", size, err)
		}
	}
	var output bytes.Buffer
	if err = p.CopyVerified(t.Context(), "data.csv", 5, secure.Digest([]byte("wrong")), &output, check); !errors.Is(err, ErrLocalSource) {
		t.Fatal("bad digest qualified local bytes", err)
	}
	if _, err = p.ReadManifest(t.Context(), "large.ready.json", check); !errors.Is(err, ErrLocalSource) {
		t.Fatal("unbounded manifest accepted", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err = p.CopyVerified(ctx, "data.csv", 5, secure.Digest(body), &output, check); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled read continued", err)
	}
}
