//go:build zipnative

package zipcontainer

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
)

func TestZIPContainerActualStockPythonProducer(t *testing.T) {
	root := os.Getenv("FREIGHTCTL_TEST_ZIP_DIR")
	if root == "" {
		t.Fatal("native stock-Python fixture directory is required")
	}
	data, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil || len(data) > 16<<10 {
		t.Fatal("missing or oversized producer manifest", err)
	}
	var m struct {
		Schema   int               `json:"schema_version"`
		Producer map[string]string `json:"producer"`
		Cases    []struct {
			Name       string `json:"name"`
			SHA256     string `json:"sha256"`
			Bytes      int64  `json:"bytes"`
			Descriptor bool   `json:"data_descriptor"`
			Method     uint16 `json:"method"`
		} `json:"cases"`
		Parts map[string]struct {
			Bytes  int64  `json:"bytes"`
			SHA256 string `json:"sha256"`
		} `json:"parts"`
	}
	if json.Unmarshal(data, &m) != nil || m.Schema != 1 || len(m.Cases) != 4 || len(m.Parts) != 3 || m.Producer["python"] == "" || m.Producer["zlib"] == "" {
		t.Fatal("incomplete stock-producer manifest")
	}
	t.Logf("stock Python %s,zlib %s;four actual stored/deflated/seekable/descriptor inputs", m.Producer["python"], m.Producer["zlib"])
	seen := map[string]bool{}
	profiles := map[string]struct {
		method     uint16
		descriptor bool
	}{"stored-seekable.zip": {0, false}, "stored-descriptor.zip": {0, true}, "deflated-seekable.zip": {8, false}, "deflated-descriptor.zip": {8, true}}
	for _, c := range m.Cases {
		profile, found := profiles[c.Name]
		if !found || profile.method != c.Method || profile.descriptor != c.Descriptor || filepath.Base(c.Name) != c.Name || c.Bytes < 22 || c.Bytes > limits().MaxBytes || seen[c.Name] {
			t.Fatal("invalid producer input binding")
		}
		seen[c.Name] = true
		body, e := os.ReadFile(filepath.Join(root, c.Name))
		if e != nil || int64(len(body)) != c.Bytes || secure.Digest(body) != c.SHA256 {
			t.Fatal("producer source identity differs", e)
		}
		f, e := os.Open(filepath.Join(root, c.Name))
		if e != nil {
			t.Fatal(e)
		}
		func() {
			defer f.Close()
			z, e := Open(context.Background(), f, c.Bytes, limits())
			if e != nil || len(z.Entries()) != len(m.Parts) {
				t.Fatal("stock ZIP refused", e)
			}
			for _, entry := range z.Entries() {
				want, found := m.Parts[entry.Name]
				if !found || entry.Method != c.Method || entry.ExpandedBytes != want.Bytes {
					t.Fatal("stock ZIP member metadata differs")
				}
				e = z.Read(context.Background(), entry.Name, func(r io.Reader) error {
					h := secure.NewDigest()
					n, err := io.CopyBuffer(h, r, make([]byte, 32<<10))
					if err != nil {
						return err
					}
					if n != want.Bytes || hex.EncodeToString(h.Sum(nil)) != want.SHA256 {
						t.Fatal("stock-produced member bytes differ")
					}
					return nil
				})
				if e != nil {
					t.Fatal(e)
				}
			}
			for _, member := range z.entries {
				if (member.flags&8 != 0) != c.Descriptor {
					t.Fatal("stock producer did not exercise the declared descriptor profile")
				}
			}
			if e = z.Verify(context.Background()); e != nil {
				t.Fatal(e)
			}
		}()
	}
}
