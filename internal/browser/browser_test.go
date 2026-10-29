package browser

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
)

func TestEmbeddedBrowserArtifactsMatchExactSources(t *testing.T) {
	data, err := assets.ReadFile("assets/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Sources []struct{ Path, SHA256 string }
		Outputs []struct {
			Name, SHA256 string
			Size         int
		}
	}
	if err = json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Sources) < 8 || len(m.Outputs) < 5 {
		t.Fatal("incomplete artifact manifest")
	}
	for _, source := range m.Sources {
		if !strings.HasPrefix(source.Path, "web/") || strings.Contains(source.Path, "..") {
			t.Fatal("unsafe source manifest path")
		}
		b, err := os.ReadFile(filepath.Join("..", "..", source.Path))
		if err != nil || secure.Digest(b) != source.SHA256 {
			t.Fatalf("stale browser source %s: rerun the browser build", source.Path)
		}
	}
	for _, out := range m.Outputs {
		if strings.ContainsAny(out.Name, "/\\") {
			t.Fatal("unsafe artifact name")
		}
		b, err := assets.ReadFile("assets/" + out.Name)
		if err != nil || len(b) != out.Size || secure.Digest(b) != out.SHA256 {
			t.Fatalf("wrong embedded browser artifact %s", out.Name)
		}
	}
}

func TestBrowserAssetBoundaryAndContentSecurityPolicy(t *testing.T) {
	for path, expected := range map[string]int{"/": 200, "/assets/app.js": 200, "/assets/hash-worker.js": 200, "/assets/manifest.json": 404, "/assets/../../.private/credential": 404, "/assets/unknown.js": 404} {
		r := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()
		Serve(w, r)
		if w.Code != expected || w.Header().Get("Content-Security-Policy") != Policy || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("static boundary", path, w.Code)
		}
	}
}
