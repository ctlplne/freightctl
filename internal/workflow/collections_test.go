package workflow

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/ctlplne/freightctl/internal/store"
)

func collectionTestSource() CollectionSource {
	return CollectionSource{Kind: "sftp.collect", Connection: Reference{ID: "00000000-0000-0000-0000-000000000001", Version: 1, Hash: strings.Repeat("a", 64)}, Manifest: "settlement.ready.json", Directory: "/incoming", Contract: CollectionContract, MaxFiles: 2, MaxFile: 1024, MaxTotal: 1024}
}
func TestCollectionManifestRequiresExactBoundedProducerClaims(t *testing.T) {
	source := collectionTestSource()
	valid := `{"schema_version":1,"batch_id":"00000000-0000-0000-0000-000000000002","files":[{"name":"one.csv","size_bytes":3,"sha256":"` + strings.Repeat("b", 64) + `"}]}`
	m, hash, e := parseCollectionManifest([]byte(valid), source)
	if e != nil || len(m.Files) != 1 || len(hash) != 64 {
		t.Fatal(m, hash, e)
	}
	pretty, _ := json.MarshalIndent(m, "", "  ")
	_, same, e := parseCollectionManifest(pretty, source)
	if e != nil || same != hash {
		t.Fatal("formatting changed typed batch identity", e)
	}
	for name, data := range map[string]string{
		"invented-authority": strings.Replace(valid, `"schema_version":1`, `"schema_version":1,"approved":true`, 1),
		"duplicate-key":      strings.Replace(valid, `"size_bytes":3`, `"size_bytes":3,"size_bytes":4`, 1),
		"traversal":          strings.Replace(valid, "one.csv", "../one.csv", 1),
		"absolute":           strings.Replace(valid, "one.csv", "/one.csv", 1),
		"nested":             strings.Replace(valid, "one.csv", "sub/one.csv", 1),
		"ready-as-payload":   strings.Replace(valid, "one.csv", "other.ready.json", 1),
		"unsafe-local-name":  strings.Replace(valid, "one.csv", "one.csv.", 1),
		"missing-digest":     strings.Replace(valid, strings.Repeat("b", 64), "", 1),
		"size-limit":         strings.Replace(valid, `"size_bytes":3`, `"size_bytes":1025`, 1),
		"invalid-batch":      strings.Replace(valid, "00000000-0000-0000-0000-000000000002", "someone-said-complete", 1),
		"null-files":         strings.Replace(valid, `[{"name":"one.csv","size_bytes":3,"sha256":"`+strings.Repeat("b", 64)+`"}]`, `null`, 1),
		"oversized-json":     valid + strings.Repeat(" ", 33<<10),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, e := parseCollectionManifest([]byte(data), source); e == nil {
				t.Fatal("untrusted manifest granted input", data[:min(len(data), 200)])
			}
		})
	}
	m.Files = append(m.Files, m.Files[0])
	data, _ := json.Marshal(m)
	if _, _, e := parseCollectionManifest(data, source); e == nil {
		t.Fatal("duplicate source name admitted")
	}
	m.Files[1].Name = "two.csv"
	m.Files[0].Size = 800
	m.Files[1].Size = 800
	data, _ = json.Marshal(m)
	if _, _, e := parseCollectionManifest(data, source); e == nil {
		t.Fatal("total bound ignored")
	}
}

func TestCollectionGoBrowserCanonicalSourceAndJobSnapshots(t *testing.T) {
	data, e := os.ReadFile("../../web/tests/fixtures/collections.json")
	if e != nil {
		t.Fatal(e)
	}
	var fixtures map[string]struct {
		Workflow  store.Configuration `json:"workflow"`
		Preview   CollectionPreview   `json:"preview"`
		Selection CollectionSelection `json:"selection"`
		View      CollectionView      `json:"view"`
	}
	if e = json.Unmarshal(data, &fixtures); e != nil || len(fixtures) != 3 {
		t.Fatal("fixture", e)
	}
	for name, f := range fixtures {
		t.Run(name, func(t *testing.T) {
			var definition Definition
			if e := Decode(f.Workflow.Definition, &definition); e != nil {
				t.Fatal(e)
			}
			normalized, e := Normalize(definition)
			if e != nil {
				t.Fatal(e)
			}
			_, hash, e := digest(normalized)
			if e != nil || hash != f.Workflow.Hash {
				t.Fatal("ordinary canonical workflow hash", hash, e)
			}
			d, e := collectionDefinition(f.View.Job)
			if e != nil {
				t.Fatal(e)
			}
			_, hash, e = digest(f.Preview.Definition)
			if e != nil || hash != f.Preview.Hash || f.View.Job.Hash != hash || d.Workflow != f.Selection.Workflow || d.Authority != 3 || f.Preview.ExternalContact || !f.Preview.ApprovalRequired {
				t.Fatal("collection canonical binding", hash, e)
			}
			m, hash, e := parseCollectionManifest(f.View.Job.Manifest, d.Source)
			if e != nil || f.View.Job.ManifestHash == nil || hash != *f.View.Job.ManifestHash || len(m.Files) != 1 {
				t.Fatal("producer manifest hash", hash, e)
			}
			if name == "local" && (len(definition.Steps) != 0 || len(d.Effects) != 0 || f.View.Inputs[0].RunID != nil) {
				t.Fatal("local collection acquired a sending intent")
			}
		})
	}
}
func TestCollectionSourcePreservesLegacyCanonicalDefinitionAndOwnsItsSnapshot(t *testing.T) {
	legacy := Definition{Schema: 1, Name: "old", Steps: []Step{{ID: "send", Kind: "sftp.deliver", Connection: collectionTestSource().Connection, Filename: "out.csv"}}}
	data, _, _ := digest(legacy)
	if bytes.Contains(data, []byte(`"source"`)) {
		t.Fatal("legacy definition acquired new meaning")
	}
	source := collectionTestSource()
	legacy.Source = &source
	normalized, e := Normalize(legacy)
	if e != nil {
		t.Fatal(e)
	}
	source.Manifest = "changed.ready.json"
	if normalized.Source.Manifest != "settlement.ready.json" {
		t.Fatal("reviewed source shares caller memory")
	}
	for _, mutate := range []func(*CollectionSource){func(s *CollectionSource) { s.Contract = "stable-size" }, func(s *CollectionSource) { s.Manifest = "../settlement.ready.json" }, func(s *CollectionSource) { s.Directory = "/incoming/../outside" }, func(s *CollectionSource) { s.MaxFiles = 65 }, func(s *CollectionSource) { s.MaxTotal = 1 << 40 }, func(s *CollectionSource) { s.Kind = "shell" }} {
		bad := collectionTestSource()
		mutate(&bad)
		legacy.Source = &bad
		if _, e := Normalize(legacy); e == nil {
			t.Fatal("invalid source authorized", bad)
		}
	}
}
