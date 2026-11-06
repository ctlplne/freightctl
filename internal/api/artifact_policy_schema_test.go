package api

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ctlplne/freightctl/internal/store"
	"github.com/google/jsonschema-go/jsonschema"
)

func TestPublicArtifactPolicySchemasMatchActualDomain(t *testing.T) {
	var cases []struct {
		Name   string `json:"name"`
		Policy string `json:"policy"`
		Valid  bool   `json:"valid"`
	}
	wire, err := os.ReadFile("../../web/tests/fixtures/artifact-policy-cases.json")
	if err != nil || json.Unmarshal(wire, &cases) != nil || len(cases) != 32 {
		t.Fatal("shared artifact policy cases missing", err)
	}
	for _, c := range cases {
		if store.ValidArtifactPolicy(c.Policy) != c.Valid {
			t.Fatalf("case %s differs from the actual custody domain", c.Name)
		}
	}
	contracts := map[string][]byte{"mcp": mcpCatalog}
	for _, name := range []string{"artifact-exchange", "artifact-onward", "artifact-collection-source", "received-artifact-copy", "artifact-evidence"} {
		body, err := os.ReadFile(filepath.Join("../../docs/api", name+".openapi.json"))
		if err != nil {
			t.Fatal(err)
		}
		contracts[name] = body
	}
	for name, wire := range contracts {
		t.Run(name, func(t *testing.T) {
			var document any
			if json.Unmarshal(wire, &document) != nil {
				t.Fatal("invalid schema document")
			}
			count := 0
			var walk func(any)
			walk = func(value any) {
				switch v := value.(type) {
				case []any:
					for _, child := range v {
						walk(child)
					}
				case map[string]any:
					if properties, ok := v["properties"].(map[string]any); ok && properties["acceptance_policy"] != nil {
						count++
						encoded, err := json.Marshal(properties["acceptance_policy"])
						if err != nil {
							t.Fatal(err)
						}
						var schema jsonschema.Schema
						if json.Unmarshal(encoded, &schema) != nil {
							t.Fatal("invalid artifact policy schema")
						}
						resolved, err := schema.Resolve(nil)
						if err != nil {
							t.Fatal(err)
						}
						for _, c := range cases {
							if (resolved.Validate(c.Policy) == nil) != store.ValidArtifactPolicy(c.Policy) {
								t.Errorf("policy schema differs from the actual custody domain: %s", c.Name)
							}
						}
					}
					for _, child := range v {
						walk(child)
					}
				}
			}
			walk(document)
			want := 1
			if name == "mcp" {
				want = 8
			}
			if count != want {
				t.Fatalf("policy schema coverage changed: got %d,want %d", count, want)
			}
		})
	}
}
