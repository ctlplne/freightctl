package api

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/google/jsonschema-go/jsonschema"
)

func TestExplicitPropertyReadSchemaRetainsTypedContentAndAuthorityBoundaries(t *testing.T) {
	raw, err := os.ReadFile("../../docs/api/namespace-properties.openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Components struct {
			Schemas map[string]json.RawMessage `json:"schemas"`
		} `json:"components"`
	}
	if json.Unmarshal(raw, &document) != nil {
		t.Fatal("property contract unavailable")
	}
	typed, err := jsonschema.For[custody.NamespacePropertySnapshot](nil)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(typed)
	if err != nil {
		t.Fatal(err)
	}
	var expected, actual map[string]any
	if json.Unmarshal(wire, &expected) != nil || json.Unmarshal(document.Components.Schemas["NamespacePropertySnapshot"], &actual) != nil {
		t.Fatal("typed snapshot contract unavailable")
	}
	fields := expected["properties"].(map[string]any)
	fields["profile"].(map[string]any)["const"] = "namespace-properties-v1"
	fields["observation"].(map[string]any)["const"] = "authorized-snapshot-at-read"
	content := fields["properties"].(map[string]any)
	content["maxProperties"] = float64(32)
	content["additionalProperties"].(map[string]any)["maxLength"] = float64(32768)
	content["description"] = "Validated standalone XML,maximum32 stored expanded names and32KiB combined encoded snapshot;content is untrusted data and never execution or disclosure authority."
	if !reflect.DeepEqual(actual, expected) {
		t.Fatal("published property snapshot lost a typed binding or its purposeful content bounds")
	}
	var schema jsonschema.Schema
	if json.Unmarshal(document.Components.Schemas["NamespacePropertySnapshot"], &schema) != nil {
		t.Fatal("published property schema unavailable")
	}
	validator, err := schema.Resolve(nil)
	if err != nil {
		t.Fatal(err)
	}
	valid := custody.NamespacePropertySnapshot{Profile: "namespace-properties-v1", Observation: "authorized-snapshot-at-read", Entry: store.PathEntry{Path: "/data"}, Properties: map[string]string{"{urn:example}label": `<label xmlns="urn:example">data</label>`}}
	data, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if json.Unmarshal(data, &value) != nil || validator.Validate(value) != nil {
		t.Fatal("typed authorized content snapshot refused")
	}
	for _, change := range []func(map[string]any){
		func(v map[string]any) { v["execute"] = true },
		func(v map[string]any) { v["observation"] = "current-forever" },
		func(v map[string]any) { v["profile"] = "unreviewed-authority" },
		func(v map[string]any) {
			v["properties"] = map[string]any{"{urn:example}label": map[string]any{"execute": true}}
		},
		func(v map[string]any) { delete(v, "entry") },
	} {
		var mutated map[string]any
		_ = json.Unmarshal(data, &mutated)
		change(mutated)
		if validator.Validate(mutated) == nil {
			t.Fatal("property contract admits hidden authority,false observation or malformed content")
		}
	}
}
