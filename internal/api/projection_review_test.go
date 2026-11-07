package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/ctlplne/freightctl/internal/checks"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/google/jsonschema-go/jsonschema"
)

func TestProjectionPreviewRejectsInjectedAuthorityBeforeService(t *testing.T) {
	s := New(&custody.Service{}, nil)
	path := "/v1/tenants/00000000-0000-0000-0000-000000000001/partners/00000000-0000-0000-0000-000000000002/checks/00000000-0000-0000-0000-000000000003/projection-preview"
	bodies := []string{
		`{"reason":"a","reason":"b"}`, `{"definition":{},"Definition":{}}`,
		`{"source_policy":{"id":"invented"}}`, `{"reason":"Review explicit rules","definition":null}`,
		`null`, `[]`, `{} {}`, strings.Repeat(" ", 33<<10),
	}
	// Otherwise-valid requests must be refused for their injected fields. A
	// missing reason/definition must not accidentally make this test pass.
	for _, inject := range []func(map[string]any){
		func(r map[string]any) { r["approved"] = true },
		func(r map[string]any) { r["force_clean"] = true },
		func(r map[string]any) { r["signature_mode"] = "reuse_exact" },
		func(r map[string]any) { r["source_policy"] = map[string]any{"id": "untrusted-override"} },
		func(r map[string]any) {
			r["definition"].(map[string]any)["run_shell"] = "SYNTHETIC_PAYLOAD_INSTRUCTION"
		},
		func(r map[string]any) {
			r["definition"].(map[string]any)["columns"].([]any)[0].(map[string]any)["execute"] = true
		},
	} {
		r := map[string]any{"reason": "Review an exact private source", "target_path": "/output.json", "definition": map[string]any{"schema_version": 1, "kind": "record_projection", "source_policy_hash": strings.Repeat("a", 64), "output_kind": "json_records", "columns": []any{map[string]any{"source": "x", "target": "x"}}}}
		inject(r)
		wire, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		bodies = append(bodies, string(wire))
	}
	for _, body := range bodies {
		req := httptest.NewRequest(http.MethodPost, "https://freightctl.invalid"+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+strings.Repeat("0", 64))
		resp := httptest.NewRecorder()
		s.ServeHTTP(resp, req)
		if resp.Code != http.StatusBadRequest {
			t.Fatalf("untrusted control body reached service: status %d", resp.Code)
		}
	}
}

func TestProjectionPreviewOpenAPIRequiresDeclarativeRulesAndExactTypedResponse(t *testing.T) {
	file, err := os.ReadFile("../../docs/api/record-projection.openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Components struct {
			Schemas map[string]json.RawMessage `json:"schemas"`
		} `json:"components"`
	}
	if json.Unmarshal(file, &document) != nil {
		t.Fatal("projection OpenAPI missing")
	}
	var schema jsonschema.Schema
	if json.Unmarshal(document.Components.Schemas["ProjectionOptions"], &schema) != nil {
		t.Fatal("request schema missing")
	}
	resolved, err := schema.Resolve(nil)
	if err != nil {
		t.Fatal(err)
	}
	valid := `{"reason":"Review exact deterministic rules","definition":{"schema_version":1,"kind":"record_projection","source_policy_hash":"` + strings.Repeat("a", 64) + `","output_kind":"json_records","columns":[{"source":"account","target":"account"}]}}`
	var original map[string]any
	if json.Unmarshal([]byte(valid), &original) != nil || resolved.Validate(original) != nil {
		t.Fatal("minimal explicit mapping refused")
	}
	for _, mutate := range []func(map[string]any){
		func(r map[string]any) { r["execute"] = true },
		func(r map[string]any) { delete(r, "definition") },
		func(r map[string]any) { r["definition"] = nil },
		func(r map[string]any) { r["definition"].(map[string]any)["columns"] = nil },
		func(r map[string]any) { r["definition"].(map[string]any)["columns"] = []any{} },
		func(r map[string]any) { r["definition"].(map[string]any)["engine"] = "unreviewed-engine" },
		func(r map[string]any) { r["definition"].(map[string]any)["output_kind"] = "shell" },
		func(r map[string]any) {
			r["definition"].(map[string]any)["columns"].([]any)[0].(map[string]any)["missing"] = "guess"
		},
		func(r map[string]any) {
			r["definition"].(map[string]any)["columns"].([]any)[0].(map[string]any)["null"] = "guess"
		},
		func(r map[string]any) {
			r["definition"].(map[string]any)["columns"].([]any)[0].(map[string]any)["conversion"] = "evaluate_code"
		},
	} {
		var r map[string]any
		_ = json.Unmarshal([]byte(valid), &r)
		mutate(r)
		if resolved.Validate(r) == nil {
			t.Fatal("schema accepted ambiguous or executable input")
		}
	}
	// Every reviewed source/check/namespace/policy/protection binding must stay
	// represented when the Go contract changes; do not silently publish a subset.
	actual, err := jsonschema.For[checks.ProjectionPreview](nil)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(actual)
	if err != nil {
		t.Fatal(err)
	}
	var got, want any
	if json.Unmarshal(wire, &want) != nil || json.Unmarshal(document.Components.Schemas["ProjectionPreview"], &got) != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("published response lost or changed a typed review binding")
	}
}

func TestProjectionDerivedOpenAPIPreservesEveryFrozenNamespaceBinding(t *testing.T) {
	raw, err := os.ReadFile("../../docs/api/record-projection.openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Components struct {
			Schemas map[string]json.RawMessage `json:"schemas"`
		} `json:"components"`
	}
	if json.Unmarshal(raw, &document) != nil {
		t.Fatal("projection schema unavailable")
	}
	typed, err := jsonschema.For[store.PathCommand](nil)
	if err != nil {
		t.Fatal(err)
	}
	walk := func(root *jsonschema.Schema, path ...string) *jsonschema.Schema {
		for _, field := range path {
			if root == nil || root.Properties[field] == nil {
				t.Fatalf("frozen schema path missing: %s", field)
			}
			root = root.Properties[field]
		}
		return root
	}
	// Derived input schemas also carry deliberate constraints beyond plain Go
	// reflection. Keep those constraints;verify every command field at all six
	// review sites,as well as the exact complete preview comparison above.
	sites := 0
	for _, name := range []string{"ProjectionPreview", "ProjectionDefinition", "ProjectionPlan"} {
		var root jsonschema.Schema
		if json.Unmarshal(document.Components.Schemas[name], &root) != nil {
			t.Fatal("derived schema unavailable", name)
		}
		context := &root
		if name != "ProjectionPlan" {
			context = walk(context, "plan")
		}
		context = walk(context, "context")
		for _, command := range []*jsonschema.Schema{walk(context, "source", "check", "binding", "target"), walk(context, "target", "command")} {
			sites++
			if len(command.Properties) != len(typed.Properties) {
				t.Fatal("frozen command field coverage differs", name)
			}
			for field := range typed.Properties {
				if command.Properties[field] == nil {
					t.Fatal("frozen command field missing", name, field)
				}
			}
			validator, err := command.Resolve(nil)
			if err != nil {
				t.Fatal(err)
			}
			value := map[string]any{"operation": "publish", "path": "/reviewed.csv", "expected_revision": float64(1), "expected_file_id": "00000041-1111-4111-8111-111111111111", "replace": true}
			if validator.Validate(value) != nil {
				t.Fatal("typed old-file review guard disappeared", name)
			}
			for _, invalid := range []any{nil, 42.0, true, []any{}, map[string]any{}} {
				value["expected_file_id"] = invalid
				if validator.Validate(value) == nil {
					t.Fatal("old-file review guard lost its exact string type", name)
				}
			}
			delete(value, "expected_file_id")
			if validator.Validate(value) != nil {
				t.Fatal("historical absent optional guard no longer represents the typed contract", name)
			}
			value["execute"] = true
			if validator.Validate(value) == nil {
				t.Fatal("schema admitted injected execution authority", name)
			}
		}
	}
	if sites != 6 {
		t.Fatal("not all frozen namespace review sites were checked")
	}
}
