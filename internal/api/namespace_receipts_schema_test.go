package api

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/ctlplne/freightctl/internal/store"
	"github.com/google/jsonschema-go/jsonschema"
)

func TestNamespaceReceiptSchemaRetainsOriginalResultAndRefusesFalseAuthority(t *testing.T) {
	raw, err := os.ReadFile("../../docs/api/namespace-receipts.openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Components struct {
			Schemas map[string]json.RawMessage `json:"schemas"`
		} `json:"components"`
	}
	if json.Unmarshal(raw, &document) != nil {
		t.Fatal("receipt contract unavailable")
	}
	typed, err := jsonschema.For[store.PathCommandReceipt](nil)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(typed)
	if err != nil {
		t.Fatal(err)
	}
	var expected, actual map[string]any
	if json.Unmarshal(wire, &expected) != nil || json.Unmarshal(document.Components.Schemas["PathCommandReceipt"], &actual) != nil {
		t.Fatal("typed receipt binding unavailable")
	}
	fields := expected["properties"].(map[string]any)
	fields["profile"].(map[string]any)["const"] = "namespace-command-receipt-v1"
	fields["observation"].(map[string]any)["const"] = "original-commit-not-current-state"
	fields["request_key"].(map[string]any)["pattern"] = "^[A-Za-z0-9._:-]{1,128}$"
	fields["request_hash"].(map[string]any)["pattern"] = "^[0-9a-f]{64}$"
	fields["completed_event_id"].(map[string]any)["pattern"] = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
	fields["result"].(map[string]any)["properties"].(map[string]any)["replayed"].(map[string]any)["const"] = false
	if !reflect.DeepEqual(actual, expected) {
		t.Fatal("receipt contract lost typed fields or historical-only constraints")
	}
	request, err := jsonschema.For[store.PathCommand](nil)
	if err != nil {
		t.Fatal(err)
	}
	wire, err = json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	expected, actual = nil, nil
	if json.Unmarshal(wire, &expected) != nil || json.Unmarshal(document.Components.Schemas["OriginalPathCommand"], &actual) != nil || !reflect.DeepEqual(actual, expected) {
		t.Fatal("original command selection lost its exact typed contract")
	}
	var schema jsonschema.Schema
	if json.Unmarshal(document.Components.Schemas["PathCommandReceipt"], &schema) != nil {
		t.Fatal("receipt schema unavailable")
	}
	validator, err := schema.Resolve(nil)
	if err != nil {
		t.Fatal(err)
	}
	value := store.PathCommandReceipt{Profile: "namespace-command-receipt-v1", Observation: "original-commit-not-current-state", RequestKey: "original", RequestHash: "b33bdcb548951183fb336740d085034be58a5aba2470b168a25f66d29cb2dad7", CompletedEventID: "10000000-1111-4111-8111-111111111111", Result: store.PathResult{Entry: store.PathEntry{Path: "/removed", Deleted: true}, Changed: 1}}
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var valid map[string]any
	if json.Unmarshal(data, &valid) != nil || validator.Validate(valid) != nil {
		t.Fatal("historical private receipt refused")
	}
	for _, change := range []func(map[string]any){
		func(v map[string]any) { v["observation"] = "current-namespace" },
		func(v map[string]any) { v["profile"] = "execute-command" },
		func(v map[string]any) { v["execute"] = true },
		func(v map[string]any) { v["request_hash"] = "unknown" },
		func(v map[string]any) { v["completed_event_id"] = "not-an-event" },
		func(v map[string]any) { v["result"].(map[string]any)["replayed"] = true },
		func(v map[string]any) { v["result"].(map[string]any)["approved"] = true },
		func(v map[string]any) { delete(v, "completed_event_id") },
	} {
		var bad map[string]any
		_ = json.Unmarshal(data, &bad)
		change(bad)
		if validator.Validate(bad) == nil {
			t.Fatal("receipt schema admits false state,authority,replay or hidden data")
		}
	}
}
