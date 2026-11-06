package api

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func TestMCPWorkflowMetadataKeepsCanonicalMeaningAcrossStoredJSONReordering(t *testing.T) {
	d := workflow.Definition{Schema: 1, Name: "private-name-sentinel", Steps: []workflow.Step{{ID: "send", Kind: "sftp.deliver", Connection: workflow.Reference{ID: "55555555-5555-4555-8555-555555555555", Version: 1, Hash: strings.Repeat("a", 64)}, Filename: "private-filename-sentinel.dat"}}}
	definition, err := workflow.Normalize(d)
	if err != nil {
		t.Fatal(err)
	}
	canonical, _ := json.Marshal(definition)
	hash := secure.Digest(canonical)
	// PostgreSQL jsonb can reorder/space object keys. This must retain the
	// normalized domain hash and original receipt instead of hashing raw JSON.
	var stored map[string]any
	if json.Unmarshal(canonical, &stored) != nil {
		t.Fatal("fixture")
	}
	reordered, _ := json.MarshalIndent(stored, "", "  ")
	if bytes.Equal(canonical, reordered) {
		t.Fatal("fixture did not change JSON representation")
	}
	c := store.Configuration{ID: "66666666-6666-4666-8666-666666666666", Version: 1, Revision: 1, Definition: reordered, Hash: hash, State: "draft"}
	raw, _ := json.Marshal(c)
	proposal, err := mcpWorkflowProposal(&workflow.Result{Resource: raw, Replayed: true})
	if err != nil || proposal["definition_hash"] != hash || proposal["accepted_state"] != "draft" || proposal["current_state"] != "not-checked" || proposal["approval_required"] != true || proposal["replayed"] != true {
		t.Fatal("stored original draft meaning lost", err)
	}
	review, err := mcpWorkflowReview(&workflow.Preview{Definition: definition, Hash: hash, ApprovalRequired: true})
	if err != nil || review["durable_effects"] != "none" || review["storage_verification"] != "not-checked" {
		t.Fatal("validation claimed execution/storage", err)
	}
	for _, value := range []map[string]any{proposal, review} {
		if _, ok := value["definition"]; ok {
			t.Fatal("raw definition returned")
		}
		if _, ok := value["effects"]; ok {
			t.Fatal("raw effects returned")
		}
		wire, _ := json.Marshal(value)
		for _, hidden := range []string{"private-name-sentinel", "private-filename-sentinel", d.Steps[0].Connection.ID, "credentials"} {
			if bytes.Contains(wire, []byte(hidden)) {
				t.Fatal("metadata projection exposed private definition", hidden)
			}
		}
	}
	c.State = "approved"
	raw, _ = json.Marshal(c)
	if _, err = mcpWorkflowProposal(&workflow.Result{Resource: raw}); err == nil {
		t.Fatal("non-draft accepted as original proposal")
	}
	if _, err = mcpWorkflowReview(&workflow.Preview{Definition: definition, Hash: hash, ApprovalRequired: true, ExternalContact: true}); err == nil {
		t.Fatal("external effect accepted as validation")
	}
}
