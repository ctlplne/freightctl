package workflow

import (
	"encoding/json"
	"strings"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestProcessingCatalogSeparatesApprovalPolicyAndExecutionFacts(t *testing.T) {
	d, _ := Normalize(processingWorkflow(t))
	wire, hash, _ := digest(d)
	c := &store.Configuration{ID: secure.NewID(), Version: 1, Definition: wire, Hash: hash, State: "approved", Revision: 2, ApprovalAuthority: 7}
	output := &store.Configuration{ID: d.Processing.OutputPolicy.ID, Version: d.Processing.OutputPolicy.Version, Hash: d.Processing.OutputPolicy.Hash, State: "active"}
	row, err := processingCatalogEntry(c, output, 7, true)
	if err != nil {
		t.Fatal(err)
	}
	if row.ID != c.ID || row.Hash != c.Hash || !row.ApprovalCurrent || !row.OutputPolicyCurrent || row.ColumnCount != len(d.Processing.Definition.Columns) {
		t.Fatal("catalog lost exact task facts")
	}
	raw, _ := json.Marshal(row)
	for _, forbidden := range []string{"namespace_root", "reason", "target_path", "staging_slots", "ready_to_execute", "receiver_persistence", "definition\":"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatal("discovery exposed private rules or promised execution")
		}
	}
	withdrawn, err := processingCatalogEntry(c, output, 7, false)
	if err != nil || withdrawn.ApprovalCurrent {
		t.Fatal("withdrawn reviewer remains current", err)
	}
	changed, err := processingCatalogEntry(c, output, 8, true)
	if err != nil || changed.ApprovalCurrent {
		t.Fatal("stale actor approval remains current", err)
	}
	old := *output
	old.State = "output_active"
	registered, err := processingCatalogEntry(c, &old, 7, true)
	if err != nil || !registered.OutputPolicyCurrent || !registered.ApprovalCurrent {
		t.Fatal("selected producer contract lost independent approval observation", err)
	}
	old.State = "output_revoked"
	registered, err = processingCatalogEntry(c, &old, 7, true)
	if err != nil || registered.OutputPolicyCurrent || !registered.ApprovalCurrent {
		t.Fatal("revoked output contract rewrote task approval or remained current", err)
	}
	old = *output
	old.Version++
	changed, err = processingCatalogEntry(c, &old, 7, true)
	if err != nil || changed.OutputPolicyCurrent || !changed.ApprovalCurrent {
		t.Fatal("changed output policy rewrote approval fact", err)
	}
}
func TestProcessingCatalogRefusesCorruptAndOtherWorkflowProfiles(t *testing.T) {
	d, _ := Normalize(processingWorkflow(t))
	wire, hash, _ := digest(d)
	base := store.Configuration{ID: secure.NewID(), Version: 1, Definition: wire, Hash: hash, State: "draft", Revision: 1}
	for _, mutate := range []func(*store.Configuration){func(c *store.Configuration) { c.Hash = strings.Repeat("f", 64) }, func(c *store.Configuration) { c.State = "succeeded" }, func(c *store.Configuration) {
		c.Definition = json.RawMessage(`{"schema_version":1,"name":"legacy","steps":[]}`)
		c.Hash = secure.Digest(c.Definition)
	}} {
		c := base
		mutate(&c)
		if _, err := processingCatalogEntry(&c, nil, 7, true); err == nil {
			t.Fatal("catalog accepted corrupt or unrelated workflow")
		}
	}
}
