package workflow

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/ctlplne/freightctl/internal/store"
)

// This serialized fixture came from a real PostgreSQL execution. The browser
// independently normalizes and compiles it; keep Go's wire contract in agreement.
func TestCollectedHandoffBrowserFixturePreservesExactGoFingerprintsAndPlans(t *testing.T) {
	data, err := os.ReadFile("../../web/tests/fixtures/collection-handoffs.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Original     *CollectionView           `json:"original"`
		View         *CollectionView           `json:"view"`
		Preview      *CollectionHandoffPreview `json:"preview"`
		Metadata     *CollectionHandoffView    `json:"metadata"`
		OriginalRun  *RunView                  `json:"original_run"`
		SuccessorRun *RunView                  `json:"successor_run"`
		Completed    *store.CollectionHandoff  `json:"completed"`
	}
	if json.Unmarshal(data, &f) != nil || f.Original == nil || f.View == nil || f.Preview == nil || f.Metadata == nil || f.OriginalRun == nil || f.SuccessorRun == nil || f.Completed == nil {
		t.Fatal("handoff browser fixture shape")
	}
	_, hash, err := digest(f.Preview.Definition)
	if err != nil || hash != f.Preview.Hash || hash != f.Completed.Hash || f.Completed.State != "completed" || f.Preview.ExternalContact || !f.Preview.ApprovalRequired || f.Metadata.Current || f.Metadata.Reason != "completed" {
		t.Fatal("Go handoff wire fingerprint or authority changed", err)
	}
	for _, c := range []*store.Configuration{f.Preview.SourceWorkflow, f.Preview.Workflow} {
		var d Definition
		if c == nil || Decode(c.Definition, &d) != nil {
			t.Fatal("workflow context")
		}
		d, err = Normalize(d)
		if err != nil {
			t.Fatal(err)
		}
		_, hash, err := digest(d)
		if err != nil || hash != c.Hash {
			t.Fatal("workflow fingerprint", err)
		}
		plan, err := CompileProgram(d, f.Preview.Definition.Plan.Facts)
		if err != nil {
			t.Fatal(err)
		}
		if c.Version == f.Preview.SourceWorkflow.Version && !reflect.DeepEqual(plan, f.Preview.SourcePlan) || c.Version == f.Preview.Workflow.Version && !reflect.DeepEqual(*plan, f.Preview.Definition.Plan) {
			t.Fatal("Go compiler disagrees with serialized review")
		}
	}
	old, err := storedExecutionPlan(f.OriginalRun.Run)
	if err != nil || !reflect.DeepEqual(old, f.Preview.SourcePlan) {
		t.Fatal("original plan changed", err)
	}
	next, err := storedExecutionPlan(f.SuccessorRun.Run)
	if err != nil || next == nil || !reflect.DeepEqual(*next, f.Preview.Definition.Plan) || !reflect.DeepEqual(next.Facts, old.Facts) {
		t.Fatal("successor facts or plan changed", err)
	}
	if !reflect.DeepEqual(f.Original.Job, f.View.Job) || !reflect.DeepEqual(f.Original.Inputs, f.View.Inputs) || len(f.View.Replacements) != 1 || f.View.Replacements[0].OriginalRunID != f.OriginalRun.Run.ID || f.View.Replacements[0].CurrentRunID != f.SuccessorRun.Run.ID {
		t.Fatal("original assignment or successor navigation changed")
	}
}
