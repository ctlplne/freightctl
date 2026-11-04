package workflow

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/ctlplne/freightctl/internal/store"
)

// A JSONB receipt may reorder execution_plan object keys. Validate the full
// typed plan against its recorded hash and source before comparing every run
// field. Never omit the plan or compare only the run identity.
func canonicalWorkflowRunReceipt(run store.WorkflowRun) (store.WorkflowRun, error) {
	plan, err := storedExecutionPlan(&run)
	if err != nil {
		return store.WorkflowRun{}, err
	}
	if plan != nil {
		run.Plan, _, err = digest(plan)
	}
	return run, err
}

func TestWorkflowRunReceiptComparisonPreservesEveryFieldAndExactPlan(t *testing.T) {
	plan, err := CompileProgram(routingDefinition(t), routingTestFacts())
	if err != nil {
		t.Fatal(err)
	}
	encoded, hash, err := digest(plan)
	if err != nil {
		t.Fatal(err)
	}
	original := store.WorkflowRun{ID: "00000000-0000-0000-0000-000000000011", WorkflowID: "00000000-0000-0000-0000-000000000012", WorkflowVersion: 1, WorkflowHash: strings.Repeat("c", 64), FileID: plan.Facts.File.ID, Source: plan.Facts.File, StorageID: strings.Repeat("d", 64), Root: "/", Authority: 1, State: "queued", Reason: "awaiting_worker", Revision: 1, Plan: encoded, PlanHash: hash}
	var object map[string]any
	if err = json.Unmarshal(encoded, &object); err != nil {
		t.Fatal(err)
	}
	reordered, err := json.MarshalIndent(object, "", " ")
	if err != nil || bytes.Equal(encoded, reordered) {
		t.Fatal("fixture did not change JSON object representation", err)
	}
	replay := original
	replay.Plan = reordered
	if reflect.DeepEqual(original, replay) {
		t.Fatal("fixture did not reproduce raw JSON receipt inequality")
	}
	canonical, err := canonicalWorkflowRunReceipt(replay)
	if err != nil || !reflect.DeepEqual(original, canonical) {
		t.Fatal("format-only receipt failed its exact typed/hash comparison", err)
	}
	for name, change := range map[string]func(*store.WorkflowRun){
		"run":              func(r *store.WorkflowRun) { r.ID += "changed" },
		"workflow":         func(r *store.WorkflowRun) { r.WorkflowID += "changed" },
		"workflow-version": func(r *store.WorkflowRun) { r.WorkflowVersion++ },
		"workflow-hash":    func(r *store.WorkflowRun) { r.WorkflowHash = strings.Repeat("e", 64) },
		"file":             func(r *store.WorkflowRun) { r.FileID += "changed" },
		"source":           func(r *store.WorkflowRun) { r.Source.Policy = "changed" },
		"storage":          func(r *store.WorkflowRun) { r.StorageID = strings.Repeat("e", 64) },
		"root":             func(r *store.WorkflowRun) { r.Root = "/other" },
		"authority":        func(r *store.WorkflowRun) { r.Authority++ },
		"state":            func(r *store.WorkflowRun) { r.State = "running" },
		"reason":           func(r *store.WorkflowRun) { r.Reason = "changed" },
		"revision":         func(r *store.WorkflowRun) { r.Revision++ },
		"routing":          func(r *store.WorkflowRun) { r.RoutingID = r.ID },
		"plan-hash":        func(r *store.WorkflowRun) { r.PlanHash = strings.Repeat("e", 64) },
		"missing-plan":     func(r *store.WorkflowRun) { r.Plan = nil },
		"unknown-plan-field": func(r *store.WorkflowRun) {
			r.Plan = append(append([]byte(nil), encoded[:len(encoded)-1]...), []byte(`,"unapproved":true}`)...)
		},
		"changed-plan": func(r *store.WorkflowRun) {
			var altered ExecutionPlan
			if json.Unmarshal(encoded, &altered) != nil {
				t.Fatal("plan fixture")
			}
			altered.Steps[0] = "south"
			r.Plan, r.PlanHash, err = digest(altered)
			if err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			altered := original
			change(&altered)
			canonical, err := canonicalWorkflowRunReceipt(altered)
			if err == nil && reflect.DeepEqual(original, canonical) {
				t.Fatal("changed run or plan accepted as the original receipt")
			}
		})
	}
}
