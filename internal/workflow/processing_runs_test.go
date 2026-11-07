package workflow

import (
	"errors"
	"strings"
	"testing"

	"github.com/ctlplne/freightctl/internal/store"
)

func TestProcessingWorkflowScopedEntryKeepsLegacyRootRequirement(t *testing.T) {
	tx := &store.Transaction{Root: "/processor"}
	for _, schema := range []int{1, 2} {
		if !errors.Is(workflowDefinitionScope(tx, Definition{Schema: schema}), store.ErrForbidden) {
			t.Fatal("processing entry opened legacy workflow root authority")
		}
	}
	if err := workflowDefinitionScope(tx, processingWorkflow(t)); err != nil {
		t.Fatal("explicit processing contract required root", err)
	}
}

func TestProcessingWorkflowHeldOutputCannotBecomeDeliveryOrReleasedSuccess(t *testing.T) {
	r := &store.WorkflowRun{State: "running"}
	p := &ProcessingObservation{ID: "11111111-1111-4111-8111-111111111111", Hash: strings.Repeat("a", 64), State: "completed", Revision: 3, Attempts: 1, FileID: "22222222-2222-4222-8222-222222222222"}
	v, state, reason, err := processingSnapshotResult(r, p)
	if err != nil || state != "attention" || reason != "output_held" || len(v.Steps) != 0 {
		t.Fatal("held generated output became a delivery or workflow success", err)
	}
	p.Released = true
	_, state, reason, err = processingSnapshotResult(r, p)
	if err != nil || state != "succeeded" || reason != "transformed_output_released" {
		t.Fatal("fresh separate release did not finish the processing task", err)
	}
	r.State = "cancelled"
	_, state, reason, err = processingSnapshotResult(r, p)
	if err != nil || state != "cancelled" || reason != "operator_cancelled" {
		t.Fatal("historical output undid cancellation", err)
	}
	p.FileID = ""
	if _, _, _, err = processingSnapshotResult(r, p); err == nil {
		t.Fatal("completion without immutable output accepted")
	}
}

func TestProcessingWorkflowDispatchPinsExactIntentAndHistoricalRevision(t *testing.T) {
	b := store.WorkflowProcessing{RunID: "11111111-1111-4111-8111-111111111111", ProjectionID: "22222222-2222-4222-8222-222222222222", Hash: strings.Repeat("a", 64)}
	d := Dispatch{RunID: b.RunID, StepID: "project", ProjectionID: b.ProjectionID, ProjectionHash: b.Hash, ProjectionRevision: 1}
	if err := validateProcessingDispatch(d, b, "project"); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Dispatch){func(d *Dispatch) { d.ProjectionHash = strings.Repeat("b", 64) }, func(d *Dispatch) { d.ProjectionID = b.RunID }, func(d *Dispatch) { d.StepID = "send" }, func(d *Dispatch) { d.DeliveryID = b.RunID }, func(d *Dispatch) { d.ProjectionRevision = 0 }} {
		copy := d
		mutate(&copy)
		if validateProcessingDispatch(copy, b, "project") == nil {
			t.Fatal("replayed key could select another effect or lose its original attempt")
		}
	}
}
