//go:build integration

package workflow

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/delivery"
	"github.com/ctlplne/freightctl/internal/store"
)

func assertCapturedRoutingRuns(t *testing.T, f *fixture, captured *CollectionView, x CollectionRoutingSelection, authorization string, expected int) *CollectionView {
	t.Helper()
	view, err := f.s.CollectionStatus(f.ctx, f.scope, captured.Job.ID)
	if err != nil || !reflect.DeepEqual(view.Job, captured.Job) {
		t.Fatal("admission changed the original capture", err)
	}
	if len(view.Inputs) != len(captured.Inputs) {
		t.Fatal("admission changed the captured input inventory")
	}
	originals := map[string]store.CollectionInput{}
	for _, input := range captured.Inputs {
		originals[input.ID] = input
	}
	seen := map[string]bool{}
	for _, input := range view.Inputs {
		original, ok := originals[input.ID]
		if !ok {
			t.Fatal("admission invented a captured input")
		}
		original.State, original.Revision, original.RunID = input.State, input.Revision, input.RunID
		if !reflect.DeepEqual(input, original) {
			t.Fatal("admission changed the captured input identity, bytes or path")
		}
		if input.RunID == nil {
			if input.State != "accepted" {
				t.Fatal("waiting input lost its accepted bytes", input.State)
			}
			continue
		}
		if input.State != "queued" || seen[*input.RunID] {
			t.Fatal("input has an invalid or duplicate run")
		}
		seen[*input.RunID] = true
		status, err := f.s.Status(f.ctx, f.scope, *input.RunID)
		if err != nil || status.Run.RoutingID != authorization || status.Run.WorkflowID != x.Workflow.ID || status.Run.WorkflowVersion != x.Workflow.Version || status.Run.WorkflowHash != x.Workflow.Hash || status.Run.FileID != *input.FileID {
			t.Fatal("partial admission changed the approved file or routing lineage", err)
		}
		plan, err := storedExecutionPlan(status.Run)
		if err != nil || plan == nil || plan.Facts.Source == nil || plan.Facts.Source.CollectionID != captured.Job.ID || plan.Facts.Source.ManifestHash != *captured.Job.ManifestHash || plan.Facts.Source.Name != input.Name || len(status.Steps) != 1 || status.Steps[0].ID != "second" {
			t.Fatal("admission lost the original producer facts or used the original recipient", err)
		}
	}
	if len(seen) != expected {
		t.Fatal("unexpected number of assigned captured inputs", len(seen), expected)
	}
	return view
}

func TestCapturedRoutingPartialCapacityKeepsExactApprovalAndResumesWithoutDuplicateInputs(t *testing.T) {
	f, captured, x, _ := capturedRoutingAuthorizationFixture(t)
	a := proposeRoutingAuthorization(t, f, captured.Job.ID, x, "capacity-routing-propose")
	a = decideRoutingAuthorization(t, f, a, "approve", "capacity-routing-approve")
	// Fill 127 of the unchanged 128 real delivery slots through ordinary runs.
	// Exactly one of the two captured files can enter on the first refresh.
	w := f.approved(t, f.definition())
	request := RunRequest{Workflow: Reference{ID: w.ID, Version: w.Version, Hash: w.Hash}, FileID: f.file.ID}
	var filler store.WorkflowRun
	for index := 0; index < 63; index++ {
		r, err := f.s.Run(f.ctx, f.scope, fmt.Sprintf("capacity-fill-%d", index), request)
		if err != nil || json.Unmarshal(r.Resource, &filler) != nil {
			t.Fatal("cannot fill the real queue", index, err)
		}
	}
	single := f.definition()
	single.Steps = single.Steps[:1]
	one := f.approved(t, single)
	if _, err := f.s.Run(f.ctx, f.scope, "capacity-fill-last-slot", RunRequest{Workflow: Reference{ID: one.ID, Version: one.Version, Hash: one.Hash}, FileID: f.file.ID}); err != nil {
		t.Fatal(err)
	}
	if count := routingPreviewCounts(t, f)[1]; count != 127 {
		t.Fatal("fixture did not establish partial capacity", count)
	}
	first, err := f.s.RefreshCollection(f.ctx, f.scope, captured.Job.ID, "capacity-admit-first", x.Collection)
	if err != nil {
		t.Fatal(err)
	}
	partial := assertCapturedRoutingRuns(t, f, captured, x, a.ID, 1)
	if count := routingPreviewCounts(t, f)[1]; count != 128 {
		t.Fatal("partial admission exceeded or failed to fill the real bound", count)
	}
	before := routingPreviewCounts(t, f)
	replayed, err := f.s.RefreshCollection(f.ctx, f.scope, captured.Job.ID, "capacity-admit-first", x.Collection)
	if err != nil || !replayed.Replayed || !bytes.Equal(first.Resource, replayed.Resource) || routingPreviewCounts(t, f) != before {
		t.Fatal("response recovery created a second partial admission", err)
	}
	if _, err = f.s.PreviewCollectionRouting(f.ctx, f.scope, captured.Job.ID, x); !errors.Is(err, store.ErrState) {
		t.Fatal("a partially assigned batch could be reinterpreted", err)
	}
	if _, err = f.s.Cancel(f.ctx, f.scope, filler.ID, "capacity-free-two-slots", Decision{Hash: w.Hash, Revision: filler.Revision}); err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.RefreshCollection(f.ctx, f.scope, captured.Job.ID, "capacity-admit-remaining", x.Collection); err != nil {
		t.Fatal(err)
	}
	complete := assertCapturedRoutingRuns(t, f, captured, x, a.ID, 2)
	for index, input := range partial.Inputs {
		if input.RunID != nil && (complete.Inputs[index].RunID == nil || *complete.Inputs[index].RunID != *input.RunID) {
			t.Fatal("resumption replaced the already assigned run")
		}
	}
	before = routingPreviewCounts(t, f)
	if _, err = f.s.RefreshCollection(f.ctx, f.scope, captured.Job.ID, "capacity-no-duplicate-refresh", x.Collection); err != nil || routingPreviewCounts(t, f)[0] != before[0] || routingPreviewCounts(t, f)[1] != before[1] {
		t.Fatal("a completed batch was sent again", err)
	}
}

func TestCapturedRoutingConcurrentAdmissionSerializesAndRevocationFencesEveryQueuedRun(t *testing.T) {
	f, captured, x, _ := capturedRoutingAuthorizationFixture(t)
	a := proposeRoutingAuthorization(t, f, captured.Job.ID, x, "concurrent-routing-propose")
	a = decideRoutingAuthorization(t, f, a, "approve", "concurrent-routing-approve")
	type outcome struct {
		result *Result
		err    error
	}
	start, outcomes := make(chan struct{}), make(chan outcome, 2)
	for index := 0; index < 2; index++ {
		go func(index int) {
			<-start
			r, err := f.s.RefreshCollection(f.ctx, f.scope, captured.Job.ID, fmt.Sprintf("concurrent-admit-%d", index), x.Collection)
			outcomes <- outcome{r, err}
		}(index)
	}
	close(start)
	for index := 0; index < 2; index++ {
		o := <-outcomes
		if o.err != nil || o.result == nil || o.result.Replayed {
			t.Error("concurrent ordinary admission failed to serialize", o.err)
		}
	}
	if t.Failed() {
		return
	}
	view := assertCapturedRoutingRuns(t, f, captured, x, a.ID, 2)
	if counts := routingPreviewCounts(t, f); counts[0] != 2 || counts[1] != 2 {
		t.Fatal("concurrent admission duplicated runs or delivery intents", counts)
	}
	a = decideRoutingAuthorization(t, f, a, "revoke", "revoke-concurrently-admitted-routing")
	before := routingPreviewCounts(t, f)
	for _, input := range view.Inputs {
		status, err := f.s.Status(f.ctx, f.scope, *input.RunID)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err = (&delivery.Service{Custody: f.s.Custody}).Claim(f.ctx, f.scope, status.Steps[0].DeliveryID, secure.NewID()); !errors.Is(err, store.ErrCollection) {
			t.Fatal("revoked routing allowed a queued transfer to start", err)
		}
		var attempts int
		if err = f.admin.QueryRow(f.ctx, `SELECT attempts FROM delivery_intents WHERE delivery_id=$1`, status.Steps[0].DeliveryID).Scan(&attempts); err != nil || attempts != 0 {
			t.Fatal("revocation refusal consumed an attempt", attempts, err)
		}
	}
	if routingPreviewCounts(t, f) != before {
		t.Fatal("revoked queued work changed durable state")
	}
	actual, err := f.s.CollectionRoutingStatus(f.ctx, f.scope, a.JobID, a.ID)
	if err != nil || actual.State != "revoked" || actual.Revision != a.Revision {
		t.Fatal("queued-run inspection restored revoked approval", err)
	}
}
