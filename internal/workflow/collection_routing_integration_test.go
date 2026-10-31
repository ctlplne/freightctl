//go:build integration

package workflow

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

func revisedCollectionRoutingWorkflow(t *testing.T, f *fixture, original *store.Configuration, d Definition) *store.Configuration {
	t.Helper()
	r, err := f.s.Draft(f.ctx, f.scope, "routing-revision-draft", DraftRequest{ID: original.ID, ExpectedVersion: original.Version, Definition: d})
	if err != nil {
		t.Fatal(err)
	}
	var w store.Configuration
	if json.Unmarshal(r.Resource, &w) != nil {
		t.Fatal("routing revision draft")
	}
	r, err = f.s.Decide(f.ctx, f.scope, w.ID, w.Version, "routing-revision-approve", "approve", Decision{Hash: w.Hash, Revision: w.Revision})
	if err != nil || json.Unmarshal(r.Resource, &w) != nil {
		t.Fatal("routing revision approval", err)
	}
	return &w
}

func capturedRoutingAuthorizationFixture(t *testing.T) (*fixture, *CollectionView, CollectionRoutingSelection, Reference) {
	t.Helper()
	f := setup(t)
	d := f.definition()
	source := collectionTestSource()
	source.Directory = "/"
	source.Connection = Reference{ID: f.connection.ID, Version: f.connection.Version, Hash: f.connection.Hash}
	d.Schema, d.Source = 2, &source
	d.Program = &Program{Nodes: []ProgramNode{{Kind: "deliver", Step: d.Steps[0].ID}}}
	original := f.approved(t, d)
	originalRef := Reference{ID: original.ID, Version: original.Version, Hash: original.Hash}
	job, owner, inputs := sealedCollectionFixture(t, f, CollectionSelection{Workflow: originalRef, Timeout: 120, Authority: 1}, "routing-guard-batch", "abc", "def")
	captured := finishSealedCollection(t, f, job, owner, inputs)
	d.Program = &Program{Nodes: []ProgramNode{{Kind: "deliver", Step: d.Steps[1].ID}}}
	w := revisedCollectionRoutingWorkflow(t, f, original, d)
	return f, captured, CollectionRoutingSelection{Collection: Decision{Hash: job.Hash, Revision: captured.Job.Revision}, Workflow: Reference{ID: w.ID, Version: w.Version, Hash: w.Hash}, Authority: 1}, originalRef
}

func proposeRoutingAuthorization(t *testing.T, f *fixture, job string, x CollectionRoutingSelection, key string) CollectionRoutingAction {
	t.Helper()
	p, err := f.s.PreviewCollectionRouting(f.ctx, f.scope, job, x)
	if err != nil {
		t.Fatal(err)
	}
	r, err := f.s.ProposeCollectionRouting(f.ctx, f.scope, job, key, CollectionRoutingProposal{Selection: x, Hash: p.Hash})
	if err != nil {
		t.Fatal(err)
	}
	var a CollectionRoutingAction
	if json.Unmarshal(r.Resource, &a) != nil || a.State != "proposed" {
		t.Fatal("routing proposal receipt")
	}
	return a
}

func decideRoutingAuthorization(t *testing.T, f *fixture, a CollectionRoutingAction, action, key string) CollectionRoutingAction {
	t.Helper()
	r, err := f.s.DecideCollectionRouting(f.ctx, f.scope, a.JobID, a.ID, key, action, Decision{Hash: a.Hash, Revision: a.Revision})
	if err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(r.Resource, &a) != nil {
		t.Fatal("routing decision receipt")
	}
	return a
}

func TestCapturedRoutingDatabaseRejectsForgedBindingsAndRunWithoutApprovalLineage(t *testing.T) {
	f, captured, x, _ := capturedRoutingAuthorizationFixture(t)
	job := captured.Job.ID
	p, err := f.s.PreviewCollectionRouting(f.ctx, f.scope, job, x)
	if err != nil {
		t.Fatal(err)
	}
	before := routingPreviewCounts(t, f)
	forged := p.Definition
	forged.Inputs = append([]CollectionRoutingBinding(nil), p.Definition.Inputs...)
	forged.Inputs[0].PlanHash = strings.Repeat("f", 64)
	raw, hash, err := digest(forged)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.s.collectionBegin(f.ctx, f.scope, "workflow_execute", "read", "write", "list")
	if err != nil {
		t.Fatal(err)
	}
	err = tx.SaveCollectionRouting(f.ctx, &store.CollectionRouting{ID: secure.NewID(), JobID: job, Version: 1, Definition: raw, Hash: hash, State: "proposed", Revision: 1}, 0)
	tx.Tx.Rollback(f.ctx)
	collectionSQLRefusal(t, err)
	if after := routingPreviewCounts(t, f); after != before {
		t.Fatal("forged authorization retained effects", before, after)
	}
	a := proposeRoutingAuthorization(t, f, job, x, "legitimate-routing-propose")
	a = decideRoutingAuthorization(t, f, a, "approve", "legitimate-routing-approve")
	tx, err = f.s.collectionBegin(f.ctx, f.scope, "workflow_execute", "read", "write", "list")
	if err != nil {
		t.Fatal(err)
	}
	_, w, err := approved(f.ctx, tx, x.Workflow)
	if err != nil {
		tx.Tx.Rollback(f.ctx)
		t.Fatal(err)
	}
	file, err := tx.File(f.ctx, *captured.Inputs[0].FileID)
	if err != nil {
		tx.Tx.Rollback(f.ctx)
		t.Fatal(err)
	}
	// This is the ordinary internal caller with no routing reference. SQL must
	// refuse it even though the target workflow and compiled plan are valid.
	_, err = f.s.stageRun(f.ctx, tx, RunRequest{Workflow: x.Workflow, FileID: file.ID}, w, file, p.Definition.StorageID)
	tx.Tx.Rollback(f.ctx)
	collectionSQLRefusal(t, err)
	if _, err = f.s.RefreshCollection(f.ctx, f.scope, job, "legitimate-routing-admit", x.Collection); err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.PreviewCollectionRouting(f.ctx, f.scope, job, x); !errors.Is(err, store.ErrState) {
		t.Fatal("already assigned input was reinterpreted", err)
	}
	view, err := f.s.CollectionStatus(f.ctx, f.scope, job)
	if err != nil || !reflect.DeepEqual(view.Job, captured.Job) {
		t.Fatal("recovery rewrote original capture", err)
	}
	for _, input := range view.Inputs {
		if input.RunID == nil {
			t.Fatal("authorized input was not queued")
		}
		r, err := f.s.Status(f.ctx, f.scope, *input.RunID)
		if err != nil || r.Run.RoutingID != a.ID {
			t.Fatal("run did not retain exact authorization", err)
		}
	}
}

func TestCapturedRoutingRevocationBlocksFallbackUntilAnotherExactApproval(t *testing.T) {
	f, captured, x, original := capturedRoutingAuthorizationFixture(t)
	job := captured.Job.ID
	a := proposeRoutingAuthorization(t, f, job, x, "routing-to-revoke")
	a = decideRoutingAuthorization(t, f, a, "approve", "approve-routing-to-revoke")
	a = decideRoutingAuthorization(t, f, a, "revoke", "revoke-routing")
	before := routingPreviewCounts(t, f)
	if _, err := f.s.RefreshCollection(f.ctx, f.scope, job, "revoked-cannot-fall-back", x.Collection); !errors.Is(err, store.ErrCollection) {
		t.Fatal("revocation silently restored old recipient rules", err)
	}
	if after := routingPreviewCounts(t, f); after != before {
		t.Fatal("revoked authorization changed admission state", before, after)
	}
	// Even choosing the original revision again requires a new explicit
	// authorization tied to the exact intervening revocation.
	x.Workflow = original
	p, err := f.s.PreviewCollectionRouting(f.ctx, f.scope, job, x)
	if err != nil || p.Definition.Previous == nil || p.Definition.Previous.ID != a.ID || p.Definition.Previous.Revision != a.Revision {
		t.Fatal("replacement lost the intervening revocation", p, err)
	}
	b := proposeRoutingAuthorization(t, f, job, x, "propose-explicit-restoration")
	if _, err = f.s.RefreshCollection(f.ctx, f.scope, job, "proposal-cannot-undo-revocation", x.Collection); !errors.Is(err, store.ErrCollection) {
		t.Fatal("a pending replacement restored execution", err)
	}
	b = decideRoutingAuthorization(t, f, b, "approve", "approve-explicit-restoration")
	if _, err = f.s.RefreshCollection(f.ctx, f.scope, job, "admit-explicit-restoration", x.Collection); err != nil {
		t.Fatal(err)
	}
	view, err := f.s.CollectionStatus(f.ctx, f.scope, job)
	if err != nil || !reflect.DeepEqual(view.Job, captured.Job) {
		t.Fatal("restoration rewrote original capture", err)
	}
	for _, input := range view.Inputs {
		if input.RunID == nil {
			t.Fatal("explicit restoration has no run")
		}
		r, err := f.s.Status(f.ctx, f.scope, *input.RunID)
		if err != nil || r.Run.RoutingID != b.ID || r.Run.WorkflowVersion != original.Version {
			t.Fatal("restored rules did not retain their new approval lineage", err)
		}
	}
}

func TestCapturedRoutingAuthorizationRepairsBlockedBatchWithoutChangingItsJob(t *testing.T) {
	f := setup(t)
	source := collectionTestSource()
	source.Directory = "/"
	source.Connection = Reference{ID: f.connection.ID, Version: f.connection.Version, Hash: f.connection.Hash}
	d := f.definition()
	d.Schema, d.Source = 2, &source
	missing := "absent.csv"
	d.Program = &Program{Nodes: []ProgramNode{{Kind: "if", When: &Condition{Op: "eq", Field: "source.name", Text: &missing}, Then: []ProgramNode{{Kind: "deliver", Step: d.Steps[0].ID}}}}}
	original := f.approved(t, d)
	oldRef := Reference{ID: original.ID, Version: original.Version, Hash: original.Hash}
	job, owner, inputs := sealedCollectionFixture(t, f, CollectionSelection{Workflow: oldRef, Timeout: 120, Authority: 1}, "blocked-routing-authorization", "abc", "def")
	captured := finishSealedCollection(t, f, job, owner, inputs)
	if _, err := f.s.RefreshCollection(f.ctx, f.scope, job.ID, "blocked-original-rules", Decision{Hash: job.Hash, Revision: captured.Job.Revision}); !errors.Is(err, ErrRouting) {
		t.Fatal("fixture did not expose the original undecidable batch", err)
	}
	name := "one.csv"
	d.Program = &Program{Nodes: []ProgramNode{{Kind: "if", When: &Condition{Op: "eq", Field: "source.name", Text: &name}, Then: []ProgramNode{{Kind: "deliver", Step: d.Steps[1].ID}}, Else: []ProgramNode{{Kind: "keep_local", Reason: "unmatched_source_file"}}}}}
	w := revisedCollectionRoutingWorkflow(t, f, original, d)
	x := CollectionRoutingSelection{Collection: Decision{Hash: job.Hash, Revision: captured.Job.Revision}, Workflow: Reference{ID: w.ID, Version: w.Version, Hash: w.Hash}, Authority: 1}
	before := routingPreviewCounts(t, f)
	p, err := f.s.PreviewCollectionRouting(f.ctx, f.scope, job.ID, x)
	if err != nil || p.ExternalContact || !p.ApprovalRequired || len(p.Definition.Inputs) != 2 || p.Definition.OriginalWorkflow != oldRef || p.Definition.Workflow != x.Workflow {
		t.Fatal("cannot review exact captured-input routing without a new collection", p, err)
	}
	if after := routingPreviewCounts(t, f); after != before {
		t.Fatal("routing preview changed execution state", before, after)
	}
	proposed, err := f.s.ProposeCollectionRouting(f.ctx, f.scope, job.ID, "routing-propose", CollectionRoutingProposal{Selection: x, Hash: p.Hash})
	if err != nil {
		t.Fatal(err)
	}
	var action CollectionRoutingAction
	if json.Unmarshal(proposed.Resource, &action) != nil || action.State != "proposed" {
		t.Fatal("routing proposal receipt")
	}
	if _, err = f.s.RefreshCollection(f.ctx, f.scope, job.ID, "proposal-cannot-route", x.Collection); !errors.Is(err, ErrRouting) {
		t.Fatal("unapproved proposal changed the effective rules", err)
	}
	if _, err = f.s.DecideCollectionRouting(f.ctx, f.scope, job.ID, action.ID, "routing-authorize", "approve", Decision{Hash: action.Hash, Revision: action.Revision}); err != nil {
		t.Fatal("cannot approve the exact captured routing choice", err)
	}
	if _, err = f.s.RefreshCollection(f.ctx, f.scope, job.ID, "route-approved-revision", x.Collection); err != nil {
		t.Fatal("ordinary batch admission ignored the approved captured routing choice", err)
	}
	after, err := f.s.CollectionStatus(f.ctx, f.scope, job.ID)
	if err != nil || !reflect.DeepEqual(after.Job, captured.Job) {
		t.Fatal("routing recovery rewrote the original job", err)
	}
	for _, input := range after.Inputs {
		if input.RunID == nil {
			t.Fatal("approved input has no disposition", input.ID)
		}
		status, err := f.s.Status(f.ctx, f.scope, *input.RunID)
		if err != nil || status.Run.WorkflowVersion != w.Version || status.Run.WorkflowHash != w.Hash || status.Run.RoutingID != action.ID {
			t.Fatal("run lost its exact approved routing-authorization lineage", status, err)
		}
		plan, err := storedExecutionPlan(status.Run)
		if err != nil || plan == nil || plan.Facts.Source == nil || plan.Facts.Source.CollectionID != job.ID || plan.Facts.Source.ManifestHash != *captured.Job.ManifestHash || plan.Facts.Source.Name != input.Name {
			t.Fatal("recovery invented new source facts", plan, err)
		}
		if input.Name == name && (len(status.Steps) != 1 || status.Steps[0].ID != d.Steps[1].ID) || input.Name != name && status.ObservedState != "kept_local" {
			t.Fatal("recovery chose an unreviewed recipient or lost the local outcome", status)
		}
	}
}
