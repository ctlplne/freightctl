//go:build integration

package workflow

import (
	"errors"
	"reflect"
	"testing"

	"github.com/ctlplne/freightctl/internal/store"
)

func routingPreviewCounts(t *testing.T, f *fixture) [4]int {
	t.Helper()
	var counts [4]int
	if err := f.admin.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM workflow_runs),(SELECT count(*) FROM delivery_intents),(SELECT count(*) FROM events),(SELECT count(*) FROM workflow_receipts)`).Scan(&counts[0], &counts[1], &counts[2], &counts[3]); err != nil {
		t.Fatal(err)
	}
	return counts
}

func TestRoutingPreviewBindsExactApprovedInputWithoutWritingOrOpeningStorage(t *testing.T) {
	f := setup(t)
	d := f.definition()
	d.Schema = 2
	d.Program = &Program{Nodes: []ProgramNode{{Kind: "deliver", Step: d.Steps[1].ID}}}
	w := f.approved(t, d)
	r := RunRequest{Workflow: Reference{ID: w.ID, Version: w.Version, Hash: w.Hash}, FileID: f.file.ID}
	before := routingPreviewCounts(t, f)
	disk := f.s.Custody.Disk
	f.s.Custody.Disk = nil
	defer func() { f.s.Custody.Disk = disk }()
	p, err := f.s.PreviewRun(f.ctx, f.scope, r)
	if err != nil {
		t.Fatal("metadata-only preview requires neither a payload reader nor a receiver", err)
	}
	plan, err := CompileProgram(d, RoutingFacts{File: *f.file})
	if err != nil {
		t.Fatal(err)
	}
	_, hash, _ := digest(plan)
	if p.ExternalContact || p.Workflow != r.Workflow || p.Source != *f.file || len(p.Potential) != 2 || len(p.Selected) != 1 || p.Selected[0].StepID != d.Steps[1].ID || !reflect.DeepEqual(p.Plan, plan) || p.PlanHash != hash {
		t.Fatal("preview changed the selected input, approved recipient or exact plan", p)
	}
	if after := routingPreviewCounts(t, f); after != before {
		t.Fatal("preview created durable execution state", before, after)
	}
	peer, _ := approvalPeer(t, f, "Unrelated routing operator", append([]string{}, store.DefaultPermissions...))
	before = routingPreviewCounts(t, f)
	if _, err := f.s.PreviewRun(f.ctx, peer, r); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("preview revealed another actor's private workflow", err)
	}
	r.Workflow.Hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if _, err := f.s.PreviewRun(f.ctx, f.scope, r); !errors.Is(err, store.ErrRevision) {
		t.Fatal("preview accepted a substituted approval hash", err)
	}
	if after := routingPreviewCounts(t, f); after != before {
		t.Fatal("rejected previews wrote state", before, after)
	}
}

func TestRoutingPreviewUsesOriginalCapturedManifestAndCreatesNoSend(t *testing.T) {
	f := setup(t)
	source := collectionTestSource()
	source.Directory = "/"
	source.Connection = Reference{ID: f.connection.ID, Version: f.connection.Version, Hash: f.connection.Hash}
	d := f.definition()
	d.Schema, d.Source = 2, &source
	name := "one.csv"
	d.Program = &Program{Nodes: []ProgramNode{{Kind: "if", When: &Condition{Op: "eq", Field: "source.name", Text: &name}, Then: []ProgramNode{{Kind: "deliver", Step: d.Steps[1].ID}}, Else: []ProgramNode{{Kind: "keep_local", Reason: "unmatched_source_file"}}}}}
	w := f.approved(t, d)
	ref := Reference{ID: w.ID, Version: w.Version, Hash: w.Hash}
	job, owner, inputs := sealedCollectionFixture(t, f, CollectionSelection{Workflow: ref, Timeout: 120, Authority: 1}, "routing-preview-batch", "abc", "def")
	captured := finishSealedCollection(t, f, job, owner, inputs)
	before := routingPreviewCounts(t, f)
	for index, input := range captured.Inputs {
		p, err := f.s.PreviewRun(f.ctx, f.scope, RunRequest{Workflow: ref, FileID: *input.FileID})
		if err != nil || p.Plan == nil || p.Plan.Facts.Source == nil {
			t.Fatal("captured file has no authoritative routing preview", p, err)
		}
		facts := p.Plan.Facts.Source
		if facts.CollectionID != job.ID || facts.ManifestHash != *captured.Job.ManifestHash || facts.Name != input.Name || facts.Index != index || facts.Count != len(captured.Inputs) {
			t.Fatal("preview invented producer facts", facts, input)
		}
		if input.Name == name && (len(p.Selected) != 1 || p.Selected[0].StepID != d.Steps[1].ID) || input.Name != name && (len(p.Selected) != 0 || p.Plan.LocalReason != "unmatched_source_file") {
			t.Fatal("preview selected an unintended recipient or lost the explicit local disposition", p)
		}
	}
	if after := routingPreviewCounts(t, f); after != before {
		t.Fatal("batch preview admitted downstream work", before, after)
	}
}
