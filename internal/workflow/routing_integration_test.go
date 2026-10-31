//go:build integration

package workflow

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestBoundedProgramBatchRejectsUndecidableSiblingEvenWhenSendQueueIsFull(t *testing.T) {
	f := setup(t)
	source := collectionTestSource()
	source.Directory = "/"
	source.Connection = Reference{ID: f.connection.ID, Version: f.connection.Version, Hash: f.connection.Hash}
	d := f.definition()
	d.Schema, d.Source = 2, &source
	name := "one.csv"
	// The first file selects a send; the later file has no explicit outcome.
	// A full queue must not hide that missing decision behind a capacity wait.
	d.Program = &Program{Nodes: []ProgramNode{{Kind: "if", When: &Condition{Op: "eq", Field: "source.name", Text: &name}, Then: []ProgramNode{{Kind: "deliver", Step: d.Steps[0].ID}}}}}
	w := f.approved(t, d)
	job, owner, inputs := sealedCollectionFixture(t, f, CollectionSelection{Workflow: Reference{ID: w.ID, Version: w.Version, Hash: w.Hash}, Timeout: 120, Authority: 1}, "undecidable-full-queue-batch", "def", "ghi")
	captured := finishSealedCollection(t, f, job, owner, inputs)
	ordinary := f.approved(t, f.definition())
	request := RunRequest{Workflow: Reference{ID: ordinary.ID, Version: ordinary.Version, Hash: ordinary.Hash}, FileID: f.file.ID}
	for index := 0; index < 64; index++ {
		if _, err := f.s.Run(f.ctx, f.scope, "fill-original-queue-"+strconv.Itoa(index), request); err != nil {
			t.Fatal("cannot establish the unchanged 128-intent admission bound", index, err)
		}
	}
	before := routingPreviewCounts(t, f)
	if before[1] != 128 {
		t.Fatal("fixture did not fill the real send queue", before[1])
	}
	if _, err := f.s.Run(f.ctx, f.scope, "original-queue-overflow-refused", request); !errors.Is(err, store.ErrLimit) {
		t.Fatal("ordinary admission exceeded its original queue bound", err)
	}
	ready, err := f.s.CollectionReady(f.ctx, f.scope, job.ID)
	if err != nil || ready.RouteReady || ready.Reason != "routing_decision_required" {
		t.Fatal("capacity concealed the undecidable sibling", ready, err)
	}
	if _, err := f.s.RefreshCollection(f.ctx, f.scope, job.ID, "undecidable-original-key", Decision{Hash: job.Hash, Revision: captured.Job.Revision}); !errors.Is(err, ErrRouting) {
		t.Fatal("a missing sibling decision became a successful partial admission or capacity wait", err)
	}
	after := routingPreviewCounts(t, f)
	if after != before {
		t.Fatal("undecidable batch or full admission wrote partial state", before, after)
	}
	view, err := f.s.CollectionStatus(f.ctx, f.scope, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range view.Inputs {
		if input.RunID != nil || input.State != "accepted" {
			t.Fatal("undecidable batch admitted a sibling", input.ID, input.State)
		}
	}
}

func TestBoundedProgramCancelledReceiptKeepsPlanPrivateInEventsAndAudit(t *testing.T) {
	f := setup(t)
	source := collectionTestSource()
	source.Directory = "/"
	source.Connection = Reference{ID: f.connection.ID, Version: f.connection.Version, Hash: f.connection.Hash}
	d := f.definition()
	d.Schema, d.Source = 2, &source
	d.Program = &Program{Nodes: []ProgramNode{{Kind: "deliver", Step: d.Steps[1].ID}}}
	w := f.approved(t, d)
	job, owner, inputs := sealedCollectionFixture(t, f, CollectionSelection{Workflow: Reference{ID: w.ID, Version: w.Version, Hash: w.Hash}, Timeout: 120, Authority: 1}, "private-cancelled-plan", "def")
	captured := finishSealedCollection(t, f, job, owner, inputs)
	if _, err := f.s.RefreshCollection(f.ctx, f.scope, job.ID, "private-plan-admit", Decision{Hash: job.Hash, Revision: captured.Job.Revision}); err != nil {
		t.Fatal(err)
	}
	view, err := f.s.CollectionStatus(f.ctx, f.scope, job.ID)
	if err != nil || view.Inputs[0].RunID == nil {
		t.Fatal("missing exact routed input", err)
	}
	status, err := f.s.Status(f.ctx, f.scope, *view.Inputs[0].RunID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.Cancel(f.ctx, f.scope, status.Run.ID, "private-plan-cancel", Decision{Hash: w.Hash, Revision: status.Run.Revision}); err != nil {
		t.Fatal(err)
	}
	var original []byte
	if err = f.admin.QueryRow(f.ctx, `SELECT payload FROM events WHERE kind='WorkflowCommandCompleted' AND resource_id=$1 AND payload->>'request_key'='private-plan-cancel'`, status.Run.ID).Scan(&original); err != nil || !bytes.Contains(original, []byte("one.csv")) {
		t.Fatal("protected journal did not preserve the original plan", err)
	}
	peer, _ := approvalPeer(t, f, "Ordinary audit reader", append([]string{}, store.DefaultPermissions...))
	events, err := f.s.Custody.DB.Events(f.ctx, peer)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := f.s.Custody.DB.SnapshotEvents(f.ctx, peer, 1000, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	for _, surface := range []struct {
		name   string
		events []store.Event
	}{{"ordinary event feed", events}, {"audit snapshot", snapshot.Events}} {
		seen := false
		for _, event := range surface.events {
			if event.Kind != "WorkflowCommandCompleted" || event.ResourceID != status.Run.ID {
				continue
			}
			seen = true
			var envelope struct {
				Redacted bool   `json:"redacted"`
				Hash     string `json:"source_payload_sha256"`
			}
			if json.Unmarshal(event.Payload, &envelope) != nil || !envelope.Redacted || envelope.Hash != secure.Digest(original) || bytes.Contains(event.Payload, []byte("one.csv")) || bytes.Contains(event.Payload, []byte("execution_plan")) {
				t.Fatal(surface.name + " disclosed a cancelled run's private plan instead of its exact journal digest")
			}
		}
		if !seen {
			t.Fatal(surface.name + " lost the cancellation event")
		}
	}
}

func TestBoundedProgramLocalOnlyRunNeedsNoAdminOrDeliverPermission(t *testing.T) {
	f := setup(t)
	permissions := []string{}
	for _, permission := range store.DefaultPermissions {
		if permission != "admin" && permission != "deliver" {
			permissions = append(permissions, permission)
		}
	}
	local, _ := approvalPeer(t, f, "Local-only workflow operator", permissions)
	f.scope = local
	d := Definition{Schema: 2, Name: "Record a local decision", Steps: []Step{}, Program: &Program{Nodes: []ProgramNode{{Kind: "keep_local", Reason: "local_review_required"}}}}
	w := f.approved(t, d)
	r := RunRequest{Workflow: Reference{ID: w.ID, Version: w.Version, Hash: w.Hash}, FileID: f.file.ID}
	if _, err := f.s.PreviewRun(f.ctx, local, r); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("local-only preview exposed another actor's unpublished raw file", err)
	}
	owned, _, err := f.s.Custody.Accept(f.ctx, local, "local-owned-source", 3, secure.Digest([]byte("def")), bytes.NewReader([]byte("def")))
	if err != nil {
		t.Fatal(err)
	}
	f.file, r.FileID = owned, owned.ID
	preview, err := f.s.PreviewRun(f.ctx, local, r)
	if err != nil || len(preview.Potential) != 0 || len(preview.Selected) != 0 || preview.Plan.LocalReason != "local_review_required" {
		t.Fatal("local-only metadata preview requires unrelated delivery authority", preview, err)
	}
	result, err := f.s.Run(f.ctx, local, "local-no-deliver", r)
	if err != nil {
		t.Fatal("recording a local outcome requires unrelated delivery authority", err)
	}
	again, err := f.s.Run(f.ctx, local, "local-no-deliver", r)
	if err != nil || !again.Replayed {
		t.Fatal("local-only replay did not return its original receipt", err)
	}
	// PostgreSQL jsonb preserves the complete result meaning, not whitespace or
	// object-key order. Compare every value, including the frozen plan/hash.
	var original, recorded any
	if json.Unmarshal(result.Resource, &original) != nil || json.Unmarshal(again.Resource, &recorded) != nil || !reflect.DeepEqual(original, recorded) {
		t.Fatal("local-only replay changed its original disposition")
	}
	var run store.WorkflowRun
	if err = json.Unmarshal(result.Resource, &run); err != nil || run.State != "kept_local" {
		t.Fatal(run, err)
	}
	status, err := f.s.Status(f.ctx, local, run.ID)
	if err != nil || status.ObservedState != "kept_local" || len(status.Steps) != 0 {
		t.Fatal(status, err)
	}
	var count int
	if err = f.admin.QueryRow(f.ctx, `SELECT count(*) FROM delivery_intents`).Scan(&count); err != nil || count != 0 {
		t.Fatal("local-only permission path created a delivery", count, err)
	}
}

func TestBoundedProgramRunQueuesOnlyFrozenSelectedCatalogSteps(t *testing.T) {
	f := setup(t)
	d := f.definition()
	d.Schema = 2
	d.Steps = append(d.Steps, Step{ID: "unused", Kind: "sftp.deliver", Connection: d.Steps[0].Connection, Filename: "unused.csv"})
	order := []string{d.Steps[1].ID, d.Steps[0].ID}
	d.Program = &Program{Nodes: []ProgramNode{{Kind: "for_each", Variable: "recipient", Steps: order, Body: []ProgramNode{{Kind: "deliver", StepVariable: "recipient"}}}}}
	w := f.approved(t, d)
	result, err := f.s.Run(f.ctx, f.scope, "planned-subset-run", RunRequest{Workflow: Reference{ID: w.ID, Version: w.Version, Hash: w.Hash}, FileID: f.file.ID})
	if err != nil {
		t.Fatal("ordinary run cannot admit the approved frozen routing plan", err)
	}
	var resource struct {
		ID   string         `json:"id"`
		Plan *ExecutionPlan `json:"execution_plan"`
		Hash string         `json:"execution_plan_hash"`
	}
	if err = json.Unmarshal(result.Resource, &resource); err != nil || resource.Plan == nil || !reflect.DeepEqual(resource.Plan.Steps, order) {
		t.Fatal("run did not freeze selected catalog order", resource, err)
	}
	_, hash, _ := digest(resource.Plan)
	if hash != resource.Hash {
		t.Fatal("run plan fingerprint is not its exact canonical plan")
	}
	status, err := f.s.Status(f.ctx, f.scope, resource.ID)
	if err != nil || len(status.Steps) != 2 || status.Steps[0].ID != order[0] || status.Steps[1].ID != order[1] {
		t.Fatal("catalog positions replaced selected execution positions", status, err)
	}
	var count int
	if err = f.admin.QueryRow(f.ctx, `SELECT count(*) FROM delivery_intents`).Scan(&count); err != nil || count != 2 {
		t.Fatal("unused catalog recipient acquired an intent", count, err)
	}
}

func TestBoundedProgramExplicitLocalRunCreatesNoDelivery(t *testing.T) {
	f := setup(t)
	d := f.definition()
	d.Schema = 2
	d.Program = &Program{Nodes: []ProgramNode{{Kind: "keep_local", Reason: "local_review_required"}}}
	w := f.approved(t, d)
	result, err := f.s.Run(f.ctx, f.scope, "explicit-local-run", RunRequest{Workflow: Reference{ID: w.ID, Version: w.Version, Hash: w.Hash}, FileID: f.file.ID})
	if err != nil {
		t.Fatal("explicit local outcome cannot be durably recorded", err)
	}
	var resource struct {
		ID    string         `json:"id"`
		Plan  *ExecutionPlan `json:"execution_plan"`
		State string         `json:"state"`
	}
	if err = json.Unmarshal(result.Resource, &resource); err != nil || resource.Plan == nil || resource.Plan.LocalReason != "local_review_required" || resource.State != "kept_local" {
		t.Fatal("local outcome became a fake send or ordinary queue", resource, err)
	}
	status, err := f.s.Status(f.ctx, f.scope, resource.ID)
	if err != nil || len(status.Steps) != 0 || status.ObservedState != "kept_local" {
		t.Fatal("local run cannot be inspected without fake delivery steps", status, err)
	}
	var count int
	if err = f.admin.QueryRow(f.ctx, `SELECT count(*) FROM delivery_intents`).Scan(&count); err != nil || count != 0 {
		t.Fatal("local decision fabricated a delivery intent", count, err)
	}
}

func TestBoundedProgramSQLRefusesForgedFactsChoicesTraceAndHash(t *testing.T) {
	f := setup(t)
	d := f.definition()
	d.Schema = 2
	d.Steps = append(d.Steps, Step{ID: "unused", Kind: "sftp.deliver", Connection: d.Steps[0].Connection, Filename: "unused.csv"})
	d.Program = &Program{Nodes: []ProgramNode{{Kind: "for_each", Variable: "destination", Steps: []string{d.Steps[1].ID, d.Steps[0].ID}, Body: []ProgramNode{{Kind: "deliver", StepVariable: "destination"}}}}}
	w := f.approved(t, d)
	for name, mutate := range map[string]func(*ExecutionPlan){
		"unselected-recipient": func(p *ExecutionPlan) { p.Steps[0] = "unused" },
		"reordered-selection":  func(p *ExecutionPlan) { p.Steps[0], p.Steps[1] = p.Steps[1], p.Steps[0] },
		"forged-file-size":     func(p *ExecutionPlan) { p.Facts.File.Size++ },
		"forged-source":        func(p *ExecutionPlan) { p.Facts.Source = routingTestFacts().Source },
		"forged-decision":      func(p *ExecutionPlan) { p.Decisions[1].Path = "different_control_path" },
		"forged-hash":          func(_ *ExecutionPlan) {},
	} {
		t.Run(name, func(t *testing.T) {
			plan, err := CompileProgram(d, RoutingFacts{File: *f.file})
			if err != nil {
				t.Fatal(err)
			}
			mutate(plan)
			encoded, hash, _ := digest(plan)
			if name == "forged-hash" {
				hash = strings.Repeat("f", 64)
			}
			run := &store.WorkflowRun{ID: secure.NewID(), WorkflowID: w.ID, WorkflowVersion: w.Version, WorkflowHash: w.Hash, FileID: f.file.ID, Source: *f.file, StorageID: f.s.Custody.Disk.Identity(), Root: "/", Authority: 1, State: "queued", Reason: "awaiting_worker", Revision: 1, Plan: encoded, PlanHash: hash}
			tx, err := f.s.begin(f.ctx, f.scope, "workflow_execute", "read", "deliver")
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Tx.Rollback(f.ctx)
			err = tx.SaveWorkflowRun(f.ctx, run, 0)
			// Refusal must occur at insertion, before any missing-step completeness
			// check could conceal an accepted forged plan or fingerprint.
			collectionSQLRefusal(t, err)
		})
	}
}

func TestBoundedProgramCollectedBatchBindsOriginalManifestFactsAndLocalOutcome(t *testing.T) {
	f := setup(t)
	source := collectionTestSource()
	source.Directory = "/"
	source.Connection = Reference{ID: f.connection.ID, Version: f.connection.Version, Hash: f.connection.Hash}
	d := f.definition()
	d.Schema = 2
	d.Source = &source
	text := "one.csv"
	d.Program = &Program{Nodes: []ProgramNode{{Kind: "if", When: &Condition{Op: "eq", Field: "source.name", Text: &text}, Then: []ProgramNode{{Kind: "for_each", Variable: "recipient", Steps: []string{d.Steps[1].ID, d.Steps[0].ID}, Body: []ProgramNode{{Kind: "deliver", StepVariable: "recipient"}}}}, Else: []ProgramNode{{Kind: "keep_local", Reason: "unmatched_source_file"}}}}}
	w := f.approved(t, d)
	selection := CollectionSelection{Workflow: Reference{ID: w.ID, Version: w.Version, Hash: w.Hash}, Timeout: 120, Authority: 1}
	job, owner, inputs := sealedCollectionFixture(t, f, selection, "routing-batch", "abc", "def")
	captured := finishSealedCollection(t, f, job, owner, inputs)
	if _, err := f.s.RefreshCollection(f.ctx, f.scope, job.ID, "route-captured-batch", Decision{Hash: job.Hash, Revision: captured.Job.Revision}); err != nil {
		t.Fatal(err)
	}
	after, err := f.s.CollectionStatus(f.ctx, f.scope, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	for index, input := range after.Inputs {
		if input.RunID == nil {
			t.Fatal("captured sibling has no durable routing disposition", input)
		}
		status, err := f.s.Status(f.ctx, f.scope, *input.RunID)
		if err != nil {
			t.Fatal(err)
		}
		plan, err := storedExecutionPlan(status.Run)
		if err != nil || plan == nil || plan.Facts.Source == nil || plan.Facts.Source.CollectionID != job.ID || plan.Facts.Source.Name != input.Name || plan.Facts.Source.Index != index || plan.Facts.Source.Count != 2 || plan.Facts.Source.ManifestHash != *after.Job.ManifestHash || plan.Facts.File.ID != *input.FileID {
			t.Fatal("routing facts came from mutable selection instead of the original producer manifest", plan, err)
		}
		if input.Name == "one.csv" {
			if len(status.Steps) != 2 || status.Steps[0].ID != d.Steps[1].ID {
				t.Fatal("branch ignored approved loop order", status)
			}
		} else if status.ObservedState != "kept_local" || len(status.Steps) != 0 {
			t.Fatal("unmatched sibling acquired a fake send", status)
		}
	}
	var count int
	if err = f.admin.QueryRow(f.ctx, `SELECT count(*) FROM delivery_intents`).Scan(&count); err != nil || count != 2 {
		t.Fatal("batch routing sent the unmatched sibling", count, err)
	}
}

func TestBoundedProgramSourceOnlyBatchRequiresAnExplicitRecordedLocalDecision(t *testing.T) {
	f := setup(t)
	source := collectionTestSource()
	source.Directory = "/"
	source.Connection = Reference{ID: f.connection.ID, Version: f.connection.Version, Hash: f.connection.Hash}
	d := f.definition()
	d.Schema = 2
	d.Source = &source
	d.Steps = []Step{}
	d.Program = &Program{Nodes: []ProgramNode{{Kind: "keep_local", Reason: "local_collection_policy"}}}
	w := f.approved(t, d)
	selection := CollectionSelection{Workflow: Reference{ID: w.ID, Version: w.Version, Hash: w.Hash}, Timeout: 120, Authority: 1}
	job, owner, inputs := sealedCollectionFixture(t, f, selection, "source-local-program", "abc")
	captured := finishSealedCollection(t, f, job, owner, inputs)
	ready, err := f.s.CollectionReady(f.ctx, f.scope, job.ID)
	if err != nil || !ready.RouteReady {
		t.Fatal("source-only program was treated as an ordinary no-program collection", ready, err)
	}
	if _, err = f.s.RefreshCollection(f.ctx, f.scope, job.ID, "record-local-source-decision", Decision{Hash: job.Hash, Revision: captured.Job.Revision}); err != nil {
		t.Fatal(err)
	}
	after, err := f.s.CollectionStatus(f.ctx, f.scope, job.ID)
	if err != nil || after.Inputs[0].RunID == nil {
		t.Fatal("local source disposition was silently discarded", after, err)
	}
	status, err := f.s.Status(f.ctx, f.scope, *after.Inputs[0].RunID)
	if err != nil || status.ObservedState != "kept_local" || len(status.Steps) != 0 {
		t.Fatal(status, err)
	}
}
