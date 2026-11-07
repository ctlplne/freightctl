//go:build integration

package checks

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func processingWorkflowFixture(t *testing.T) (*fixture, *Service, *store.Configuration, *store.File) {
	t.Helper()
	f := setup(t)
	s, p, source := policyAndFile(t, f, goodCSV, true)
	f.wf.Processor = s
	if _, err := s.Run(f.ctx, f.scope, source.ID, "processing-source-check"); err != nil {
		t.Fatal(err)
	}
	rules, err := NormalizeRecordProjection(testPolicy(t), RecordProjection{Schema: 1, Kind: "record_projection", SourcePolicyHash: p.Hash, OutputKind: "json_records", MaxBytes: 8192, Columns: []ProjectionColumn{{Source: "amount", Target: "total"}, {Source: "account", Target: "account"}, {Source: "day", Target: "day"}}})
	if err != nil {
		t.Fatal(err)
	}
	output, err := projectionOutputPolicy(testPolicy(t), rules)
	if err != nil {
		t.Fatal(err)
	}
	registered, err := s.Register(f.ctx, f.scope, "processing-output-policy", PolicyRequest{ExpectedVersion: 1, Definition: output})
	if err != nil {
		t.Fatal(err)
	}
	var policy store.Configuration
	if json.Unmarshal(registered.Resource, &policy) != nil {
		t.Fatal("output policy")
	}
	definition := workflow.Definition{Schema: 3, Name: "Approved settlement processing", Processing: &workflow.ProcessingTask{ID: "project", Kind: "records.project", Definition: rules, OutputPolicy: workflow.Reference{ID: policy.ID, Version: policy.Version, Hash: policy.Hash}, TargetPath: "/workflow-output.json", Reason: "Create a distinct held settlement artifact"}}
	draft, err := f.wf.Draft(f.ctx, f.scope, "processing-workflow-draft", workflow.DraftRequest{Definition: definition})
	if err != nil {
		t.Fatal(err)
	}
	var cfg store.Configuration
	if json.Unmarshal(draft.Resource, &cfg) != nil {
		t.Fatal("workflow draft")
	}
	if _, err = f.wf.Decide(f.ctx, f.scope, cfg.ID, cfg.Version, "processing-workflow-approval", "approve", workflow.Decision{Hash: cfg.Hash, Revision: cfg.Revision}); err != nil {
		t.Fatal(err)
	}
	return f, s, &cfg, source
}

func TestProcessingWorkflowActualConfinedActorHasNoAdministrationReleaseOrDelivery(t *testing.T) {
	f := setup(t)
	manager := f.scope
	s := &Service{Custody: f.wf.Custody}
	wf := &workflow.Service{Custody: s.Custody, Processor: s}
	registered, err := s.Register(f.ctx, manager, "scoped-wf-input-policy", PolicyRequest{Definition: testPolicy(t)})
	if err != nil {
		t.Fatal(err)
	}
	var input store.Configuration
	if json.Unmarshal(registered.Resource, &input) != nil {
		t.Fatal("source policy")
	}
	mode := uint32(0777)
	if _, err = s.Custody.PathCommand(f.ctx, manager, "processor-directory", store.PathCommand{Operation: "mkdir", Path: "/processor", Mode: &mode}); err != nil {
		t.Fatal(err)
	}
	account := store.AccountCommand{Operation: "create", ID: secure.NewID(), CredentialHash: secure.Digest([]byte(secure.NewID())), Policy: &store.AccountPolicy{Label: "Scoped workflow processor", Root: "/processor", Permissions: []string{"read", "write", "check_run", "workflow_manage", "workflow_approve", "workflow_execute"}}}
	if _, err = s.Custody.DB.ChangeAccount(f.ctx, manager, "processor-account", account); err != nil {
		t.Fatal(err)
	}
	actor := store.Scope{Tenant: manager.Tenant, Partner: manager.Partner, TokenHash: account.CredentialHash}
	source, _, err := s.Custody.AcceptAt(f.ctx, actor, "scoped-wf-input", int64(len(goodCSV)), secure.Digest([]byte(goodCSV)), strings.NewReader(goodCSV), custody.UploadTarget{Path: "/input.csv"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Run(f.ctx, actor, source.ID, "scoped-wf-source-check"); err != nil {
		t.Fatal(err)
	}
	rules, err := NormalizeRecordProjection(testPolicy(t), RecordProjection{Schema: 1, Kind: "record_projection", SourcePolicyHash: input.Hash, OutputKind: "json_records", MaxBytes: 8192, Columns: []ProjectionColumn{{Source: "account", Target: "account"}, {Source: "amount", Target: "amount"}, {Source: "day", Target: "day"}}})
	if err != nil {
		t.Fatal(err)
	}
	output, err := projectionOutputPolicy(testPolicy(t), rules)
	if err != nil {
		t.Fatal(err)
	}
	registered, err = s.Register(f.ctx, manager, "scoped-wf-output-policy", PolicyRequest{ExpectedVersion: 1, Definition: output})
	if err != nil {
		t.Fatal(err)
	}
	var policy store.Configuration
	if json.Unmarshal(registered.Resource, &policy) != nil {
		t.Fatal("output policy")
	}
	definition := workflow.Definition{Schema: 3, Name: "Confined approved processing", Processing: &workflow.ProcessingTask{ID: "project", Kind: "records.project", Definition: rules, OutputPolicy: workflow.Reference{ID: policy.ID, Version: policy.Version, Hash: policy.Hash}, TargetPath: "/derived.json", Reason: "Create held records only inside this actor namespace"}}
	drafted, err := wf.Draft(f.ctx, actor, "scoped-wf-draft", workflow.DraftRequest{Definition: definition})
	if err != nil {
		t.Fatal(err)
	}
	var cfg store.Configuration
	if json.Unmarshal(drafted.Resource, &cfg) != nil {
		t.Fatal("workflow draft")
	}
	if _, err = wf.Decide(f.ctx, actor, cfg.ID, cfg.Version, "scoped-wf-approve", "approve", workflow.Decision{Hash: cfg.Hash, Revision: 1}); err != nil {
		t.Fatal(err)
	}
	created, err := wf.Run(f.ctx, actor, "scoped-wf-run", workflow.RunRequest{Workflow: workflow.Reference{ID: cfg.ID, Version: cfg.Version, Hash: cfg.Hash}, FileID: source.ID})
	if err != nil {
		t.Fatal(err)
	}
	var run store.WorkflowRun
	if json.Unmarshal(created.Resource, &run) != nil || run.Root != "/processor" {
		t.Fatal("workflow lost confined root")
	}
	worked, err := wf.Work(f.ctx, actor, run.ID, "scoped-wf-work")
	if err != nil || worked.Processing == nil || worked.Status.ObservedReason != "output_held" {
		t.Fatal("confined workflow required unrelated root privileges", err)
	}
	checked, err := s.Get(f.ctx, actor, worked.Processing.FileID)
	if err != nil {
		t.Fatal(err)
	}
	if checked.Check.State != "queued" || checked.Check.ReportHash != "" {
		t.Fatal("workflow processing supplied a completed check report")
	}
	deniedRelease := releaseDecision(checked.Check)
	deniedRelease.ReportHash = secure.Digest([]byte("not a completed check report"))
	if _, err = s.Release(f.ctx, actor, worked.Processing.FileID, "cannot-release", deniedRelease); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("workflow execution granted release", err)
	}
	var root, target string
	if err = f.admin.QueryRow(f.ctx, `SELECT binding->>'namespace_root',binding->'target'->>'path' FROM file_checks WHERE file_id=$1`, worked.Processing.FileID).Scan(&root, &target); err != nil || root != "/processor" || target != "/derived.json" {
		t.Fatal("processing target escaped actor namespace", err)
	}
}

func TestProcessingWorkflowActualFailureKeyNeverAdvancesToLaterRetry(t *testing.T) {
	f, s, cfg, source := processingWorkflowFixture(t)
	r := processingWorkflowRun(t, f, cfg, source, "processing-retry-run")
	budget := s.Custody.MaxStored
	s.Custody.MaxStored = 1
	failed, err := f.wf.Work(f.ctx, f.scope, r.ID, "processing-failed-attempt")
	s.Custody.MaxStored = budget
	if err != nil || failed.Processing == nil || failed.Processing.State != "failed" || failed.Processing.Attempts != 1 {
		t.Fatal("failed private stage did not retain its first attempt", err)
	}
	completed, err := f.wf.Work(f.ctx, f.scope, r.ID, "processing-second-attempt")
	if err != nil || completed.Processing == nil || completed.Processing.State != "completed" || completed.Processing.Attempts != 2 {
		t.Fatal("fresh authorized key did not retry the failed attempt", err)
	}
	old, err := f.wf.Work(f.ctx, f.scope, r.ID, "processing-failed-attempt")
	if err != nil || !old.Replayed || old.Processing.State != "failed" || old.Processing.Attempts != 1 || old.Status.Processing.State != "completed" || old.Status.Processing.Attempts != 2 {
		t.Fatal("historical command was reinterpreted as the later attempt", err)
	}
}

func TestProcessingWorkflowActualSQLRejectsHeldSuccessAndMissingAtomicMembership(t *testing.T) {
	f, _, cfg, source := processingWorkflowFixture(t)
	r := processingWorkflowRun(t, f, cfg, source, "processing-sql-run")
	tx, err := f.wf.Custody.DB.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	copy := *r
	copy.State = "succeeded"
	copy.Reason = "transformed_output_released"
	copy.Revision++
	err = tx.SaveWorkflowRun(f.ctx, &copy, r.Revision)
	tx.Tx.Rollback(f.ctx)
	if err == nil {
		t.Fatal("SQL treated zero delivery steps as processing success before fresh release")
	}
	tx, err = f.wf.Custody.DB.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	copy = *r
	copy.ID = secure.NewID()
	if err = tx.SaveWorkflowRun(f.ctx, &copy, 0); err != nil {
		tx.Tx.Rollback(f.ctx)
		t.Fatal(err)
	}
	if err = tx.Tx.Commit(f.ctx); err == nil {
		t.Fatal("schema3 run committed without its processing binding")
	}
	var count int
	if err = f.admin.QueryRow(f.ctx, `SELECT count(*) FROM workflow_runs WHERE run_id=$1`, copy.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("failed membership commit retained a partial run", err)
	}
}
func processingWorkflowRun(t *testing.T, f *fixture, cfg *store.Configuration, source *store.File, key string) *store.WorkflowRun {
	t.Helper()
	r, err := f.wf.Run(f.ctx, f.scope, key, workflow.RunRequest{Workflow: workflow.Reference{ID: cfg.ID, Version: cfg.Version, Hash: cfg.Hash}, FileID: source.ID})
	if err != nil {
		t.Fatal(err)
	}
	var run store.WorkflowRun
	if json.Unmarshal(r.Resource, &run) != nil {
		t.Fatal("run receipt")
	}
	return &run
}
func TestProcessingWorkflowActualApprovedTaskHoldsOutputUntilFreshSeparateRelease(t *testing.T) {
	f, s, cfg, source := processingWorkflowFixture(t)
	if _, _, err := s.Custody.Download(f.ctx, f.scope, source.ID); !errors.Is(err, store.ErrState) {
		t.Fatal("held retired-policy source unexpectedly downloadable", err)
	}
	r := processingWorkflowRun(t, f, cfg, source, "processing-run")
	var bindings, deliveries int
	if err := f.admin.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM workflow_processing WHERE run_id=$1),(SELECT count(*) FROM workflow_steps WHERE run_id=$1)`, r.ID).Scan(&bindings, &deliveries); err != nil || bindings != 1 || deliveries != 0 {
		t.Fatal("run did not atomically bind exactly one processing intent and no delivery", err)
	}
	worked, err := f.wf.Work(f.ctx, f.scope, r.ID, "processing-work")
	if err != nil {
		t.Fatal(err)
	}
	if worked.Status.ObservedState != "attention" || worked.Status.ObservedReason != "output_held" || worked.Processing == nil || worked.Processing.State != "completed" || worked.Status.Processing.Released || len(worked.Status.Steps) != 0 {
		t.Fatal("processing inherited release or became delivery")
	}
	file := worked.Processing.FileID
	if file == source.ID {
		t.Fatal("processing rewrote its input")
	}
	if _, _, err = s.Custody.Download(f.ctx, f.scope, file); !errors.Is(err, store.ErrState) {
		t.Fatal("held output leaked", err)
	}
	replayed, err := f.wf.Work(f.ctx, f.scope, r.ID, "processing-work")
	if err != nil || !replayed.Replayed || replayed.Processing.ID != worked.Processing.ID || replayed.Processing.Attempts != 1 {
		t.Fatal("work response-loss replay advanced processing", err)
	}
	if _, err = s.Run(f.ctx, f.scope, file, "processing-output-check"); err != nil {
		t.Fatal(err)
	}
	checked := getCheck(t, s, f, file)
	if _, err = s.Release(f.ctx, f.scope, file, "processing-output-release", releaseDecision(checked)); err != nil {
		t.Fatal(err)
	}
	if _, err = f.wf.RefreshRun(f.ctx, f.scope, r.ID, "processing-refresh"); err != nil {
		t.Fatal(err)
	}
	view, err := f.wf.Status(f.ctx, f.scope, r.ID)
	if err != nil || view.Run.State != "succeeded" || view.ObservedReason != "transformed_output_released" || !view.Processing.Released {
		t.Fatal("fresh release not observed independently", err)
	}
	_, reader, err := s.Custody.Download(f.ctx, f.scope, file)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	data, err := io.ReadAll(reader)
	if err != nil || !bytes.Contains(data, []byte(`"account":"0001"`)) || !bytes.Contains(data, []byte(`"total":1.01`)) {
		t.Fatal("generated immutable records changed identifiers or exact decimal", err)
	}
	original, err := f.wf.Run(f.ctx, f.scope, "processing-run", workflow.RunRequest{Workflow: workflow.Reference{ID: cfg.ID, Version: cfg.Version, Hash: cfg.Hash}, FileID: source.ID})
	if err != nil || !original.Replayed {
		t.Fatal("original run receipt revalidated an already-published target", err)
	}
}
func TestProcessingWorkflowActualRevocationStopsDirectWorkerAndAllowsSafeCancellation(t *testing.T) {
	f, s, cfg, source := processingWorkflowFixture(t)
	r := processingWorkflowRun(t, f, cfg, source, "processing-run-revoke")
	view, err := f.wf.Status(f.ctx, f.scope, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.wf.Decide(f.ctx, f.scope, cfg.ID, cfg.Version, "revoke-processing", "revoke", workflow.Decision{Hash: cfg.Hash, Revision: 2}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.StartProjection(f.ctx, f.scope, view.Processing.ID, "direct-revoked-start", ProjectionStartDecision{Hash: view.Processing.Hash, Revision: view.Processing.Revision}); err == nil {
		t.Fatal("direct projection API bypassed workflow revocation")
	}
	if _, err = f.wf.Work(f.ctx, f.scope, r.ID, "revoked-work"); err == nil {
		t.Fatal("revoked task executed")
	}
	if _, err = f.wf.Cancel(f.ctx, f.scope, r.ID, "cancel-revoked", workflow.Decision{Hash: cfg.Hash, Revision: r.Revision}); err != nil {
		t.Fatal("revocation prevented retiring pending work", err)
	}
	view, err = f.wf.Status(f.ctx, f.scope, r.ID)
	if err != nil || view.ObservedState != "cancelled" || view.Processing.State != "cancelled" {
		t.Fatal("workflow cancellation left executable processing", err)
	}
}
