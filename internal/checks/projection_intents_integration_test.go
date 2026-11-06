//go:build integration

package checks

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
)

func projectionIntentRow(t *testing.T, result *Result) *store.RecordProjection {
	t.Helper()
	var v struct {
		Kind       string                  `json:"kind"`
		Projection *store.RecordProjection `json:"projection"`
	}
	if result == nil || json.Unmarshal(result.Resource, &v) != nil || v.Kind != "record_projection" || v.Projection == nil {
		t.Fatal("invalid projection receipt")
	}
	return v.Projection
}
func approvedProjection(t *testing.T) (*fixture, *Service, *store.RecordProjection) {
	t.Helper()
	f := setup(t)
	s, p, source := policyAndFile(t, f, goodCSV, true)
	if _, err := s.Run(f.ctx, f.scope, source.ID, "source-check"); err != nil {
		t.Fatal(err)
	}
	definition, err := NormalizeRecordProjection(testPolicy(t), RecordProjection{Schema: 1, Kind: "record_projection", SourcePolicyHash: p.Hash, OutputKind: "json_records", MaxBytes: 8192, Columns: []ProjectionColumn{{Source: "amount", Target: "total"}, {Source: "account", Target: "account"}, {Source: "day", Target: "date"}}})
	if err != nil {
		t.Fatal(err)
	}
	output, err := projectionOutputPolicy(testPolicy(t), definition)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Register(f.ctx, f.scope, "output-policy", PolicyRequest{ExpectedVersion: 1, Definition: output}); err != nil {
		t.Fatal(err)
	}
	preview, err := s.PreviewProjection(f.ctx, f.scope, source.ID, ProjectionOptions{TargetPath: "/derived.json", Reason: "Process reviewed rows into separately held custody", Definition: definition})
	if err != nil {
		t.Fatal(err)
	}
	saved, err := s.ProposeProjection(f.ctx, f.scope, "propose", preview.Plan)
	if err != nil {
		t.Fatal(err)
	}
	r := projectionIntentRow(t, saved)
	replay, err := s.ProposeProjection(f.ctx, f.scope, "propose", preview.Plan)
	if err != nil || !replay.Replayed || projectionIntentRow(t, replay).ID != r.ID {
		t.Fatal("proposal response-loss replay", err)
	}
	if _, err = s.StartProjection(f.ctx, f.scope, r.ID, "unapproved", ProjectionStartDecision{Hash: r.Hash, Revision: r.Revision}); !errors.Is(err, store.ErrState) {
		t.Fatal("unapproved processing start", err)
	}
	approved, err := s.DecideProjection(f.ctx, f.scope, r.ID, "approve", PolicyRecheckDecision{Operation: "approve", Hash: r.Hash, Revision: r.Revision})
	if err != nil {
		t.Fatal(err)
	}
	return f, s, projectionIntentRow(t, approved)
}
func startProjection(t *testing.T, f *fixture, s *Service, r *store.RecordProjection, key string) (*store.RecordProjection, ProjectionAttempt) {
	t.Helper()
	result, err := s.StartProjection(f.ctx, f.scope, r.ID, key, ProjectionStartDecision{Hash: r.Hash, Revision: r.Revision})
	if err != nil {
		t.Fatal(err)
	}
	row := projectionIntentRow(t, result)
	return row, ProjectionAttempt{ID: row.ID, Number: row.Attempts, WorkerID: row.WorkerID}
}
func TestProjectionActualDurableApprovalHeldOutputAndOriginalReceipts(t *testing.T) {
	f, s, r := approvedProjection(t)
	running, attempt := startProjection(t, f, s, r, "start")
	wrong := attempt
	wrong.WorkerID = "88888888-8888-4888-8888-888888888888"
	if _, err := s.WorkProjection(f.ctx, f.scope, "foreign-worker", wrong); !errors.Is(err, store.ErrState) {
		t.Fatal("worker substitution", err)
	}
	result, err := s.WorkProjection(f.ctx, f.scope, "work", attempt)
	if err != nil {
		t.Fatal(err)
	}
	completed := projectionIntentRow(t, result)
	if completed.State != "completed" || completed.Attempts != 1 || completed.FileID == r.SourceID {
		t.Fatal("no distinct completed artifact")
	}
	var output ProjectionOutput
	if json.Unmarshal(completed.Result, &output) != nil || output.Kind != "record_projection_output" || output.Acceptance != "durable-held-pending-checks-and-release" || output.Attempt != attempt || output.File.ID != completed.FileID {
		t.Fatal("invalid processing receipt")
	}
	c := getCheck(t, s, f, completed.FileID)
	if c.State != "held" || c.Attempts != 0 || c.ReportHash != "" {
		t.Fatal("source checks or release inherited")
	}
	if _, _, err = s.Custody.Download(f.ctx, f.scope, completed.FileID); !errors.Is(err, store.ErrState) {
		t.Fatal("held output downloadable", err)
	}
	if _, err = s.Custody.StatPath(f.ctx, f.scope, "/derived.json"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("output published before separate release", err)
	}
	replay, err := s.WorkProjection(f.ctx, f.scope, "work", attempt)
	if err != nil || !replay.Replayed || !sameJSON(replay.Resource, result.Resource) {
		t.Fatal("lost work response changed result", err)
	}
	old, err := s.StartProjection(f.ctx, f.scope, r.ID, "start", ProjectionStartDecision{Hash: r.Hash, Revision: r.Revision})
	if err != nil || !old.Replayed || projectionIntentRow(t, old).WorkerID != running.WorkerID {
		t.Fatal("start replay pretended current completion", err)
	}
	if _, err = s.Run(f.ctx, f.scope, completed.FileID, "fresh-output-check"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Release(f.ctx, f.scope, completed.FileID, "separate-output-release", releaseDecision(getCheck(t, s, f, completed.FileID))); err != nil {
		t.Fatal(err)
	}
	_, reader, err := s.Custody.Download(f.ctx, f.scope, completed.FileID)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	actual, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if string(actual) != "[{\"total\":1.01,\"account\":\"0001\",\"date\":\"2026-10-28\"}]\n" {
		t.Fatal("independent receiver got different exact output")
	}
	decoder := json.NewDecoder(bytes.NewReader(actual))
	decoder.UseNumber()
	var rows []map[string]any
	if decoder.Decode(&rows) != nil || len(rows) != 1 || rows[0]["total"].(json.Number).String() != "1.01" || rows[0]["account"] != "0001" {
		t.Fatal("money or identifier changed")
	}
	var count int
	if err = f.admin.QueryRow(f.ctx, `SELECT count(*) FROM events WHERE kind='FileAccepted' AND resource_id=$1 AND payload->'record_projection'->>'id'=$2 AND payload->'record_projection'->>'source_file_id'=$3`, completed.FileID, r.ID, r.SourceID).Scan(&count); err != nil || count != 1 {
		t.Fatal("missing or duplicate immutable lineage", count, err)
	}
}
func TestProjectionActualReceiptRollbackAdoptsSealedOutputWithoutDuplicateAcceptance(t *testing.T) {
	f, s, r := approvedProjection(t)
	_, attempt := startProjection(t, f, s, r, "start")
	d, err := decodeProjection(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.admin.Exec(f.ctx, `CREATE FUNCTION freightctl_test_projection_receipt_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.request_key='work-fault' THEN RAISE EXCEPTION 'task-owned projection receipt failure';END IF;RETURN NEW;END $$;CREATE TRIGGER freightctl_test_projection_receipt_failure BEFORE INSERT ON check_receipts FOR EACH ROW EXECUTE FUNCTION freightctl_test_projection_receipt_failure()`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.WorkProjection(f.ctx, f.scope, "work-fault", attempt); err == nil {
		t.Fatal("receipt fault ignored")
	}
	var count int
	if err = f.admin.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM files WHERE file_id=$1)+(SELECT count(*) FROM events WHERE resource_id=$1)+(SELECT count(*) FROM check_receipts WHERE request_key='work-fault')`, d.Slots[0]).Scan(&count); err != nil || count != 0 {
		t.Fatal("partial SQL commit", count, err)
	}
	name := filepath.Join(f.diskPath, custody.Name(f.scope.Tenant, f.scope.Partner, d.Slots[0]))
	before, err := os.Stat(name)
	if err != nil || before.Mode().Perm() != 0400 {
		t.Fatal("sealed uncertain-commit candidate lost", err)
	}
	if _, err = f.admin.Exec(f.ctx, `DROP TRIGGER freightctl_test_projection_receipt_failure ON check_receipts;DROP FUNCTION freightctl_test_projection_receipt_failure()`); err != nil {
		t.Fatal(err)
	}
	completed, err := s.WorkProjection(f.ctx, f.scope, "work-fault", attempt)
	if err != nil || projectionIntentRow(t, completed).FileID != d.Slots[0] {
		t.Fatal("sealed retry not adopted", err)
	}
	after, err := os.Stat(name)
	if err != nil || !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("adoption replaced bytes", err)
	}
	if err = f.admin.QueryRow(f.ctx, `SELECT count(*) FROM events WHERE resource_id=$1 AND kind='FileAccepted'`, d.Slots[0]).Scan(&count); err != nil || count != 1 {
		t.Fatal("duplicate accepted output", count, err)
	}
}
func TestProjectionActualFailureReceiptRetryAndOldWorkerFence(t *testing.T) {
	f, s, r := approvedProjection(t)
	running, attempt := startProjection(t, f, s, r, "start")
	maximum := s.Custody.MaxStored
	s.Custody.MaxStored = 1
	result, err := s.WorkProjection(f.ctx, f.scope, "quota-failure", attempt)
	if err != nil {
		t.Fatal(err)
	}
	failed := projectionIntentRow(t, result)
	if failed.State != "failed" || failed.FileID != "" || bytes.Contains(failed.Result, []byte("output_sha256")) {
		t.Fatal("failed quota attempt advertised output")
	}
	s.Custody.MaxStored = maximum
	_, second := startProjection(t, f, s, failed, "retry")
	if second.Number != 2 || second.WorkerID == running.WorkerID {
		t.Fatal("retry did not fence old worker")
	}
	if _, err = s.WorkProjection(f.ctx, f.scope, "stale-worker", attempt); !errors.Is(err, store.ErrState) {
		t.Fatal("old worker completed new attempt", err)
	}
	replay, err := s.WorkProjection(f.ctx, f.scope, "quota-failure", attempt)
	if err != nil || !replay.Replayed || projectionIntentRow(t, replay).State != "failed" {
		t.Fatal("failure replay reinterpreted as retry", err)
	}
	completed, err := s.WorkProjection(f.ctx, f.scope, "retry-work", second)
	if err != nil || projectionIntentRow(t, completed).State != "completed" {
		t.Fatal("new authorized attempt did not complete", err)
	}
}

func TestProjectionActualRuntimeRejectsDefinitionAndTransitionForgery(t *testing.T) {
	f, s, r := approvedProjection(t)
	tx, err := s.Custody.DB.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	forged := *r
	forged.Revision++
	forged.State = "completed"
	if err = tx.SaveRecordProjection(f.ctx, &forged, r.Revision); err == nil {
		t.Fatal("runtime forged completion without running worker or held output")
	}
	tx.Tx.Rollback(f.ctx)
	tx, err = s.Custody.DB.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	d, err := decodeProjection(r)
	if err != nil {
		t.Fatal(err)
	}
	d.Plan.Context.Authority++
	forged = *r
	forged.Revision++
	forged.Definition, forged.Hash, _ = canonical(d)
	if err = tx.SaveRecordProjection(f.ctx, &forged, r.Revision); err == nil {
		t.Fatal("runtime rewrote approved bindings")
	}
	tx.Tx.Rollback(f.ctx)
	if _, err = s.DecideProjection(f.ctx, f.scope, r.ID, "cancel", PolicyRecheckDecision{Operation: "cancel", Hash: r.Hash, Revision: r.Revision}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.StartProjection(f.ctx, f.scope, r.ID, "cancelled-start", ProjectionStartDecision{Hash: r.Hash, Revision: r.Revision + 1}); !errors.Is(err, store.ErrState) {
		t.Fatal("cancelled proposal started", err)
	}
}
