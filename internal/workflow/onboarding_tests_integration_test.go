//go:build integration

package workflow

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/delivery"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/jackc/pgx/v5/pgconn"
)

// Seed coordinator observations through the real event-bound store to isolate
// transaction/authorization guards. This fixture qualifies no SFTP peer; the
// separate native journey must use actual successful network probes.
func onboardingTestFixture(t *testing.T) (*fixture, store.OnboardingCommand, OnboardingTestPreviewRequest) {
	return onboardingTestFixtureReceipt(t, "business")
}
func onboardingTestFixtureReceipt(t *testing.T, receipt string) (*fixture, store.OnboardingCommand, OnboardingTestPreviewRequest) {
	t.Helper()
	f := setup(t)
	command, r := probePlanReceipt(t, f, receipt)
	p := startProbe(t, f, "test-probe", r)
	tx, err := f.s.Custody.DB.BeginOnboardingManagement(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Tx.Rollback(f.ctx)
	now, err := tx.DatabaseTime(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	lease := now.Add(20 * time.Second)
	p.State = "running"
	p.Revision = 2
	p.WorkerKey = "fixture-observer"
	p.Owner = secure.NewID()
	p.StartedAt = &now
	p.LeaseUntil = &lease
	p.Observation = store.OnboardingProbeObservation{Code: "probing"}
	if err = tx.SaveOnboardingProbe(f.ctx, &p, 1); err != nil {
		t.Fatal(err)
	}
	complete, err := tx.DatabaseTime(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	p.State = "succeeded"
	p.Revision = 3
	p.CompletedAt = &complete
	p.Observation = store.OnboardingProbeObservation{Code: "connectivity_verified", SSH: true, SFTP: true, Extensions: true, Directory: true}
	if err = tx.SaveOnboardingProbe(f.ctx, &p, 2); err != nil {
		t.Fatal(err)
	}
	if err = tx.Tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	d := f.definition()
	d.Steps = d.Steps[:1]
	wf := f.approved(t, d)
	return f, command, OnboardingTestPreviewRequest{Plan: r.Plan, RequirementID: r.RequirementID, ProbeID: p.ID, Workflow: Reference{ID: wf.ID, Version: wf.Version, Hash: wf.Hash}, FileID: f.file.ID, ExpectedAuthority: 1}
}
func testIntent(t *testing.T, f *fixture, r OnboardingTestPreviewRequest, key string) (*OnboardingTestPreview, *Result, OnboardingTestResult) {
	t.Helper()
	p, err := f.s.PreviewOnboardingTest(f.ctx, f.scope, r)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := f.s.StartOnboardingTest(f.ctx, f.scope, key, OnboardingTestStartRequest{Definition: p.Definition})
	if err != nil {
		t.Fatal(err)
	}
	var result OnboardingTestResult
	if json.Unmarshal(saved.Resource, &result) != nil {
		t.Fatal("test intent response")
	}
	return p, saved, result
}
func TestOnboardingTestAtomicIntentReceiptAndPrivateLineage(t *testing.T) {
	f, _, r := onboardingTestFixture(t)
	var before, after int
	if err := f.admin.QueryRow(f.ctx, `SELECT count(*) FROM events`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	preview, err := f.s.PreviewOnboardingTest(f.ctx, f.scope, r)
	if err != nil || preview.ExternalContact || preview.ProductionActive {
		t.Fatal(preview, err)
	}
	if err = f.admin.QueryRow(f.ctx, `SELECT count(*) FROM events`).Scan(&after); err != nil || before != after {
		t.Fatal("preview mutated domain", err)
	}
	_, saved, result := testIntent(t, f, r, "intent")
	if result.Kind != "onboarding_test" || result.Test.ID != result.Run.ID || result.Run.State != "queued" || result.Test.Hash != preview.Hash || result.Test.Definition.File != *f.file {
		t.Fatal("unbound intent", result)
	}
	repeated, err := f.s.StartOnboardingTest(f.ctx, f.scope, "intent", OnboardingTestStartRequest{Definition: preview.Definition})
	if err != nil || !repeated.Replayed || !bytes.Equal(repeated.Resource, saved.Resource) {
		t.Fatal("exact receipt replay", err)
	}
	status, err := f.s.OnboardingTestStatus(f.ctx, f.scope, result.Test.ID)
	if err != nil || !status.Current || status.ProductionActive || len(status.Status.Steps) != 1 || status.Status.Steps[0].State != "queued" || status.Status.Steps[0].Attempts != 0 {
		t.Fatal(status, err)
	}
	review, err := f.s.ReviewOnboardingTest(f.ctx, f.scope, result.Test.ID)
	if err != nil || review.Ready || review.Reason != "exchange_not_succeeded" {
		t.Fatal("unexecuted intent invented evidence", review, err)
	}
	changed := preview.Definition
	changed.File.SHA256 = secure.Digest([]byte("changed"))
	if _, err = f.s.StartOnboardingTest(f.ctx, f.scope, "intent", OnboardingTestStartRequest{Definition: changed}); !errors.Is(err, store.ErrConflict) {
		t.Fatal("changed receipt meaning", err)
	}
	if _, err = f.s.StartOnboardingTest(f.ctx, f.scope, "changed", OnboardingTestStartRequest{Definition: changed}); !errors.Is(err, store.ErrRevision) {
		t.Fatal("changed reviewed source", err)
	}
	events, err := f.s.Custody.DB.Events(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	redacted := 0
	for _, e := range events {
		if (e.Kind == "OnboardingTestRecorded" || e.Kind == "WorkflowCommandCompleted") && e.ResourceID == result.Test.ID {
			var payload map[string]any
			_ = json.Unmarshal(e.Payload, &payload)
			if payload["redacted"] != true || bytes.Contains(e.Payload, []byte(result.Test.Definition.RequirementID)) {
				t.Fatal("private test lineage in ordinary feed")
			}
			redacted++
		}
	}
	if redacted != 2 {
		t.Fatal("missing redacted events", redacted)
	}
}
func testStagingTransition(t *testing.T, f *fixture, deliveryID string) error {
	t.Helper()
	tx, err := f.s.Custody.DB.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Tx.Rollback(f.ctx)
	intent, err := tx.Delivery(f.ctx, deliveryID, true)
	if err != nil {
		t.Fatal(err)
	}
	now, err := tx.DatabaseTime(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	until := now.Add(30 * time.Second)
	previous := intent.Revision
	intent.State = "staging"
	intent.Revision++
	intent.Attempts++
	intent.Fence++
	intent.LeaseOwner = secure.NewID()
	intent.LeaseUntil = &until
	return tx.SaveDelivery(f.ctx, intent, previous)
}
func TestOnboardingTestPlanDriftStopsOrdinaryAndDirectWorkers(t *testing.T) {
	f, command, r := onboardingTestFixture(t)
	preview, saved, result := testIntent(t, f, r, "drift")
	status, err := f.s.Status(f.ctx, f.scope, result.Run.ID)
	if err != nil {
		t.Fatal(err)
	}
	intentID := status.Steps[0].DeliveryID
	if err = testStagingTransition(t, f, intentID); err != nil {
		t.Fatal("positive control under current binding", err)
	}
	command.ExpectedVersion = 1
	command.Definition.Name = "Updated requirement review"
	if _, err = f.s.Custody.DB.SaveOnboarding(f.ctx, f.scope, "plan-v2", command); err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.Work(f.ctx, f.scope, result.Run.ID, "drift-work"); !errors.Is(err, store.ErrState) {
		t.Fatal("ordinary worker crossed changed requirement", err)
	}
	if _, err = (&delivery.Service{Custody: f.s.Custody}).Work(f.ctx, f.scope, intentID); !errors.Is(err, store.ErrState) {
		t.Fatal("direct delivery worker bypassed test", err)
	}
	var pgerr *pgconn.PgError
	if err = testStagingTransition(t, f, intentID); !errors.As(err, &pgerr) || pgerr.Code != "23514" || pgerr.Message != "onboarding test bindings changed" {
		t.Fatal("SQL effect guard bypass", err)
	}
	historical, err := f.s.StartOnboardingTest(f.ctx, f.scope, "drift", OnboardingTestStartRequest{Definition: preview.Definition})
	if err != nil || !historical.Replayed || !bytes.Equal(historical.Resource, saved.Resource) {
		t.Fatal("historical receipt queued work or changed meaning", err)
	}
	view, err := f.s.OnboardingTestStatus(f.ctx, f.scope, result.Test.ID)
	if err != nil || view.Current || view.Status.ObservedState != "attention" || view.Status.ObservedReason != "onboarding_binding_changed" || view.Status.Steps[0].Attempts != 0 {
		t.Fatal("changed binding hidden", view, err)
	}
}
func TestOnboardingTestReceiptFailureRollsBackAllEffects(t *testing.T) {
	f, _, r := onboardingTestFixture(t)
	p, err := f.s.PreviewOnboardingTest(f.ctx, f.scope, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.admin.Exec(f.ctx, `CREATE FUNCTION freightctl_test_receipt_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture receipt unavailable'; END $$;CREATE TRIGGER freightctl_test_receipt_failure BEFORE INSERT ON workflow_receipts FOR EACH ROW EXECUTE FUNCTION freightctl_test_receipt_failure()`); err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.StartOnboardingTest(f.ctx, f.scope, "rollback", OnboardingTestStartRequest{Definition: p.Definition}); err == nil {
		t.Fatal("receipt failure ignored")
	}
	for _, table := range []string{"onboarding_tests", "workflow_runs", "workflow_steps", "delivery_intents"} {
		var count int
		if err = f.admin.QueryRow(f.ctx, `SELECT count(*) FROM `+table).Scan(&count); err != nil || count != 0 {
			t.Fatal("partial intent survived rollback", table, count, err)
		}
	}
}

func TestOnboardingTestConcurrentReplayPrivacyAndImmutableSQL(t *testing.T) {
	f, _, r := onboardingTestFixture(t)
	p, err := f.s.PreviewOnboardingTest(f.ctx, f.scope, r)
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	results := make(chan *Result, 8)
	failures := make(chan error, 8)
	for i := 0; i < 8; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			v, e := f.s.StartOnboardingTest(f.ctx, f.scope, "concurrent", OnboardingTestStartRequest{Definition: p.Definition})
			if e != nil {
				failures <- e
			} else {
				results <- v
			}
		}()
	}
	group.Wait()
	close(results)
	close(failures)
	for e := range failures {
		t.Fatal(e)
	}
	var first []byte
	created := 0
	var saved OnboardingTestResult
	for v := range results {
		if !v.Replayed {
			created++
		}
		if first == nil {
			first = v.Resource
		} else if !bytes.Equal(first, v.Resource) {
			t.Fatal("concurrent replay differs")
		}
		if json.Unmarshal(v.Resource, &saved) != nil {
			t.Fatal("response")
		}
	}
	if created != 1 {
		t.Fatal("duplicate creation", created)
	}
	for _, q := range []string{`UPDATE onboarding_tests SET definition_hash=definition_hash`, `DELETE FROM onboarding_tests`} {
		var pgerr *pgconn.PgError
		if _, e := f.admin.Exec(f.ctx, q); !errors.As(e, &pgerr) || pgerr.Code != "23514" {
			t.Fatal("immutable SQL lineage changed", e)
		}
	}
	token := filepath.Join(t.TempDir(), "other.token")
	if err = secure.WriteToken(token); err != nil {
		t.Fatal(err)
	}
	if err = store.Provision(f.ctx, f.adminPath, f.scope.Tenant, f.scope.Partner, token); err != nil {
		t.Fatal(err)
	}
	secret, err := secure.ReadSecret(token, 64)
	if err != nil {
		t.Fatal(err)
	}
	other := store.Scope{Tenant: f.scope.Tenant, Partner: f.scope.Partner, TokenHash: secure.Digest(secret.Bytes)}
	secret.Close()
	if _, err = f.s.OnboardingTestStatus(f.ctx, other, saved.Test.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("other actor read test", err)
	}
	page, err := f.s.ListOnboardingTests(f.ctx, other, r.Plan.ID, "", 50)
	if err != nil || len(page.Tests) != 0 {
		t.Fatal("other actor listed private lineage", page, err)
	}
	if _, err = f.s.StartOnboardingTest(f.ctx, other, "copy-authority", OnboardingTestStartRequest{Definition: p.Definition}); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("another actor borrowed probe/workflow", err)
	}
}
