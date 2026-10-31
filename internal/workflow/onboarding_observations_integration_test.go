//go:build integration

package workflow

import (
	"bytes"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/jackc/pgx/v5/pgconn"
)

func observationFixture(t *testing.T) (*fixture, OnboardingProductionResult, OnboardingObservationSelection) {
	t.Helper()
	f, run, _ := prepublicationFixture(t, "publishing")
	tx, err := f.s.Custody.DB.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	steps, err := tx.WorkflowSteps(f.ctx, run.Run.ID)
	if err != nil {
		t.Fatal(err)
	}
	d, err := tx.Delivery(f.ctx, steps[0].DeliveryID, true)
	if err != nil {
		t.Fatal(err)
	}
	prior := d.Revision
	d.Revision++
	d.State = "ambiguous"
	d.LeaseOwner = ""
	d.LeaseUntil = nil
	d.Observation = json.RawMessage(`{"code":"publication_outcome_uncertain"}`)
	if err = tx.SaveDelivery(f.ctx, d, prior); err != nil {
		t.Fatal(err)
	}
	test, err := tx.OnboardingTest(f.ctx, run.Dispatch.Definition.TestID)
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.Tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	return f, run, OnboardingObservationSelection{SourceRunID: run.Run.ID, SourceHash: run.Dispatch.Hash, ProbeID: test.Definition.Probe.ID, FileID: f.file.ID, Authority: 1}
}
func proposeObservation(t *testing.T, f *fixture, r OnboardingObservationSelection, key string) (*OnboardingObservationPreview, store.OnboardingObservationSummary, *Result) {
	t.Helper()
	p, err := f.s.PreviewOnboardingObservation(f.ctx, f.scope, r)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := f.s.ProposeOnboardingObservation(f.ctx, f.scope, key, OnboardingObservationProposal{Definition: p.Definition})
	if err != nil {
		t.Fatal(err)
	}
	var result OnboardingObservationReceipt
	if json.Unmarshal(saved.Resource, &result) != nil || result.Kind != "onboarding_observation" {
		t.Fatal("observation receipt")
	}
	return p, result.Observation, saved
}
func approveObservation(t *testing.T, f *fixture, o store.OnboardingObservationSummary) store.OnboardingObservationSummary {
	t.Helper()
	result, err := f.s.DecideOnboardingObservation(f.ctx, f.scope, o.ID, "approve", "approve-"+o.ID, Decision{Hash: o.Hash, Revision: o.Revision})
	if err != nil {
		t.Fatal(err)
	}
	var saved OnboardingObservationReceipt
	if json.Unmarshal(result.Resource, &saved) != nil {
		t.Fatal("approval receipt")
	}
	return saved.Observation
}
func claimFixtureObservation(t *testing.T, f *fixture, id string) *store.OnboardingObservation {
	t.Helper()
	tx, err := f.s.Custody.DB.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	o, err := tx.OnboardingObservation(f.ctx, id, true)
	if err != nil {
		t.Fatal(err)
	}
	now, err := tx.DatabaseTime(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	until := now.Add(30 * time.Second)
	o.State = "running"
	o.Revision = 3
	o.WorkerKey = "fixture-read-only-work"
	o.Owner = secure.NewID()
	o.StartedAt = &now
	o.LeaseUntil = &until
	o.Result = observationResult("observing")
	if err = tx.SaveOnboardingObservation(f.ctx, o, 2); err != nil {
		t.Fatal(err)
	}
	if err = tx.Tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	return o
}
func finishFixtureObservation(t *testing.T, f *fixture, o *store.OnboardingObservation) {
	t.Helper()
	tx, err := f.s.Custody.DB.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	now, err := tx.DatabaseTime(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	o.State = "succeeded"
	o.Revision = 4
	o.CompletedAt = &now
	o.Result = observationResult("remote_file_integrity_observed")
	o.Result.Integrity = true
	o.Result.Reconciled = true
	o.Result.SHA256 = o.Definition.Wire.SHA256
	o.Result.Size = o.Definition.Wire.Size
	if err = tx.SaveOnboardingObservation(f.ctx, o, 3); err != nil {
		t.Fatal(err)
	}
	if err = tx.Tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
}
func TestOnboardingObservationApprovalAndRecoveredOutcomePreserveOriginal(t *testing.T) {
	f, original, r := observationFixture(t)
	p, o, first := proposeObservation(t, f, r, "observe-original")
	if p.ExternalContact || p.ResendAuthorized || p.Definition.Source.State != "ambiguous" || p.Definition.Wire.SHA256 != f.file.SHA256 {
		t.Fatal("preview invented outcome", p)
	}
	replay, err := f.s.ProposeOnboardingObservation(f.ctx, f.scope, "observe-original", OnboardingObservationProposal{Definition: p.Definition})
	if err != nil || !replay.Replayed || !bytes.Equal(first.Resource, replay.Resource) {
		t.Fatal("proposal replay", err)
	}
	if _, err = f.s.WorkOnboardingObservation(f.ctx, f.scope, o.ID, "unapproved", OnboardingProbeWorkRequest{Hash: o.Hash}); !errors.Is(err, store.ErrState) {
		t.Fatal("implicit observation approval", err)
	}
	o = approveObservation(t, f, o)
	claimed := claimFixtureObservation(t, f, o.ID)
	finishFixtureObservation(t, f, claimed)
	view, err := f.s.OnboardingProductionStatus(f.ctx, f.scope, original.Run.ID)
	if err != nil || view.Outcome == nil || view.Outcome.State != "integrity_confirmed" || view.Outcome.Observation.ID != o.ID || view.Status.Steps[0].State != "ambiguous" || view.Status.Run.Revision != original.Run.Revision || view.Dispatch.Hash != original.Dispatch.Hash {
		t.Fatal("original meaning changed or receipt lost", view, err)
	}
	read, err := f.s.WorkOnboardingObservation(f.ctx, f.scope, o.ID, claimed.WorkerKey, OnboardingProbeWorkRequest{Hash: o.Hash})
	if err != nil || read.Observation.State != "succeeded" || read.Observation.Result.Business != "unknown" || read.ResendAuthorized {
		t.Fatal("recorded work replay", read, err)
	}
}
func TestOnboardingObservationReceiptFailureRollsBackIntent(t *testing.T) {
	f, _, r := observationFixture(t)
	p, err := f.s.PreviewOnboardingObservation(f.ctx, f.scope, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.admin.Exec(f.ctx, `CREATE FUNCTION freightctl_observation_receipt_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture observation receipt unavailable';END $$;CREATE TRIGGER freightctl_observation_receipt_failure BEFORE INSERT ON workflow_receipts FOR EACH ROW EXECUTE FUNCTION freightctl_observation_receipt_failure()`); err != nil {
		t.Fatal(err)
	}
	_, err = f.s.ProposeOnboardingObservation(f.ctx, f.scope, "failed-observation", OnboardingObservationProposal{Definition: p.Definition})
	var pgerr *pgconn.PgError
	if !errors.As(err, &pgerr) || pgerr.Code != "P0001" || pgerr.Message != "fixture observation receipt unavailable" {
		t.Fatal("did not reach required receipt boundary", err)
	}
	var n int
	if err = f.admin.QueryRow(f.ctx, `SELECT count(*) FROM onboarding_observations`).Scan(&n); err != nil || n != 0 {
		t.Fatal("orphan observation", n, err)
	}
}
func TestOnboardingObservationConcurrentProposalAndImmutableSQL(t *testing.T) {
	f, _, r := observationFixture(t)
	p, err := f.s.PreviewOnboardingObservation(f.ctx, f.scope, r)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan *Result, 8)
	failures := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, e := f.s.ProposeOnboardingObservation(f.ctx, f.scope, "same-observation", OnboardingObservationProposal{Definition: p.Definition})
			if e != nil {
				failures <- e
			} else {
				results <- v
			}
		}()
	}
	wg.Wait()
	close(results)
	close(failures)
	for e := range failures {
		t.Fatal(e)
	}
	var first []byte
	for v := range results {
		if first == nil {
			first = v.Resource
		} else if !bytes.Equal(first, v.Resource) {
			t.Fatal("concurrent receipt changed")
		}
	}
	var receipt OnboardingObservationReceipt
	if json.Unmarshal(first, &receipt) != nil {
		t.Fatal("receipt")
	}
	tx, err := f.s.Custody.DB.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Tx.Exec(f.ctx, `UPDATE onboarding_observations SET definition=jsonb_set(definition,'{effect,path}','"/other"') WHERE observation_id=$1`, receipt.Observation.ID)
	_ = tx.Tx.Rollback(f.ctx)
	if err == nil {
		t.Fatal("immutable observation retargeted")
	}
	var n int
	if err = f.admin.QueryRow(f.ctx, `SELECT count(*) FROM onboarding_observations`).Scan(&n); err != nil || n != 1 {
		t.Fatal(n, err)
	}
}
func TestOnboardingObservationObserverRevocationBlocksWithoutReading(t *testing.T) {
	f, _, r := observationFixture(t)
	p, o, _ := proposeObservation(t, f, r, "revoke-observer")
	o = approveObservation(t, f, o)
	if _, err := f.s.RevokeConnection(f.ctx, f.scope, p.Definition.Observer.Connection.ID, p.Definition.Observer.Connection.Version, "revoke-observer-connection", Decision{Hash: p.Definition.Observer.Connection.Hash, Revision: 1}); err != nil {
		t.Fatal(err)
	}
	v, err := f.s.WorkOnboardingObservation(f.ctx, f.scope, o.ID, "blocked-observation", OnboardingProbeWorkRequest{Hash: o.Hash})
	if err != nil || v.Observation.State != "blocked" || v.Observation.Result.Integrity || v.Observation.StartedAt != nil {
		t.Fatal("revoked observer contacted", v, err)
	}
}
func TestOnboardingObservationExpiredWorkerNeverInventsReceiptOrRestarts(t *testing.T) {
	f, _, r := observationFixture(t)
	_, o, _ := proposeObservation(t, f, r, "lost-observer")
	o = approveObservation(t, f, o)
	claimed := claimFixtureObservation(t, f, o.ID)
	v, err := f.s.WorkOnboardingObservation(f.ctx, f.scope, o.ID, claimed.WorkerKey, OnboardingProbeWorkRequest{Hash: o.Hash})
	if err != nil || v.Observation.State != "running" {
		t.Fatal("live work replay", v, err)
	}
	deadline := time.Now().Add(35 * time.Second)
	for time.Now().Before(deadline) {
		var expired bool
		if err = f.admin.QueryRow(f.ctx, `SELECT lease_until<=clock_timestamp() FROM onboarding_observations WHERE observation_id=$1`, o.ID).Scan(&expired); err != nil {
			t.Fatal(err)
		}
		if expired {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	v, err = f.s.WorkOnboardingObservation(f.ctx, f.scope, o.ID, claimed.WorkerKey, OnboardingProbeWorkRequest{Hash: o.Hash})
	if err != nil || v.Observation.State != "expired" || v.Observation.Result.Integrity {
		t.Fatal("expired read fabricated success", v, err)
	}
	if _, err = f.s.WorkOnboardingObservation(f.ctx, f.scope, o.ID, "different-work", OnboardingProbeWorkRequest{Hash: o.Hash}); !errors.Is(err, store.ErrConflict) {
		t.Fatal("different work key replayed", err)
	}
}

func TestOnboardingObservationPrivateHistoryRedactionAndPermissionRemoval(t *testing.T) {
	f, _, r := observationFixture(t)
	p, o, _ := proposeObservation(t, f, r, "private-observation")
	o = approveObservation(t, f, o)
	peer := store.AccountCommand{Operation: "create", ID: secure.NewID(), CredentialHash: secure.Digest([]byte("synthetic observation manager")), Policy: &store.AccountPolicy{Label: "Observation permission manager", Root: "/", Permissions: append([]string{}, store.DefaultPermissions...)}}
	if _, err := f.s.Custody.DB.ChangeAccount(f.ctx, f.scope, "observation-peer", peer); err != nil {
		t.Fatal(err)
	}
	other := store.Scope{Tenant: f.scope.Tenant, Partner: f.scope.Partner, TokenHash: peer.CredentialHash}
	if _, err := f.s.OnboardingObservationStatus(f.ctx, other, o.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("another actor read observation", err)
	}
	page, err := f.s.ListOnboardingObservations(f.ctx, other, p.Definition.Observer.Plan.ID, "", 50)
	if err != nil || len(page.Observations) != 0 {
		t.Fatal("another actor listed observation", page, err)
	}
	events, err := f.s.Custody.DB.Events(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	redacted := 0
	for _, e := range events {
		if e.ResourceID == o.ID && (e.Kind == "OnboardingObservationChanged" || e.Kind == "WorkflowCommandCompleted") {
			if !bytes.Contains(e.Payload, []byte(`"redacted":true`)) {
				t.Fatal("observation audit leaked private evidence", e.Kind)
			}
			redacted++
		}
	}
	if redacted != 4 {
		t.Fatal("observation audit", redacted)
	}
	identity, err := f.s.Custody.DB.Identity(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	permissions := []string{}
	for _, p := range identity.Permissions {
		if p != "workflow_execute" {
			permissions = append(permissions, p)
		}
	}
	_, err = f.s.Custody.DB.ChangeAccount(f.ctx, other, "remove-observation-execution", store.AccountCommand{Operation: "update", ID: identity.Actor, ExpectedRevision: 1, Policy: &store.AccountPolicy{Label: "Observation review only", Root: "/", Permissions: permissions}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.WorkOnboardingObservation(f.ctx, f.scope, o.ID, "removed-observation-work", OnboardingProbeWorkRequest{Hash: o.Hash}); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("removed execution permission read receiver", err)
	}
}

func TestOnboardingObservationRecordedRecoveryDoesNotNeedWorkerCapacity(t *testing.T) {
	f, _, r := observationFixture(t)
	_, done, _ := proposeObservation(t, f, r, "completed-observation")
	done = approveObservation(t, f, done)
	claimed := claimFixtureObservation(t, f, done.ID)
	finishFixtureObservation(t, f, claimed)
	_, waiting, _ := proposeObservation(t, f, r, "waiting-observation")
	waiting = approveObservation(t, f, waiting)
	for i := 0; i < 2; i++ {
		_, release, err := f.s.Custody.DB.OnboardingObservationWorkerSlot(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer release()
	}
	if _, err := f.s.WorkOnboardingObservation(f.ctx, f.scope, waiting.ID, "capacity-limited-observation", OnboardingProbeWorkRequest{Hash: waiting.Hash}); !errors.Is(err, store.ErrLimit) {
		t.Fatal("unbounded observer capacity", err)
	}
	v, err := f.s.OnboardingObservationStatus(f.ctx, f.scope, waiting.ID)
	if err != nil || v.Observation.State != "approved" || v.Observation.StartedAt != nil {
		t.Fatal("capacity refusal changed approved work", v, err)
	}
	v, err = f.s.WorkOnboardingObservation(f.ctx, f.scope, done.ID, claimed.WorkerKey, OnboardingProbeWorkRequest{Hash: done.Hash})
	if err != nil || v.Observation.State != "succeeded" || v.ExternalContact {
		t.Fatal("recorded recovery spent a worker slot", v, err)
	}
}
