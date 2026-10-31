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
	"github.com/ctlplne/freightctl/internal/delivery"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/jackc/pgx/v5/pgconn"
)

// These event-bound coordinator fixtures isolate transaction/state guards.
// Their observations are seeded; only the native peer journey qualifies SFTP.
func completedReleaseFixture(t *testing.T, receipt string) (*fixture, store.OnboardingCommand, OnboardingReleaseSelection, OnboardingTestResult) {
	t.Helper()
	f, command, request := onboardingTestFixtureReceipt(t, receipt)
	_, _, result := testIntent(t, f, request, "release-test")
	tx, err := f.s.Custody.DB.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Tx.Rollback(f.ctx)
	steps, err := tx.WorkflowSteps(f.ctx, result.Run.ID)
	if err != nil || len(steps) != 1 {
		t.Fatal(steps, err)
	}
	d, err := tx.Delivery(f.ctx, steps[0].DeliveryID, true)
	if err != nil {
		t.Fatal(err)
	}
	now, err := tx.DatabaseTime(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	lease := now.Add(30 * time.Second)
	for _, state := range []string{"staging", "publishing", "succeeded"} {
		previous := d.Revision
		d.State = state
		d.Revision++
		if state == "staging" {
			d.Attempts++
			d.Fence++
			d.LeaseOwner = secure.NewID()
			d.LeaseUntil = &lease
		}
		if state == "succeeded" {
			d.LeaseOwner = ""
			d.LeaseUntil = nil
			d.Observation, _ = json.Marshal(map[string]any{"code": "remote_file_integrity_observed", "size_bytes": f.file.Size, "sha256": f.file.SHA256, "host_fingerprint": f.connection.HostFingerprint, "file_fsync_acknowledged": true, "reconciled": false, "business_acceptance": "unknown", "directory_power_loss_durability": "not established"})
		}
		if err = tx.SaveDelivery(f.ctx, d, previous); err != nil {
			t.Fatal(state, err)
		}
	}
	r := result.Run
	r.State = "succeeded"
	r.Reason = "all_integrity_receipts_observed"
	r.Revision++
	if err = tx.SaveWorkflowRun(f.ctx, r, 1); err != nil {
		t.Fatal(err)
	}
	if err = tx.Tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	return f, command, OnboardingReleaseSelection{Plan: request.Plan, TestIDs: []string{result.Test.ID}, Authority: 1}, result
}
func proposeRelease(t *testing.T, f *fixture, r OnboardingReleaseSelection, key string) (*OnboardingReleasePreview, store.OnboardingReleaseSummary, *Result) {
	t.Helper()
	preview, err := f.s.PreviewOnboardingRelease(f.ctx, f.scope, r)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := f.s.ProposeOnboardingRelease(f.ctx, f.scope, key, OnboardingReleaseProposal{Selection: r, Hash: preview.Hash})
	if err != nil {
		t.Fatal(err)
	}
	var result OnboardingReleaseResult
	if json.Unmarshal(saved.Resource, &result) != nil || result.Kind != "onboarding_release" {
		t.Fatal("receipt")
	}
	return preview, result.Release, saved
}
func decideRelease(t *testing.T, f *fixture, r store.OnboardingReleaseSummary, action string) store.OnboardingReleaseSummary {
	t.Helper()
	saved, err := f.s.DecideOnboardingRelease(f.ctx, f.scope, r.ID, action, action+"-"+r.ID+"-"+time.Now().Format("150405.000000000"), Decision{Hash: r.Hash, Revision: r.Revision})
	if err != nil {
		t.Fatal(action, err)
	}
	var result OnboardingReleaseResult
	if json.Unmarshal(saved.Resource, &result) != nil {
		t.Fatal("receipt")
	}
	return result.Release
}
func productionIntent(t *testing.T, f *fixture, r store.OnboardingReleaseSummary, requirement, file, key string) (*OnboardingProductionPreview, OnboardingProductionResult, *Result) {
	t.Helper()
	preview, err := f.s.PreviewOnboardingProduction(f.ctx, f.scope, r.ID, OnboardingProductionSelection{Decision: Decision{Hash: r.Hash, Revision: r.Revision}, RequirementID: requirement, FileID: file})
	if err != nil {
		t.Fatal(err)
	}
	saved, err := f.s.StartOnboardingProduction(f.ctx, f.scope, key, OnboardingProductionStart{Definition: preview.Definition})
	if err != nil {
		t.Fatal(err)
	}
	var result OnboardingProductionResult
	if json.Unmarshal(saved.Resource, &result) != nil || result.Kind != "onboarding_production" {
		t.Fatal("receipt")
	}
	return preview, result, saved
}
func TestOnboardingReleaseApprovalActivationSuspensionAndExactQueuedEpoch(t *testing.T) {
	f, _, selection, test := completedReleaseFixture(t, "integrity")
	preview, r, first := proposeRelease(t, f, selection, "release")
	replay, err := f.s.ProposeOnboardingRelease(f.ctx, f.scope, "release", OnboardingReleaseProposal{Selection: selection, Hash: preview.Hash})
	if err != nil || !replay.Replayed || !bytes.Equal(replay.Resource, first.Resource) {
		t.Fatal("proposal replay", err)
	}
	if _, err = f.s.DecideOnboardingRelease(f.ctx, f.scope, r.ID, "activate", "skip-approval", Decision{Hash: r.Hash, Revision: r.Revision}); !errors.Is(err, store.ErrState) {
		t.Fatal("activation without approval", err)
	}
	r = decideRelease(t, f, r, "approve")
	if r.ApprovedRevision != 2 {
		t.Fatal(r)
	}
	if _, err = f.s.PreviewOnboardingProduction(f.ctx, f.scope, r.ID, OnboardingProductionSelection{Decision: Decision{Hash: r.Hash, Revision: r.Revision}, RequirementID: test.Test.Definition.RequirementID, FileID: f.file.ID}); !errors.Is(err, store.ErrState) {
		t.Fatal("approval implicitly activated", err)
	}
	r = decideRelease(t, f, r, "activate")
	status, err := f.s.OnboardingReleaseStatus(f.ctx, f.scope, r.ID)
	if err != nil || !status.ProductionActive {
		t.Fatal(status, err)
	}
	source, _, err := f.s.Custody.Accept(f.ctx, f.scope, "production-source", 3, secure.Digest([]byte("xyz")), bytes.NewBufferString("xyz"))
	if err != nil {
		t.Fatal(err)
	}
	p, production, saved := productionIntent(t, f, r, test.Test.Definition.RequirementID, source.ID, "production")
	steps, err := f.s.Status(f.ctx, f.scope, production.Run.ID)
	if err != nil || steps.Steps[0].Attempts != 0 {
		t.Fatal(steps, err)
	}
	if err = testStagingTransition(t, f, steps.Steps[0].DeliveryID); err != nil {
		t.Fatal("current activation positive control", err)
	}
	r = decideRelease(t, f, r, "suspend")
	status, err = f.s.OnboardingReleaseStatus(f.ctx, f.scope, r.ID)
	if err != nil || status.ProductionActive || !status.Current {
		t.Fatal(status, err)
	}
	if _, err = f.s.Work(f.ctx, f.scope, production.Run.ID, "suspended-work"); !errors.Is(err, store.ErrState) {
		t.Fatal("suspended ordinary worker", err)
	}
	direct := &delivery.Service{Custody: f.s.Custody}
	if _, err = direct.Work(f.ctx, f.scope, steps.Steps[0].DeliveryID); !errors.Is(err, store.ErrState) {
		t.Fatal("suspended direct worker", err)
	}
	var pgerr *pgconn.PgError
	if err = testStagingTransition(t, f, steps.Steps[0].DeliveryID); !errors.As(err, &pgerr) || pgerr.Code != "23514" || pgerr.Message != "production activation changed" {
		t.Fatal("suspended SQL effect", err)
	}
	repeated, err := f.s.StartOnboardingProduction(f.ctx, f.scope, "production", OnboardingProductionStart{Definition: p.Definition})
	if err != nil || !repeated.Replayed || !bytes.Equal(repeated.Resource, saved.Resource) {
		t.Fatal("historical dispatch receipt", err)
	}
	r = decideRelease(t, f, r, "activate")
	old, err := f.s.Status(f.ctx, f.scope, production.Run.ID)
	if err != nil || old.ObservedState != "attention" || old.Steps[0].Attempts != 0 {
		t.Fatal("old activation epoch revived", old, err)
	}
	_, next, _ := productionIntent(t, f, r, test.Test.Definition.RequirementID, source.ID, "new-production")
	fresh, err := f.s.Status(f.ctx, f.scope, next.Run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err = testStagingTransition(t, f, fresh.Steps[0].DeliveryID); err != nil {
		t.Fatal("fresh activation control", err)
	}
}
func TestOnboardingReleaseRequiresAllExactSuccessfulEvidenceAndCurrentPlan(t *testing.T) {
	f, command, selection, _ := completedReleaseFixture(t, "integrity")
	preview, r, _ := proposeRelease(t, f, selection, "release")
	bad := selection
	bad.TestIDs = append(bad.TestIDs, bad.TestIDs[0])
	if _, err := f.s.PreviewOnboardingRelease(f.ctx, f.scope, bad); !errors.Is(err, ErrInput) {
		t.Fatal("duplicate test", err)
	}
	command.ExpectedVersion = 1
	command.Definition.Requirements = append(command.Definition.Requirements, store.OnboardingRequirement{ID: secure.NewID(), Name: "Second required exchange", ContactID: command.Definition.Contacts[0].ID, Direction: "send", Protocol: "sftp", Receipt: "integrity"})
	current, err := f.s.Custody.DB.SaveOnboarding(f.ctx, f.scope, "plan-v2", command)
	if err != nil {
		t.Fatal(err)
	}
	bad = selection
	bad.Plan = store.OnboardingReference{ID: current.Plan.ID, Version: current.Plan.Version, Hash: current.Plan.Hash}
	if _, err = f.s.PreviewOnboardingRelease(f.ctx, f.scope, bad); !errors.Is(err, ErrInput) {
		t.Fatal("omitted requirement", err)
	}
	if _, err = f.s.DecideOnboardingRelease(f.ctx, f.scope, r.ID, "approve", "stale-approve", Decision{Hash: preview.Hash, Revision: 1}); !errors.Is(err, store.ErrRevision) {
		t.Fatal("stale release approved", err)
	}
	view, err := f.s.OnboardingReleaseStatus(f.ctx, f.scope, r.ID)
	if err != nil || view.Current || view.ProductionActive {
		t.Fatal(view, err)
	}
	// Stale security context must not prevent a currently authorized operator
	// from revoking the historical release.
	r = decideRelease(t, f, r, "revoke")
	if r.State != "revoked" {
		t.Fatal(r)
	}
}
func TestOnboardingReleaseIntegrityCannotSatisfyBusinessReceipt(t *testing.T) {
	f, _, selection, _ := completedReleaseFixture(t, "business")
	if _, err := f.s.PreviewOnboardingRelease(f.ctx, f.scope, selection); !errors.Is(err, store.ErrState) {
		t.Fatal("invented downstream business acceptance", err)
	}
}
func TestOnboardingReleaseConcurrentReplayAndImmutableDefinition(t *testing.T) {
	f, _, selection, _ := completedReleaseFixture(t, "integrity")
	p, err := f.s.PreviewOnboardingRelease(f.ctx, f.scope, selection)
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
			r, e := f.s.ProposeOnboardingRelease(f.ctx, f.scope, "one-release", OnboardingReleaseProposal{Selection: selection, Hash: p.Hash})
			if e != nil {
				failures <- e
			} else {
				results <- r
			}
		}()
	}
	group.Wait()
	close(results)
	close(failures)
	for e := range failures {
		t.Fatal(e)
	}
	created := 0
	var data []byte
	for r := range results {
		if !r.Replayed {
			created++
		}
		if data == nil {
			data = r.Resource
		} else if !bytes.Equal(data, r.Resource) {
			t.Fatal("concurrent receipt differs")
		}
	}
	if created != 1 {
		t.Fatal("duplicate releases", created)
	}
	for _, q := range []string{`UPDATE onboarding_releases SET definition_hash=repeat('0',64)`, `DELETE FROM onboarding_releases`} {
		var pgerr *pgconn.PgError
		if _, err = f.admin.Exec(f.ctx, q); !errors.As(err, &pgerr) || pgerr.Code != "23514" {
			t.Fatal("unjournaled definition mutation", err)
		}
	}
}

func TestOnboardingReleaseAndDispatchReceiptFailuresRollbackAllEffects(t *testing.T) {
	f, _, selection, test := completedReleaseFixture(t, "integrity")
	_, r, _ := proposeRelease(t, f, selection, "release")
	r = decideRelease(t, f, r, "approve")
	r = decideRelease(t, f, r, "activate")
	preview, err := f.s.PreviewOnboardingProduction(f.ctx, f.scope, r.ID, OnboardingProductionSelection{Decision: Decision{Hash: r.Hash, Revision: r.Revision}, RequirementID: test.Test.Definition.RequirementID, FileID: f.file.ID})
	if err != nil {
		t.Fatal(err)
	}
	var eventsBefore int
	if err = f.admin.QueryRow(f.ctx, `SELECT count(*) FROM events`).Scan(&eventsBefore); err != nil {
		t.Fatal(err)
	}
	if _, err = f.admin.Exec(f.ctx, `CREATE FUNCTION freightctl_release_receipt_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture release receipt unavailable';END $$;CREATE TRIGGER freightctl_release_receipt_failure BEFORE INSERT ON workflow_receipts FOR EACH ROW EXECUTE FUNCTION freightctl_release_receipt_failure()`); err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.StartOnboardingProduction(f.ctx, f.scope, "failed-production", OnboardingProductionStart{Definition: preview.Definition}); err == nil {
		t.Fatal("failed production receipt acknowledged")
	}
	if _, err = f.s.DecideOnboardingRelease(f.ctx, f.scope, r.ID, "suspend", "failed-suspend", Decision{Hash: r.Hash, Revision: r.Revision}); err == nil {
		t.Fatal("failed lifecycle receipt acknowledged")
	}
	var eventsAfter, runs, dispatches int
	if err = f.admin.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM events),(SELECT count(*) FROM workflow_runs),(SELECT count(*) FROM onboarding_dispatches)`).Scan(&eventsAfter, &runs, &dispatches); err != nil || eventsAfter != eventsBefore || runs != 1 || dispatches != 0 {
		t.Fatal("partial effects survived receipt failure", eventsBefore, eventsAfter, runs, dispatches, err)
	}
	view, err := f.s.OnboardingReleaseStatus(f.ctx, f.scope, r.ID)
	if err != nil || view.Release.Revision != 3 || !view.ProductionActive {
		t.Fatal("lifecycle rollback", view, err)
	}
}
func TestOnboardingReleasePrivateHistoryPermissionRemovalAndRedactedAudit(t *testing.T) {
	f, _, selection, test := completedReleaseFixture(t, "integrity")
	_, r, _ := proposeRelease(t, f, selection, "release")
	r = decideRelease(t, f, r, "approve")
	r = decideRelease(t, f, r, "activate")
	_, production, _ := productionIntent(t, f, r, test.Test.Definition.RequirementID, f.file.ID, "production")
	identity, err := f.s.Custody.DB.Identity(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	peer := store.AccountCommand{Operation: "create", ID: secure.NewID(), CredentialHash: secure.Digest([]byte("synthetic release permission manager")), Policy: &store.AccountPolicy{Label: "Release scope observer", Root: "/", Permissions: append([]string{}, store.DefaultPermissions...)}}
	if _, err = f.s.Custody.DB.ChangeAccount(f.ctx, f.scope, "release-peer", peer); err != nil {
		t.Fatal(err)
	}
	other := store.Scope{Tenant: f.scope.Tenant, Partner: f.scope.Partner, TokenHash: peer.CredentialHash}
	page, err := f.s.ListOnboardingReleases(f.ctx, other, r.Plan.ID, "", 50)
	if err != nil || len(page.Releases) != 0 {
		t.Fatal("other actor private list", page, err)
	}
	if _, err = f.s.OnboardingReleaseStatus(f.ctx, other, r.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("other actor read release", err)
	}
	if _, err = f.s.OnboardingProductionStatus(f.ctx, other, production.Run.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("other actor read dispatch", err)
	}
	history, err := f.s.ListOnboardingProduction(f.ctx, f.scope, r.ID, "", 50)
	if err != nil || len(history.Dispatches) != 1 || history.Dispatches[0].ID != production.Run.ID {
		t.Fatal(history, err)
	}
	status, err := f.s.OnboardingProductionStatus(f.ctx, f.scope, production.Run.ID)
	if err != nil || !status.Current || status.Status.Steps[0].Attempts != 0 {
		t.Fatal(status, err)
	}
	events, err := f.s.Custody.DB.Events(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	redacted := 0
	for _, e := range events {
		if e.ResourceID == r.ID || e.Kind == "OnboardingProductionQueued" || (e.ResourceID == production.Run.ID && e.Kind == "WorkflowCommandCompleted") {
			if (e.Kind == "OnboardingReleaseChanged" || e.Kind == "WorkflowCommandCompleted" || e.Kind == "OnboardingProductionQueued") && !bytes.Contains(e.Payload, []byte(`"redacted":true`)) {
				t.Fatal("private release payload in ordinary audit", e.Kind)
			}
			redacted++
		}
	}
	if redacted < 7 {
		t.Fatal("missing release audit", redacted)
	}
	permissions := []string{}
	for _, grant := range store.DefaultPermissions {
		if grant != "workflow_approve" {
			permissions = append(permissions, grant)
		}
	}
	if _, err = f.s.Custody.DB.ChangeAccount(f.ctx, other, "remove-release-approval", store.AccountCommand{Operation: "update", ID: identity.Actor, ExpectedRevision: 1, Policy: &store.AccountPolicy{Label: "Release manager without approval", Root: "/", Permissions: permissions}}); err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.DecideOnboardingRelease(f.ctx, f.scope, r.ID, "revoke", "missing-approve", Decision{Hash: r.Hash, Revision: r.Revision}); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("missing approval grant", err)
	}
	r = decideRelease(t, f, r, "suspend")
	if r.State != "suspended" {
		t.Fatal(r)
	}
}
