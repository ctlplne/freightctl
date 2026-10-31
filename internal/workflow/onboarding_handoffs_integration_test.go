//go:build integration

package workflow

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/delivery"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/jackc/pgx/v5/pgconn"
)

func handoffFixture(t *testing.T) (*fixture, store.OnboardingReleaseSummary, OnboardingProductionResult, OnboardingHandoffSelection) {
	t.Helper()
	f, _, selection, test := completedReleaseFixture(t, "integrity")
	_, r, _ := proposeRelease(t, f, selection, "release")
	r = decideRelease(t, f, r, "approve")
	r = decideRelease(t, f, r, "activate")
	_, production, _ := productionIntent(t, f, r, test.Test.Definition.RequirementID, f.file.ID, "original-production")
	// A prepared dispatcher still has zero delivery attempts. It must be fenced
	// after replacement just like a worker that had not yet read the queue.
	if _, _, err := f.s.prepare(f.ctx, f.scope, production.Run.ID, "prepared-old-worker"); err != nil {
		t.Fatal(err)
	}
	r = decideRelease(t, f, r, "suspend")
	r = decideRelease(t, f, r, "activate")
	return f, r, production, OnboardingHandoffSelection{SourceRunID: production.Run.ID, SourceHash: production.Dispatch.Hash, Target: store.OnboardingActivationReference{ID: r.ID, Revision: r.Revision, Hash: r.Hash}, FileID: f.file.ID}
}
func proposeHandoff(t *testing.T, f *fixture, r OnboardingHandoffSelection, key string) (*OnboardingHandoffPreview, store.OnboardingHandoffSummary, *Result) {
	t.Helper()
	p, err := f.s.PreviewOnboardingHandoff(f.ctx, f.scope, r)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := f.s.ProposeOnboardingHandoff(f.ctx, f.scope, key, OnboardingHandoffProposal{Definition: p.Definition})
	if err != nil {
		t.Fatal(err)
	}
	var result OnboardingHandoffResult
	if json.Unmarshal(saved.Resource, &result) != nil || result.Kind != "onboarding_handoff" {
		t.Fatal("handoff receipt")
	}
	return p, result.Handoff, saved
}
func decideHandoff(t *testing.T, f *fixture, h store.OnboardingHandoffSummary, action, key string) (store.OnboardingHandoffSummary, *Result) {
	t.Helper()
	saved, err := f.s.DecideOnboardingHandoff(f.ctx, f.scope, h.ID, action, key, Decision{Hash: h.Hash, Revision: h.Revision})
	if err != nil {
		t.Fatal(action, err)
	}
	var result OnboardingHandoffResult
	if json.Unmarshal(saved.Resource, &result) != nil {
		t.Fatal("handoff result")
	}
	return result.Handoff, saved
}
func TestOnboardingHandoffPreservesSourceAndFencesPreparedWorker(t *testing.T) {
	f, _, original, r := handoffFixture(t)
	var before int
	if err := f.admin.QueryRow(f.ctx, `SELECT count(*) FROM events`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	p, err := f.s.PreviewOnboardingHandoff(f.ctx, f.scope, r)
	if err != nil || p.ExternalContact || p.Definition.Source.Attempts != 0 || p.Definition.Source.RunRevision != 2 {
		t.Fatal(p, err)
	}
	var after int
	if err = f.admin.QueryRow(f.ctx, `SELECT count(*) FROM events`).Scan(&after); err != nil || before != after {
		t.Fatal("preview changed domain state", before, after, err)
	}
	p, h, first := proposeHandoff(t, f, r, "handoff")
	repeated, err := f.s.ProposeOnboardingHandoff(f.ctx, f.scope, "handoff", OnboardingHandoffProposal{Definition: p.Definition})
	if err != nil || !repeated.Replayed || !bytes.Equal(repeated.Resource, first.Resource) {
		t.Fatal("proposal replay", err)
	}
	if _, err = f.s.DecideOnboardingHandoff(f.ctx, f.scope, h.ID, "execute", "without-approval", Decision{Hash: h.Hash, Revision: 1}); !errors.Is(err, store.ErrState) {
		t.Fatal("implicit approval", err)
	}
	h, _ = decideHandoff(t, f, h, "approve", "approve-handoff")
	h, completed := decideHandoff(t, f, h, "execute", "execute-handoff")
	if h.State != "completed" || h.NewRunID == "" || h.NewRunID == original.Run.ID {
		t.Fatal(h)
	}
	repeated, err = f.s.DecideOnboardingHandoff(f.ctx, f.scope, h.ID, "execute", "execute-handoff", Decision{Hash: h.Hash, Revision: 2})
	if err != nil || !repeated.Replayed || !bytes.Equal(repeated.Resource, completed.Resource) {
		t.Fatal("execution receipt replay", err)
	}
	old, err := f.s.OnboardingProductionStatus(f.ctx, f.scope, original.Run.ID)
	if err != nil || old.Status.Run.State != "cancelled" || old.Status.Run.Source != *f.file || old.Status.Steps[0].Attempts != 0 || old.Dispatch.Hash != original.Dispatch.Hash {
		t.Fatal("original meaning changed or lost", old, err)
	}
	next, err := f.s.OnboardingProductionStatus(f.ctx, f.scope, h.NewRunID)
	if err != nil || next.Status.ObservedState != "queued" || next.Status.Run.Source != *f.file {
		t.Fatal("successor", next, err)
	}

	_, hash, err := digest(next.Dispatch.Definition)
	if err != nil || hash != p.Definition.TargetHash {
		t.Fatal("changed target", err)
	}
	late := &delivery.Service{Custody: f.s.Custody}
	if _, _, err = late.Claim(f.ctx, f.scope, p.Definition.Source.Delivery.ID, secure.NewID()); !errors.Is(err, store.ErrState) {
		t.Fatal("prepared old worker acquired delivery", err)
	}
	var sourceTx, targetTx, handoffTx string
	if err = f.admin.QueryRow(f.ctx, `SELECT (SELECT xmin::text FROM workflow_runs WHERE run_id=$1),(SELECT xmin::text FROM workflow_runs WHERE run_id=$2),(SELECT xmin::text FROM onboarding_handoffs WHERE handoff_id=$3)`, original.Run.ID, h.NewRunID, h.ID).Scan(&sourceTx, &targetTx, &handoffTx); err != nil || sourceTx != targetTx || sourceTx != handoffTx {
		t.Fatal("non-atomic successor", sourceTx, targetTx, handoffTx, err)
	}
}
func TestOnboardingHandoffRollbackAndDeferredCancellationGuard(t *testing.T) {
	f, _, original, r := handoffFixture(t)
	_, h, _ := proposeHandoff(t, f, r, "handoff")
	h, _ = decideHandoff(t, f, h, "approve", "approve")
	if _, err := f.admin.Exec(f.ctx, `CREATE FUNCTION freightctl_handoff_receipt_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture handoff receipt unavailable';END $$;CREATE TRIGGER freightctl_handoff_receipt_failure BEFORE INSERT ON workflow_receipts FOR EACH ROW EXECUTE FUNCTION freightctl_handoff_receipt_failure()`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.DecideOnboardingHandoff(f.ctx, f.scope, h.ID, "execute", "failed-execution", Decision{Hash: h.Hash, Revision: h.Revision}); err == nil {
		t.Fatal("failed receipt acknowledged")
	}
	old, err := f.s.OnboardingProductionStatus(f.ctx, f.scope, original.Run.ID)
	if err != nil || old.Status.Run.State != "running" || old.Status.Steps[0].State != "queued" || old.Status.Steps[0].Attempts != 0 {
		t.Fatal("source cancellation survived rollback", old, err)
	}
	view, err := f.s.OnboardingHandoffStatus(f.ctx, f.scope, h.ID)
	if err != nil || view.Handoff.State != "approved" || !view.Current {
		t.Fatal("approval lost", view, err)
	}
	var count int
	if err = f.admin.QueryRow(f.ctx, `SELECT count(*) FROM onboarding_dispatches`).Scan(&count); err != nil || count != 1 {
		t.Fatal("orphan replacement", count, err)
	}
	tx, err := f.s.Custody.DB.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	intent, err := tx.Delivery(f.ctx, view.Handoff.Definition.Source.Delivery.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	previous := intent.Revision
	intent.State = "cancelled"
	intent.Revision++
	intent.Observation, _ = json.Marshal(map[string]string{"code": "onboarding_handoff", "handoff_id": h.ID})
	if err = tx.SaveDelivery(f.ctx, intent, previous); err != nil {
		t.Fatal(err)
	}
	var pgerr *pgconn.PgError
	if err = tx.Tx.Commit(f.ctx); !errors.As(err, &pgerr) || pgerr.Code != "23514" {
		t.Fatal("incomplete handoff cancellation committed", err)
	}
}
func TestOnboardingHandoffRefusesAttemptedAndUnlinkedChangedSources(t *testing.T) {
	t.Run("attempted", func(t *testing.T) {
		f, r, original, selection := handoffFixture(t)
		r = decideRelease(t, f, r, "suspend")
		// Reactivate the original epoch is impossible; the queued successor target
		// is refreshed only to test admission after a real recorded attempt below.
		r = decideRelease(t, f, r, "activate")
		_, fresh, _ := productionIntent(t, f, r, original.Dispatch.Definition.RequirementID, f.file.ID, "attempted-source")
		worker := &delivery.Service{Custody: f.s.Custody}
		if _, _, err := worker.Claim(f.ctx, f.scope, func() string {
			v, e := f.s.Status(f.ctx, f.scope, fresh.Run.ID)
			if e != nil {
				t.Fatal(e)
			}
			return v.Steps[0].DeliveryID
		}(), secure.NewID()); err != nil {
			t.Fatal(err)
		}
		r = decideRelease(t, f, r, "suspend")
		r = decideRelease(t, f, r, "activate")
		selection.SourceRunID = fresh.Run.ID
		selection.SourceHash = fresh.Dispatch.Hash
		selection.Target = store.OnboardingActivationReference{ID: r.ID, Revision: r.Revision, Hash: r.Hash}
		if _, err := f.s.PreviewOnboardingHandoff(f.ctx, f.scope, selection); !errors.Is(err, store.ErrState) {
			t.Fatal("attempted intent treated as unsent", err)
		}
	})
	t.Run("unlinked-identical-copy", func(t *testing.T) {
		f, _, _, r := handoffFixture(t)
		copy, _, err := f.s.Custody.Accept(f.ctx, f.scope, "unlinked-copy", f.file.Size, f.file.SHA256, bytes.NewBufferString("abc"))
		if err != nil {
			t.Fatal(err)
		}
		r.FileID = copy.ID
		if _, err = f.s.PreviewOnboardingHandoff(f.ctx, f.scope, r); !errors.Is(err, store.ErrRevision) {
			t.Fatal("raw copy bypassed checked lineage", err)
		}
	})
}
func TestOnboardingHandoffStaleSourceAndTargetRequireNewReview(t *testing.T) {
	f, r, _, selection := handoffFixture(t)
	_, h, _ := proposeHandoff(t, f, selection, "handoff")
	r = decideRelease(t, f, r, "suspend")
	if _, err := f.s.DecideOnboardingHandoff(f.ctx, f.scope, h.ID, "approve", "stale-approval", Decision{Hash: h.Hash, Revision: 1}); !errors.Is(err, store.ErrRevision) {
		t.Fatal("changed target approved", err)
	}
	view, err := f.s.OnboardingHandoffStatus(f.ctx, f.scope, h.ID)
	if err != nil || view.Current || view.Reason != "binding_changed" {
		t.Fatal(view, err)
	}
	h, _ = decideHandoff(t, f, h, "cancel", "cancel-stale")
	if h.State != "cancelled" {
		t.Fatal(h)
	}
}
func TestOnboardingHandoffConcurrentExecutionPrivateHistoryAndImmutableSQL(t *testing.T) {
	f, _, _, selection := handoffFixture(t)
	_, h, _ := proposeHandoff(t, f, selection, "handoff")
	h, _ = decideHandoff(t, f, h, "approve", "approve")
	var group sync.WaitGroup
	results := make(chan *Result, 8)
	failures := make(chan error, 8)
	for i := 0; i < 8; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			r, e := f.s.DecideOnboardingHandoff(f.ctx, f.scope, h.ID, "execute", "one-execute", Decision{Hash: h.Hash, Revision: 2})
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
	var first []byte
	for r := range results {
		if !r.Replayed {
			created++
		}
		if first == nil {
			first = r.Resource
		} else if !bytes.Equal(first, r.Resource) {
			t.Fatal("concurrent receipts differ")
		}
	}
	if created != 1 {
		t.Fatal("multiple completions", created)
	}
	for _, q := range []string{`UPDATE onboarding_handoffs SET definition_hash=repeat('0',64)`, `DELETE FROM onboarding_handoffs`} {
		var pgerr *pgconn.PgError
		if _, err := f.admin.Exec(f.ctx, q); !errors.As(err, &pgerr) || pgerr.Code != "23514" {
			t.Fatal("immutable handoff changed", err)
		}
	}
	token := filepath.Join(t.TempDir(), "other.token")
	if err := secure.WriteToken(token); err != nil {
		t.Fatal(err)
	}
	if err := store.Provision(f.ctx, f.adminPath, f.scope.Tenant, f.scope.Partner, token); err != nil {
		t.Fatal(err)
	}
	secret, err := secure.ReadSecret(token, 64)
	if err != nil {
		t.Fatal(err)
	}
	other := store.Scope{Tenant: f.scope.Tenant, Partner: f.scope.Partner, TokenHash: secure.Digest(secret.Bytes)}
	secret.Close()
	if _, err = f.s.OnboardingHandoffStatus(f.ctx, other, h.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("other actor read handoff", err)
	}
	page, err := f.s.ListOnboardingHandoffs(f.ctx, other, selectionSourcePlan(t, f, h.ID), "", 50)
	if err != nil || len(page.Handoffs) != 0 {
		t.Fatal("other actor listed handoff", page, err)
	}
	events, err := f.s.Custody.DB.Events(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, e := range events {
		if e.ResourceID == h.ID && (e.Kind == "OnboardingHandoffChanged" || e.Kind == "WorkflowCommandCompleted") {
			if !bytes.Contains(e.Payload, []byte(`"redacted":true`)) {
				t.Fatal("private handoff exposed", e.Kind)
			}
			count++
		}
	}
	if count != 6 {
		t.Fatal("handoff audit", count)
	}
}
func selectionSourcePlan(t *testing.T, f *fixture, id string) string {
	t.Helper()
	v, e := f.s.OnboardingHandoffStatus(f.ctx, f.scope, id)
	if e != nil {
		t.Fatal(e)
	}
	return v.Handoff.Definition.Source.Plan.ID
}

func TestOnboardingHandoffAcrossClientKeyAndCredentialRotation(t *testing.T) {
	f, _, selection, oldTest := completedReleaseFixture(t, "integrity")
	_, oldRelease, _ := proposeRelease(t, f, selection, "old-release")
	oldRelease = decideRelease(t, f, oldRelease, "approve")
	oldRelease = decideRelease(t, f, oldRelease, "activate")
	_, oldProduction, originalReceipt := productionIntent(t, f, oldRelease, oldTest.Test.Definition.RequirementID, f.file.ID, "before-rotation")
	oldScope := f.scope
	identity, err := f.s.Custody.DB.Identity(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	peer := store.AccountCommand{Operation: "create", ID: secure.NewID(), CredentialHash: secure.Digest([]byte("synthetic handoff rotation manager")), Policy: &store.AccountPolicy{Label: "Handoff rotation manager", Root: "/", Permissions: append([]string{}, store.DefaultPermissions...)}}
	if _, err = f.s.Custody.DB.ChangeAccount(f.ctx, f.scope, "rotation-manager", peer); err != nil {
		t.Fatal(err)
	}
	peerScope := store.Scope{Tenant: f.scope.Tenant, Partner: f.scope.Partner, TokenHash: peer.CredentialHash}
	rotatedHash := secure.Digest([]byte("synthetic rotated handoff credential"))
	if _, err = f.s.Custody.DB.ChangeAccount(f.ctx, peerScope, "rotate-handoff-credential", store.AccountCommand{Operation: "rotate", ID: identity.Actor, ExpectedRevision: 1, CredentialHash: rotatedHash}); err != nil {
		t.Fatal(err)
	}
	f.scope.TokenHash = rotatedHash
	if _, err = f.s.OnboardingProductionStatus(f.ctx, oldScope, oldProduction.Run.ID); !errors.Is(err, store.ErrUnauthorized) {
		t.Fatal("old credential retained access", err)
	}
	// Suspend remains available despite the original authority becoming stale.
	oldRelease = decideRelease(t, f, oldRelease, "suspend")
	request := f.request
	request.ID = f.connection.ID
	request.ExpectedVersion = 1
	request.KeyFile = filepath.Join(t.TempDir(), "new-client")
	request.KeyPublicFile = request.KeyFile + ".pub"
	if err = secure.GenerateSSHHostIdentity(request.KeyFile, request.KeyPublicFile); err != nil {
		t.Fatal(err)
	}
	registered, err := f.s.RegisterConnection(f.ctx, f.scope, "rotated-client", request)
	if err != nil {
		t.Fatal(err)
	}
	var connection ConnectionView
	if json.Unmarshal(registered.Resource, &connection) != nil {
		t.Fatal("connection receipt")
	}
	if connection.KeyFingerprint == f.connection.KeyFingerprint {
		t.Fatal("client identity did not rotate")
	}
	f.connection = connection
	probeRequest := store.OnboardingProbeRequest{Plan: selection.Plan, RequirementID: oldTest.Test.Definition.RequirementID, Connection: store.OnboardingReference{ID: connection.ID, Version: connection.Version, Hash: connection.Hash}, ExpectedAuthority: 2}
	probe := startProbe(t, f, "new-authority-probe", probeRequest)
	seedSuccessfulProbe(t, f, probe)
	definition := f.definition()
	definition.Steps = definition.Steps[:1]
	draft, err := f.s.Draft(f.ctx, f.scope, "rotated-workflow", DraftRequest{ID: oldTest.Run.WorkflowID, ExpectedVersion: 1, Definition: definition})
	if err != nil {
		t.Fatal(err)
	}
	var wf store.Configuration
	if json.Unmarshal(draft.Resource, &wf) != nil {
		t.Fatal("workflow")
	}
	approved, err := f.s.Decide(f.ctx, f.scope, wf.ID, wf.Version, "approve-rotated-workflow", "approve", Decision{Hash: wf.Hash, Revision: wf.Revision})
	if err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(approved.Resource, &wf) != nil {
		t.Fatal("workflow approval")
	}
	_, _, newTest := testIntent(t, f, OnboardingTestPreviewRequest{Plan: selection.Plan, RequirementID: probeRequest.RequirementID, ProbeID: probe.ID, Workflow: Reference{ID: wf.ID, Version: wf.Version, Hash: wf.Hash}, FileID: f.file.ID, ExpectedAuthority: 2}, "rotated-test")
	completeFixtureExchange(t, f, newTest)
	_, target, _ := proposeRelease(t, f, OnboardingReleaseSelection{Plan: selection.Plan, TestIDs: []string{newTest.Test.ID}, Authority: 2}, "new-release")
	target = decideRelease(t, f, target, "approve")
	target = decideRelease(t, f, target, "activate")
	preview, h, _ := proposeHandoff(t, f, OnboardingHandoffSelection{SourceRunID: oldProduction.Run.ID, SourceHash: oldProduction.Dispatch.Hash, Target: store.OnboardingActivationReference{ID: target.ID, Revision: target.Revision, Hash: target.Hash}, FileID: f.file.ID}, "rotated-handoff")
	if preview.Definition.Source.Dispatch.Definition.Authority != 1 || preview.Definition.Target.Authority != 2 || preview.Definition.Source.Dispatch.Definition.Effect.KeyFingerprint == preview.Definition.Target.Effect.KeyFingerprint {
		t.Fatal("rotation context lost")
	}
	h, _ = decideHandoff(t, f, h, "approve", "approve-rotated-handoff")
	h, _ = decideHandoff(t, f, h, "execute", "execute-rotated-handoff")
	next, err := f.s.OnboardingProductionStatus(f.ctx, f.scope, h.NewRunID)
	if err != nil || !next.Current || next.Status.Run.Source != *f.file || next.Status.Run.Authority != 2 {
		t.Fatal(next, err)
	}
	historical, err := f.s.StartOnboardingProduction(f.ctx, f.scope, "before-rotation", OnboardingProductionStart{Definition: oldProduction.Dispatch.Definition})
	if err != nil || !historical.Replayed || !bytes.Equal(historical.Resource, originalReceipt.Resource) {
		t.Fatal("original receipt was rewritten or lost", err)
	}
}
