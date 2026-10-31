//go:build integration

package workflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/jackc/pgx/v5/pgconn"
)

func approvalPeer(t *testing.T, f *fixture, label string, permissions []string) (store.Scope, store.AccountCommand) {
	t.Helper()
	c := store.AccountCommand{Operation: "create", ID: secure.NewID(), CredentialHash: secure.Digest([]byte(secure.NewID())), Policy: &store.AccountPolicy{Label: label, Root: "/", Permissions: permissions}}
	if _, err := f.s.Custody.DB.ChangeAccount(f.ctx, f.scope, "create-"+c.ID, c); err != nil {
		t.Fatal(err)
	}
	return store.Scope{Tenant: f.scope.Tenant, Partner: f.scope.Partner, TokenHash: c.CredentialHash}, c
}
func approvalFixture(t *testing.T) (*fixture, OnboardingReleaseSelection, OnboardingTestResult, store.Scope, store.AccountCommand) {
	t.Helper()
	f, _, selection, test := completedReleaseFixture(t, "integrity")
	if _, err := f.s.ChangeOnboardingApprovalPolicy(f.ctx, f.scope, "independent-policy", OnboardingApprovalPolicyChange{Mode: "independent"}); err != nil {
		t.Fatal(err)
	}
	reviewer, c := approvalPeer(t, f, "Independent reviewer", []string{"inspect", "workflow_approve"})
	return f, selection, test, reviewer, c
}
func reviewSelection(r store.OnboardingReleaseSummary, reviewer string) OnboardingApprovalSelection {
	return OnboardingApprovalSelection{ReleaseID: r.ID, Decision: Decision{Hash: r.Hash, Revision: r.Revision}, ReviewerID: reviewer}
}
func proposeApproval(t *testing.T, f *fixture, r store.OnboardingReleaseSummary, reviewer string, key string) (*OnboardingApprovalPreview, store.OnboardingApprovalSummary, *Result) {
	t.Helper()
	selection := reviewSelection(r, reviewer)
	p, err := f.s.PreviewOnboardingApproval(f.ctx, f.scope, selection)
	if err != nil {
		t.Fatal(err)
	}
	out, err := f.s.ProposeOnboardingApproval(f.ctx, f.scope, key, OnboardingApprovalProposal{Selection: selection, Hash: p.Hash})
	if err != nil {
		t.Fatal(err)
	}
	var v OnboardingApprovalResult
	if json.Unmarshal(out.Resource, &v) != nil || v.Kind != "onboarding_approval" {
		t.Fatal("receipt")
	}
	return p, v.Review, out
}
func approveReview(t *testing.T, f *fixture, scope store.Scope, r store.OnboardingApprovalSummary, key string) (*Result, error) {
	t.Helper()
	return f.s.DecideOnboardingApproval(f.ctx, scope, r.ID, "approve", key, Decision{Revision: r.Revision, Hash: r.Hash})
}
func TestOnboardingIndependentApprovalRequiresNamedDifferentReviewerAndKeepsSourcesPrivate(t *testing.T) {
	f, selection, test, reviewer, c := approvalFixture(t)
	p, r, _ := proposeRelease(t, f, selection, "governed-release")
	if p.Definition.ApprovalPolicy == nil || p.Definition.ApprovalPolicy.Mode != "independent" || p.Definition.ApprovalPolicy.Revision != 1 {
		t.Fatal(p.Definition)
	}
	if _, err := f.s.DecideOnboardingRelease(f.ctx, f.scope, r.ID, "approve", "self-release-approve", Decision{Revision: 1, Hash: r.Hash}); !errors.Is(err, store.ErrState) {
		t.Fatal("self approval activated without independent decision", err)
	}
	owner, err := f.s.Custody.DB.Identity(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.PreviewOnboardingApproval(f.ctx, f.scope, reviewSelection(r, owner.Actor)); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("self review allowed", err)
	}
	preview, review, _ := proposeApproval(t, f, r, c.ID, "request-independent")
	if preview.ExternalContact || preview.GrantsFileAccess || len(preview.Definition.Effects) != 1 || preview.Definition.Effects[0].File.ID != f.file.ID {
		t.Fatal(preview)
	}
	seen, err := f.s.OnboardingApprovalStatus(f.ctx, reviewer, review.ID)
	if err != nil || seen.Hash != review.Hash {
		t.Fatal(seen, err)
	}
	if _, err = f.s.OnboardingReleaseStatus(f.ctx, reviewer, r.ID); err == nil {
		t.Fatal("reviewer gained private release access")
	}
	if _, err = f.s.OnboardingTestStatus(f.ctx, reviewer, test.Test.ID); err == nil {
		t.Fatal("reviewer gained private test access")
	}
	if _, err = f.s.Custody.DB.Onboarding(f.ctx, reviewer, selection.Plan.ID, 0); err == nil {
		t.Fatal("reviewer gained private plan access")
	}
	outsider, _ := approvalPeer(t, f, "Other full manager", append([]string{}, store.DefaultPermissions...))
	if _, err = f.s.OnboardingApprovalStatus(f.ctx, outsider, review.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("unassigned manager read package", err)
	}
	page, err := f.s.ListOnboardingApprovals(f.ctx, outsider, "", 50)
	if err != nil || len(page.Reviews) != 0 {
		t.Fatal(page, err)
	}
	if _, err = approveReview(t, f, f.scope, review, "owner-forges-review"); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("owner impersonated reviewer", err)
	}
	if _, err = approveReview(t, f, outsider, review, "outsider-forges-review"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	a, err := approveReview(t, f, reviewer, review, "independent-approve")
	if err != nil {
		t.Fatal(err)
	}
	replay, err := approveReview(t, f, reviewer, review, "independent-approve")
	if err != nil || !bytes.Equal(a.Resource, replay.Resource) {
		t.Fatal("lost decision response changed", err)
	}
	r = decideRelease(t, f, r, "approve")
	r = decideRelease(t, f, r, "activate")
	_, production, _ := productionIntent(t, f, r, preview.Definition.Effects[0].RequirementID, f.file.ID, "governed-production")
	tx, err := f.s.Custody.DB.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	current, err := tx.OnboardingRunCurrent(f.ctx, production.Run.ID)
	tx.Tx.Rollback(f.ctx)
	if err != nil || !current {
		t.Fatal("approved run unavailable", current, err)
	}
}
func TestOnboardingApprovalPolicyEpochAndReviewerRevocationFenceQueuedProduction(t *testing.T) {
	for _, change := range []string{"policy", "reviewer"} {
		t.Run(change, func(t *testing.T) {
			f, selection, _, reviewer, c := approvalFixture(t)
			_, r, _ := proposeRelease(t, f, selection, "governed-release")
			p, review, _ := proposeApproval(t, f, r, c.ID, "request-review")
			if _, err := approveReview(t, f, reviewer, review, "approve-review"); err != nil {
				t.Fatal(err)
			}
			r = decideRelease(t, f, r, "approve")
			r = decideRelease(t, f, r, "activate")
			_, production, _ := productionIntent(t, f, r, p.Definition.Effects[0].RequirementID, f.file.ID, "production")
			if change == "policy" {
				if _, err := f.s.ChangeOnboardingApprovalPolicy(f.ctx, f.scope, "new-policy", OnboardingApprovalPolicyChange{ExpectedRevision: 1, Mode: "author"}); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := f.s.Custody.DB.ChangeAccount(f.ctx, f.scope, "rotate-reviewer", store.AccountCommand{Operation: "rotate", ID: c.ID, ExpectedRevision: 1, CredentialHash: secure.Digest([]byte(secure.NewID()))}); err != nil {
					t.Fatal(err)
				}
			}
			tx, err := f.s.Custody.DB.Begin(f.ctx, f.scope)
			if err != nil {
				t.Fatal(err)
			}
			current, err := tx.OnboardingRunCurrent(f.ctx, production.Run.ID)
			tx.Tx.Rollback(f.ctx)
			if err != nil || current {
				t.Fatal("stale independent authority remained executable", current, err)
			}
			if _, err = f.s.PreviewOnboardingProduction(f.ctx, f.scope, r.ID, OnboardingProductionSelection{Decision: Decision{Hash: r.Hash, Revision: r.Revision}, RequirementID: p.Definition.Effects[0].RequirementID, FileID: f.file.ID}); err == nil {
				t.Fatal("new work allowed under stale policy/reviewer")
			}
			view, err := f.s.OnboardingReleaseStatus(f.ctx, f.scope, r.ID)
			if err != nil || view.Current || view.ProductionActive {
				t.Fatal(view, err)
			}
		})
	}
}
func TestOnboardingApprovalWithdrawAndStaleDecisionCannotRestoreAuthority(t *testing.T) {
	f, selection, _, reviewer, c := approvalFixture(t)
	_, r, _ := proposeRelease(t, f, selection, "release")
	_, review, _ := proposeApproval(t, f, r, c.ID, "request")
	if _, err := approveReview(t, f, reviewer, review, "approve"); err != nil {
		t.Fatal(err)
	}
	saved, err := f.s.OnboardingApprovalStatus(f.ctx, f.scope, review.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.DecideOnboardingApproval(f.ctx, f.scope, review.ID, "withdraw", "withdraw", Decision{Hash: saved.Hash, Revision: saved.Revision}); err != nil {
		t.Fatal(err)
	}
	original, err := approveReview(t, f, reviewer, review, "approve")
	if err != nil || original == nil {
		t.Fatal("historical retry receipt lost", err)
	}
	if _, err = f.s.DecideOnboardingRelease(f.ctx, f.scope, r.ID, "approve", "late-approve", Decision{Hash: r.Hash, Revision: r.Revision}); !errors.Is(err, store.ErrState) {
		t.Fatal("historical replay restored live authority", err)
	}
	if _, err = f.s.ChangeOnboardingApprovalPolicy(f.ctx, reviewer, "reviewer-policy", OnboardingApprovalPolicyChange{ExpectedRevision: 1, Mode: "author"}); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("reviewer relaxed administrator policy", err)
	}
}
func TestOnboardingApprovalReceiptFailureRollsBackActualReviewerDecision(t *testing.T) {
	f, selection, _, reviewer, c := approvalFixture(t)
	_, r, _ := proposeRelease(t, f, selection, "release")
	_, review, _ := proposeApproval(t, f, r, c.ID, "request")
	_, err := f.admin.Exec(f.ctx, `CREATE FUNCTION freightctl_review_receipt_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.kind='WorkflowCommandCompleted' AND NEW.payload->>'request_key'='fail-review-receipt' THEN RAISE EXCEPTION 'injected independent review receipt failure' USING ERRCODE='P0001';END IF;RETURN NEW;END $$;CREATE TRIGGER freightctl_review_receipt_fail BEFORE INSERT ON events FOR EACH ROW EXECUTE FUNCTION freightctl_review_receipt_fail()`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = approveReview(t, f, reviewer, review, "fail-review-receipt")
	var pe *pgconn.PgError
	if !errors.As(err, &pe) || pe.Code != "P0001" || pe.Message != "injected independent review receipt failure" {
		t.Fatal("did not reach exact receipt boundary", err)
	}
	got, err := f.s.OnboardingApprovalStatus(f.ctx, f.scope, review.ID)
	if err != nil || got.State != "pending" || got.Revision != 1 {
		t.Fatal("decision escaped failed receipt", got, err)
	}
	if _, err = f.admin.Exec(f.ctx, `DROP TRIGGER freightctl_review_receipt_fail ON events`); err != nil {
		t.Fatal(err)
	}
	if _, err = approveReview(t, f, reviewer, review, "fail-review-receipt"); err != nil {
		t.Fatal(err)
	}
}
func TestOnboardingApprovalConcurrentOriginalKeyAndSQLForgeryRefusal(t *testing.T) {
	f, selection, _, _, c := approvalFixture(t)
	_, r, _ := proposeRelease(t, f, selection, "release")
	x := reviewSelection(r, c.ID)
	p, err := f.s.PreviewOnboardingApproval(f.ctx, f.scope, x)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	outputs := make(chan *Result, 8)
	failures := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, e := f.s.ProposeOnboardingApproval(f.ctx, f.scope, "same-review", OnboardingApprovalProposal{Selection: x, Hash: p.Hash})
			if e != nil {
				failures <- e
			} else {
				outputs <- v
			}
		}()
	}
	wg.Wait()
	close(outputs)
	close(failures)
	for e := range failures {
		t.Fatal(e)
	}
	var first []byte
	for v := range outputs {
		if first == nil {
			first = v.Resource
		} else if !bytes.Equal(first, v.Resource) {
			t.Fatal("concurrent output drift")
		}
	}
	var out OnboardingApprovalResult
	if json.Unmarshal(first, &out) != nil {
		t.Fatal("receipt")
	}
	tx, err := f.s.Custody.DB.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	review, err := tx.OnboardingApprovalReview(f.ctx, out.Review.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	review.State = "approved"
	review.Revision++
	err = tx.SaveOnboardingApprovalReview(f.ctx, review, 1)
	tx.Tx.Rollback(f.ctx)
	var pe *pgconn.PgError
	if !errors.As(err, &pe) || pe.Code != "42501" || pe.Message != "approval requires exact current independent reviewer" {
		t.Fatal("SQL owner forged reviewer decision", err)
	}
	var count int
	if err = f.admin.QueryRow(f.ctx, `SELECT count(*) FROM onboarding_approval_reviews`).Scan(&count); err != nil || count != 1 {
		t.Fatal(count, err)
	}
}

// A worker's current-approval check must not take the account writer lock and
// hide staged state from a separate operator. The original native crash replay
// found that such a lock made its status read wait through the whole barrier.
func TestOnboardingApprovalWorkerGuardKeepsReadOnlyStatusObservable(t *testing.T) {
	f, selection, _, reviewer, c := approvalFixture(t)
	_, r, _ := proposeRelease(t, f, selection, "release")
	p, review, _ := proposeApproval(t, f, r, c.ID, "review")
	if _, err := approveReview(t, f, reviewer, review, "approve-review"); err != nil {
		t.Fatal(err)
	}
	r = decideRelease(t, f, r, "approve")
	r = decideRelease(t, f, r, "activate")
	_, production, _ := productionIntent(t, f, r, p.Definition.Effects[0].RequirementID, f.file.ID, "production")
	worker, err := f.s.Custody.DB.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Tx.Rollback(f.ctx)
	current, err := worker.OnboardingRunCurrent(f.ctx, production.Run.ID)
	if err != nil || !current {
		t.Fatal(current, err)
	}
	ctx, cancel := context.WithTimeout(f.ctx, 2*time.Second)
	defer cancel()
	status, err := f.s.OnboardingProductionStatus(ctx, f.scope, production.Run.ID)
	if err != nil || status.Status.Run.State != "queued" {
		t.Fatal("worker guard blocked separate read-only status", status, err)
	}
}

func TestOnboardingApprovalRejectedHistoryAndPolicyReplayDoNotRestoreAuthority(t *testing.T) {
	f, selection, _, reviewer, c := approvalFixture(t)
	_, r, _ := proposeRelease(t, f, selection, "release")
	_, review, _ := proposeApproval(t, f, r, c.ID, "request")
	rejected, err := f.s.DecideOnboardingApproval(f.ctx, reviewer, review.ID, "reject", "reject-review", Decision{Hash: review.Hash, Revision: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = approveReview(t, f, reviewer, review, "approve-rejected"); !errors.Is(err, store.ErrRevision) {
		t.Fatal("rejected review revived", err)
	}
	_, fresh, _ := proposeApproval(t, f, r, c.ID, "fresh-after-rejection")
	if fresh.ID == review.ID {
		t.Fatal("rejected record overwritten")
	}
	replay, err := f.s.DecideOnboardingApproval(f.ctx, reviewer, review.ID, "reject", "reject-review", Decision{Hash: review.Hash, Revision: 1})
	if err != nil || !bytes.Equal(rejected.Resource, replay.Resource) {
		t.Fatal("original rejection receipt changed", err)
	}
	if _, err = approveReview(t, f, reviewer, fresh, "fresh-approval"); err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.ChangeOnboardingApprovalPolicy(f.ctx, f.scope, "replace-policy", OnboardingApprovalPolicyChange{ExpectedRevision: 1, Mode: "author"}); err != nil {
		t.Fatal(err)
	}
	old, err := f.s.ChangeOnboardingApprovalPolicy(f.ctx, f.scope, "independent-policy", OnboardingApprovalPolicyChange{Mode: "independent"})
	if err != nil {
		t.Fatal(err)
	}
	var previous OnboardingApprovalPolicyResult
	if json.Unmarshal(old.Resource, &previous) != nil || previous.Policy.Revision != 1 {
		t.Fatal("historical policy receipt", previous)
	}
	current, err := f.s.OnboardingApprovalPolicy(f.ctx, f.scope)
	if err != nil || current.Revision != 2 || current.Mode != "author" {
		t.Fatal("policy replay rewound active revision", current, err)
	}
}

func TestOnboardingApprovalCredentialMutationWaitsForGuardThenInvalidatesIt(t *testing.T) {
	f, selection, _, reviewer, c := approvalFixture(t)
	_, r, _ := proposeRelease(t, f, selection, "release")
	p, review, _ := proposeApproval(t, f, r, c.ID, "request")
	if _, err := approveReview(t, f, reviewer, review, "approve-review"); err != nil {
		t.Fatal(err)
	}
	r = decideRelease(t, f, r, "approve")
	r = decideRelease(t, f, r, "activate")
	_, production, _ := productionIntent(t, f, r, p.Definition.Effects[0].RequirementID, f.file.ID, "production")
	worker, err := f.s.Custody.DB.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	current, err := worker.OnboardingRunCurrent(f.ctx, production.Run.ID)
	if err != nil || !current {
		worker.Tx.Rollback(f.ctx)
		t.Fatal(current, err)
	}
	done := make(chan error, 1)
	finished := false
	defer func() {
		worker.Tx.Rollback(context.Background())
		if !finished {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("credential writer did not finish after releasing exact guard")
			}
		}
	}()
	go func() {
		_, e := f.s.Custody.DB.ChangeAccount(f.ctx, f.scope, "rotate-during-guard", store.AccountCommand{Operation: "rotate", ID: c.ID, ExpectedRevision: 1, CredentialHash: secure.Digest([]byte(secure.NewID()))})
		done <- e
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var waiting bool
		err = f.admin.QueryRow(f.ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks l JOIN pg_stat_activity a USING(pid) WHERE a.datname=current_database() AND a.application_name='freightctl' AND l.locktype='advisory' AND NOT l.granted AND a.query LIKE 'INSERT INTO account_revisions%')`).Scan(&waiting)
		if err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("actual credential mutation did not wait at approval guard")
		}
		time.Sleep(10 * time.Millisecond)
	}
	select {
	case e := <-done:
		finished = true
		t.Fatal("credential mutation crossed live approval guard", e)
	default:
	}
	if err = worker.Tx.Rollback(f.ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-done:
		finished = true
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("credential mutation remained blocked after guard release")
	}
	tx, err := f.s.Custody.DB.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Tx.Rollback(f.ctx)
	current, err = tx.OnboardingRunCurrent(f.ctx, production.Run.ID)
	if err != nil || current {
		t.Fatal("rotated reviewer remained authorized", current, err)
	}
}
