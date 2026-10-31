//go:build integration

package workflow

import (
	"bytes"
	"context"
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

func outboundFixture(t *testing.T) (*fixture, *delivery.Service, store.Scope, store.AccountCommand) {
	t.Helper()
	f := setup(t)
	s := &delivery.Service{Custody: f.s.Custody}
	if _, err := s.ChangeDispatchPolicy(f.ctx, f.scope, "independent-dispatch-policy", delivery.DispatchPolicyChange{Mode: "independent"}); err != nil {
		t.Fatal(err)
	}
	reviewer, c := approvalPeer(t, f, "Dispatch reviewer", []string{"inspect", "workflow_approve"})
	return f, s, reviewer, c
}
func directDispatch(t *testing.T, f *fixture, s *delivery.Service, key string, queue bool) (*store.Delivery, delivery.Request) {
	t.Helper()
	r := delivery.Request{FileID: f.file.ID, Address: f.request.Address, User: f.request.User, Directory: f.request.Directory, Filename: "dispatch.csv", HostPublicFile: f.request.HostPublicFile, KeyFile: f.request.KeyFile, KeyPublicFile: f.request.KeyPublicFile}
	out, err := s.Create(f.ctx, f.scope, key, r)
	if err != nil {
		t.Fatal(err)
	}
	if queue {
		out, err = s.Command(f.ctx, f.scope, out.Delivery.ID, key+"-queue", "approve", out.Delivery.DefinitionHash, out.Delivery.Revision)
		if err != nil {
			t.Fatal(err)
		}
	}
	return out.Delivery, r
}
func proposeDispatch(t *testing.T, f *fixture, s *delivery.Service, d *store.Delivery, reviewer, key string) (*delivery.DispatchPreview, store.OutboundDispatchSummary, *delivery.DispatchResult) {
	t.Helper()
	selection := delivery.DispatchSelection{DeliveryID: d.ID, DispatchDecision: delivery.DispatchDecision{Hash: d.DefinitionHash, Revision: d.Revision}, ReviewerID: reviewer}
	p, err := s.PreviewDispatchReview(f.ctx, f.scope, selection)
	if err != nil {
		t.Fatal(err)
	}
	out, err := s.ProposeDispatchReview(f.ctx, f.scope, key, delivery.DispatchProposal{Selection: selection, Hash: p.Hash})
	if err != nil {
		t.Fatal(err)
	}
	var r delivery.DispatchReviewResult
	if json.Unmarshal(out.Resource, &r) != nil || r.Kind != "outbound_dispatch_review" {
		t.Fatal("receipt")
	}
	return p, r.Review, out
}
func decideDispatch(t *testing.T, f *fixture, s *delivery.Service, scope store.Scope, r store.OutboundDispatchSummary, action, key string) (store.OutboundDispatchSummary, *delivery.DispatchResult, error) {
	t.Helper()
	out, err := s.DecideDispatchReview(f.ctx, scope, r.ID, action, key, delivery.DispatchDecision{Hash: r.Hash, Revision: r.Revision})
	if err != nil {
		return store.OutboundDispatchSummary{}, nil, err
	}
	var v delivery.DispatchReviewResult
	if json.Unmarshal(out.Resource, &v) != nil {
		t.Fatal("receipt")
	}
	return v.Review, out, nil
}
func TestOutboundDispatchDirectWorkerRequiresDifferentNamedAccountAndKeepsSourcesPrivate(t *testing.T) {
	f, s, reviewer, c := outboundFixture(t)
	d, _ := directDispatch(t, f, s, "direct", true)
	if _, _, err := s.Claim(f.ctx, f.scope, d.ID, secure.NewID()); !errors.Is(err, store.ErrDispatchApproval) {
		t.Fatal("direct worker bypassed policy", err)
	}
	owner, err := f.s.Custody.DB.Identity(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	self := delivery.DispatchSelection{DeliveryID: d.ID, DispatchDecision: delivery.DispatchDecision{Hash: d.DefinitionHash, Revision: d.Revision}, ReviewerID: owner.Actor}
	if _, err = s.PreviewDispatchReview(f.ctx, f.scope, self); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("self review accepted", err)
	}
	p, r, _ := proposeDispatch(t, f, s, d, c.ID, "request")
	b, _ := json.Marshal(p)
	if bytes.Contains(b, []byte(f.request.KeyFile)) || p.ExternalContact || p.GrantsFileAccess || p.Definition.AttemptLimit != 8 || p.Definition.Effect.FinalPath != "/inbox/"+d.ID+"-dispatch.csv" {
		t.Fatal("private reference or effect disclosure", string(b))
	}
	if _, err = s.DispatchReview(f.ctx, reviewer, r.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DispatchDelivery(f.ctx, reviewer, d.ID); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("reviewer gained original delivery", err)
	}
	if _, _, err = f.s.Custody.Download(f.ctx, reviewer, d.FileID); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("reviewer gained bytes", err)
	}
	other, _ := approvalPeer(t, f, "Other manager", append([]string{}, store.DefaultPermissions...))
	if _, err = s.DispatchReview(f.ctx, other, r.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("unassigned manager learned review", err)
	}
	if _, _, err = decideDispatch(t, f, s, f.scope, r, "approve", "self-approve"); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("owner forged approval", err)
	}
	approved, first, err := decideDispatch(t, f, s, reviewer, r, "approve", "review-approve")
	if err != nil {
		t.Fatal(err)
	}
	_, again, err := decideDispatch(t, f, s, reviewer, r, "approve", "review-approve")
	if err != nil || !bytes.Equal(first.Resource, again.Resource) {
		t.Fatal("lost response changed receipt", err)
	}
	if approved.State != "approved" {
		t.Fatal(approved)
	}
	claimed, _, err := s.Claim(f.ctx, f.scope, d.ID, secure.NewID())
	if err != nil || claimed.State != "staging" || claimed.Attempts != 1 {
		t.Fatal(claimed, err)
	}
}
func TestOutboundDispatchPolicyCannotBeBypassedThroughOrdinaryWorkflowOrCapacity(t *testing.T) {
	f, s, reviewer, c := outboundFixture(t)
	definition := f.definition()
	definition.Steps = definition.Steps[:1]
	w := f.approved(t, definition)
	out, err := f.s.Run(f.ctx, f.scope, "ordinary-workflow", RunRequest{Workflow: Reference{ID: w.ID, Version: w.Version, Hash: w.Hash}, FileID: f.file.ID})
	if err != nil {
		t.Fatal(err)
	}
	var run store.WorkflowRun
	if json.Unmarshal(out.Resource, &run) != nil {
		t.Fatal("run")
	}
	status, err := f.s.Status(f.ctx, f.scope, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	id := status.Steps[0].DeliveryID
	// Fill only this fixture's ordinary worker slots. Policy refusal must occur
	// before acquiring a stream or consuming an attempt/ciphertext reservation.
	var release []func()
	for i := 0; i < 2; i++ {
		_, done, e := f.s.Custody.DB.DeliveryWorkerSlot(f.ctx)
		if e != nil {
			t.Fatal(e)
		}
		release = append(release, done)
	}
	if _, err = s.Work(f.ctx, f.scope, id); !errors.Is(err, store.ErrDispatchApproval) {
		t.Fatal("policy check consumed transfer capacity", err)
	}
	for _, done := range release {
		done()
	}
	if _, err = f.s.Work(f.ctx, f.scope, run.ID, "ordinary-worker"); !errors.Is(err, store.ErrDispatchApproval) {
		t.Fatal("workflow bypassed dispatch approval", err)
	}
	d, err := s.Status(f.ctx, f.scope, id)
	if err != nil || d.Attempts != 0 || d.Fence != 0 || d.State != "queued" {
		t.Fatal(d, err)
	}
	p, r, _ := proposeDispatch(t, f, s, d, c.ID, "workflow-review")
	if p.Definition.Effect.Workflow == nil || p.Definition.Effect.Workflow.RunID != run.ID {
		t.Fatal("workflow binding absent")
	}
	if _, _, err = decideDispatch(t, f, s, reviewer, r, "approve", "workflow-approve-dispatch"); err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.Claim(f.ctx, f.scope, id, secure.NewID()); err != nil {
		t.Fatal("approved ordinary intent cannot run", err)
	}
}
func TestOutboundDispatchReviewerRotationCanReapproveTheSameUntouchedIntent(t *testing.T) {
	f, s, reviewer, c := outboundFixture(t)
	d, _ := directDispatch(t, f, s, "direct", true)
	_, r, _ := proposeDispatch(t, f, s, d, c.ID, "request")
	r, _, err := decideDispatch(t, f, s, reviewer, r, "approve", "approve")
	if err != nil {
		t.Fatal(err)
	}
	nextHash := secure.Digest([]byte(secure.NewID()))
	if _, err = f.s.Custody.DB.ChangeAccount(f.ctx, f.scope, "rotate-reviewer", store.AccountCommand{Operation: "rotate", ID: c.ID, ExpectedRevision: 1, CredentialHash: nextHash}); err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.Claim(f.ctx, f.scope, d.ID, secure.NewID()); !errors.Is(err, store.ErrDispatchApproval) {
		t.Fatal("old authority remained executable", err)
	}
	if _, _, err = decideDispatch(t, f, s, f.scope, r, "withdraw", "withdraw-old"); err != nil {
		t.Fatal(err)
	}
	same, err := s.Status(f.ctx, f.scope, d.ID)
	if err != nil || same.ID != d.ID || same.Attempts != 0 || same.DefinitionHash != d.DefinitionHash {
		t.Fatal(same, err)
	}
	p, fresh, _ := proposeDispatch(t, f, s, same, c.ID, "fresh-request")
	if p.Definition.ReviewerAuthority != 2 {
		t.Fatal(p.Definition)
	}
	reviewer.TokenHash = nextHash
	if _, _, err = decideDispatch(t, f, s, reviewer, fresh, "approve", "new-approval"); err != nil {
		t.Fatal(err)
	}
	claimed, _, err := s.Claim(f.ctx, f.scope, d.ID, secure.NewID())
	if err != nil || claimed.ID != d.ID || claimed.Attempts != 1 {
		t.Fatal(claimed, err)
	}
}
func TestOutboundDispatchPolicyChangePreservesOriginalCreateAndPolicyReceipts(t *testing.T) {
	f := setup(t)
	s := &delivery.Service{Custody: f.s.Custody}
	old, request := directDispatch(t, f, s, "same-direct-create", true)
	first, err := s.ChangeDispatchPolicy(f.ctx, f.scope, "policy", delivery.DispatchPolicyChange{Mode: "independent"})
	if err != nil {
		t.Fatal(err)
	}
	original, err := s.Create(f.ctx, f.scope, "same-direct-create", request)
	if err != nil || !original.Replayed || original.Delivery.ID != old.ID || original.Delivery.DefinitionHash != old.DefinitionHash {
		t.Fatal("policy drift reinterpreted original create key", original, err)
	}
	if _, _, err = s.Claim(f.ctx, f.scope, old.ID, secure.NewID()); !errors.Is(err, store.ErrDispatchApproval) {
		t.Fatal("legacy intent silently adopted new policy", err)
	}
	fresh, _ := directDispatch(t, f, s, "new-current-intent", true)
	if fresh.DefinitionHash == old.DefinitionHash {
		t.Fatal("new definition did not bind policy")
	}
	if _, err = s.ChangeDispatchPolicy(f.ctx, f.scope, "policy-two", delivery.DispatchPolicyChange{ExpectedRevision: 1, Mode: "author"}); err != nil {
		t.Fatal(err)
	}
	replay, err := s.ChangeDispatchPolicy(f.ctx, f.scope, "policy", delivery.DispatchPolicyChange{Mode: "independent"})
	if err != nil || !bytes.Equal(first.Resource, replay.Resource) {
		t.Fatal(err)
	}
	current, err := s.DispatchPolicy(f.ctx, f.scope)
	if err != nil || current.Revision != 2 || current.Mode != "author" {
		t.Fatal("historical receipt rewound policy", current, err)
	}
	if _, _, err = s.Claim(f.ctx, f.scope, fresh.ID, secure.NewID()); !errors.Is(err, store.ErrDispatchApproval) {
		t.Fatal("pending work adopted policy-two without decision", err)
	}
}
func TestOutboundDispatchConcurrentReceiptAndExactRollbackBoundary(t *testing.T) {
	f, s, reviewer, c := outboundFixture(t)
	d, _ := directDispatch(t, f, s, "direct", true)
	selection := delivery.DispatchSelection{DeliveryID: d.ID, DispatchDecision: delivery.DispatchDecision{Hash: d.DefinitionHash, Revision: d.Revision}, ReviewerID: c.ID}
	p, err := s.PreviewDispatchReview(f.ctx, f.scope, selection)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan *delivery.DispatchResult, 8)
	failures := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, e := s.ProposeDispatchReview(f.ctx, f.scope, "same-review-key", delivery.DispatchProposal{Selection: selection, Hash: p.Hash})
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
			t.Fatal("concurrent review receipt changed")
		}
	}
	var result delivery.DispatchReviewResult
	json.Unmarshal(first, &result)
	r := result.Review
	if _, err = f.admin.Exec(f.ctx, `CREATE FUNCTION freightctl_dispatch_receipt_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.kind='WorkflowCommandCompleted' AND NEW.payload->>'request_key'='injected-dispatch-approval' THEN RAISE EXCEPTION 'injected dispatch receipt boundary' USING ERRCODE='P0001';END IF;RETURN NEW;END $$;CREATE TRIGGER freightctl_dispatch_receipt_failure BEFORE INSERT ON events FOR EACH ROW EXECUTE FUNCTION freightctl_dispatch_receipt_failure()`); err != nil {
		t.Fatal(err)
	}
	_, _, err = decideDispatch(t, f, s, reviewer, r, "approve", "injected-dispatch-approval")
	var pe *pgconn.PgError
	if !errors.As(err, &pe) || pe.Code != "P0001" || pe.Message != "injected dispatch receipt boundary" {
		t.Fatal("did not reach actual receipt boundary", err)
	}
	got, err := s.DispatchReview(f.ctx, f.scope, r.ID)
	if err != nil || got.State != "pending" || got.Revision != 1 {
		t.Fatal(got, err)
	}
	if _, err = f.admin.Exec(f.ctx, `DROP TRIGGER freightctl_dispatch_receipt_failure ON events`); err != nil {
		t.Fatal(err)
	}
	if _, _, err = decideDispatch(t, f, s, reviewer, r, "approve", "injected-dispatch-approval"); err != nil {
		t.Fatal(err)
	}
}
func TestOutboundDispatchSQLForgeryRefusesWhileReadOnlyReceiptRecoveryRemainsPossible(t *testing.T) {
	f, s, reviewer, c := outboundFixture(t)
	d, _ := directDispatch(t, f, s, "direct", true)
	tx, err := f.s.Custody.DB.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	row, err := tx.Delivery(f.ctx, d.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	now, _ := tx.DatabaseTime(f.ctx)
	until := now.Add(30 * time.Second)
	row.State = "staging"
	row.Revision++
	row.Fence++
	row.Attempts++
	row.LeaseOwner = secure.NewID()
	row.LeaseUntil = &until
	err = tx.SaveDelivery(f.ctx, row, d.Revision)
	tx.Tx.Rollback(f.ctx)
	var pe *pgconn.PgError
	if !errors.As(err, &pe) || pe.Code != "23514" || pe.Message != "current outbound dispatch approval required" {
		t.Fatal("SQL staging forged consent", err)
	}
	_, r, _ := proposeDispatch(t, f, s, d, c.ID, "request")
	r, _, err = decideDispatch(t, f, s, reviewer, r, "approve", "approve")
	if err != nil {
		t.Fatal(err)
	}
	claimed, _, err := s.Claim(f.ctx, f.scope, d.ID, secure.NewID())
	if err != nil {
		t.Fatal(err)
	}
	// Real SQL projection fixture, not network evidence: preserve an uncertain
	// existing publication. Native qualification proves the independent read.
	tx, err = f.s.Custody.DB.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	row, err = tx.Delivery(f.ctx, d.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	previous := row.Revision
	row.State = "publishing"
	row.Revision++
	row.Observation = json.RawMessage(`{"code":"atomic_publication_pending"}`)
	if err = tx.SaveDelivery(f.ctx, row, previous); err != nil {
		t.Fatal(err)
	}
	previous = row.Revision
	row.State = "ambiguous"
	row.Revision++
	row.LeaseOwner = ""
	row.LeaseUntil = nil
	row.Observation = json.RawMessage(`{"code":"worker_lost_during_publication"}`)
	if err = tx.SaveDelivery(f.ctx, row, previous); err != nil {
		t.Fatal(err)
	}
	if err = tx.Tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, err = decideDispatch(t, f, s, reviewer, r, "withdraw", "reviewer-withdraw"); err != nil {
		t.Fatal(err)
	}
	tx, err = f.s.Custody.DB.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	row, err = tx.Delivery(f.ctx, d.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	previous = row.Revision
	row.State = "succeeded"
	row.Revision++
	row.Observation, _ = json.Marshal(map[string]any{"code": "remote_file_integrity_observed", "reconciled": true, "size_bytes": f.file.Size, "sha256": f.file.SHA256, "business_acceptance": "unknown", "directory_power_loss_durability": "not established", "file_fsync_acknowledged": false})
	if err = tx.SaveDelivery(f.ctx, row, previous); err != nil {
		t.Fatal("read-only exact receipt blocked by withdrawn sending consent", err)
	}
	if err = tx.Tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	if row.Fence != claimed.Fence || row.Attempts != claimed.Attempts {
		t.Fatal("receipt invented another attempt")
	}
}
func TestOutboundDispatchGuardAllowsStatusAndSerializesCredentialMutation(t *testing.T) {
	f, s, reviewer, c := outboundFixture(t)
	d, _ := directDispatch(t, f, s, "direct", true)
	_, r, _ := proposeDispatch(t, f, s, d, c.ID, "request")
	if _, _, err := decideDispatch(t, f, s, reviewer, r, "approve", "approve"); err != nil {
		t.Fatal(err)
	}
	worker, err := f.s.Custody.DB.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Tx.Rollback(context.Background())
	if err = worker.CheckOutboundDispatch(f.ctx, d.ID); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(f.ctx, 2*time.Second)
	view, err := s.DispatchDelivery(ctx, f.scope, d.ID)
	cancel()
	if err != nil || !view.CurrentApproval {
		t.Fatal("worker guard blocked read-only status", view, err)
	}
	done := make(chan error, 1)
	finished := false
	defer func() {
		worker.Tx.Rollback(context.Background())
		if !finished {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("credential writer did not finish")
			}
		}
	}()
	go func() {
		_, e := f.s.Custody.DB.ChangeAccount(f.ctx, f.scope, "rotate-during-dispatch-guard", store.AccountCommand{Operation: "rotate", ID: c.ID, ExpectedRevision: 1, CredentialHash: secure.Digest([]byte(secure.NewID()))})
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
			t.Fatal("actual credential mutation did not wait at dispatch guard")
		}
		time.Sleep(10 * time.Millisecond)
	}
	select {
	case e := <-done:
		finished = true
		t.Fatal("credential mutation crossed dispatch guard", e)
	default:
	}
	worker.Tx.Rollback(f.ctx)
	select {
	case err = <-done:
		finished = true
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("writer stayed blocked")
	}
	if _, _, err = s.Claim(f.ctx, f.scope, d.ID, secure.NewID()); !errors.Is(err, store.ErrDispatchApproval) {
		t.Fatal("rotated reviewer still authorized", err)
	}
}
func TestOutboundDispatchReviewsAndPoliciesStayTenantPartnerScoped(t *testing.T) {
	f, s, _, c := outboundFixture(t)
	d, _ := directDispatch(t, f, s, "direct", true)
	_, r, _ := proposeDispatch(t, f, s, d, c.ID, "request")
	for _, sameTenant := range []bool{true, false} {
		tenant := f.scope.Tenant
		if !sameTenant {
			tenant = secure.NewID()
		}
		partner := secure.NewID()
		token := filepath.Join(t.TempDir(), "different-scope.token")
		if err := secure.WriteToken(token); err != nil {
			t.Fatal(err)
		}
		if err := store.Provision(f.ctx, f.adminPath, tenant, partner, token); err != nil {
			t.Fatal(err)
		}
		secret, err := secure.ReadSecret(token, 64)
		if err != nil {
			t.Fatal(err)
		}
		scope := store.Scope{Tenant: tenant, Partner: partner, TokenHash: secure.Digest(secret.Bytes)}
		secret.Close()
		if _, err = s.DispatchReview(f.ctx, scope, r.ID); !errors.Is(err, store.ErrNotFound) {
			t.Fatal("cross-scope metadata disclosure", err)
		}
		page, err := s.DispatchReviews(f.ctx, scope, "", 50)
		if err != nil || len(page.Reviews) != 0 {
			t.Fatal(page, err)
		}
		policy, err := s.DispatchPolicy(f.ctx, scope)
		if err != nil || policy.Revision != 0 || policy.Mode != "author" {
			t.Fatal("cross-scope policy leaked", policy, err)
		}
	}
}
func TestOutboundDispatchRejectionAndPermissionChangesDoNotRestoreAuthority(t *testing.T) {
	f, s, reviewer, c := outboundFixture(t)
	d, _ := directDispatch(t, f, s, "direct", true)
	_, r, _ := proposeDispatch(t, f, s, d, c.ID, "request")
	_, first, err := decideDispatch(t, f, s, reviewer, r, "reject", "reject")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = decideDispatch(t, f, s, reviewer, r, "approve", "revive-rejected"); !errors.Is(err, store.ErrRevision) {
		t.Fatal(err)
	}
	_, fresh, _ := proposeDispatch(t, f, s, d, c.ID, "fresh")
	if _, _, err = decideDispatch(t, f, s, reviewer, fresh, "approve", "fresh-approve"); err != nil {
		t.Fatal(err)
	}
	_, again, err := decideDispatch(t, f, s, reviewer, r, "reject", "reject")
	if err != nil || !bytes.Equal(first.Resource, again.Resource) {
		t.Fatal("historical rejection changed", err)
	}
	if _, err = f.s.Custody.DB.ChangeAccount(f.ctx, f.scope, "remove-reviewer-inspect", store.AccountCommand{Operation: "update", ID: c.ID, ExpectedRevision: 1, Policy: &store.AccountPolicy{Label: "Approval without inspect", Root: "/", Permissions: []string{"workflow_approve"}}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.Claim(f.ctx, f.scope, d.ID, secure.NewID()); !errors.Is(err, store.ErrDispatchApproval) {
		t.Fatal("permission drift retained consent", err)
	}
	if _, err = s.DispatchReview(f.ctx, reviewer, r.ID); err == nil {
		t.Fatal("revoked inspection still disclosed metadata")
	}
}
