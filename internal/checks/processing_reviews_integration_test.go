//go:build integration

package checks

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

type independentProcessing struct {
	f                *fixture
	checks           *Service
	workflows        *workflow.Service
	worker, reviewer store.Scope
	reviewerAccount  store.AccountCommand
	cfg              store.Configuration
	source           *store.File
	review           store.ProcessingReview
}

func sameProcessingReceipt(a, b []byte) bool {
	decode := func(raw []byte) (any, error) {
		var v any
		d := json.NewDecoder(bytes.NewReader(raw))
		d.UseNumber()
		err := d.Decode(&v)
		return v, err
	}
	x, e := decode(a)
	y, f := decode(b)
	return e == nil && f == nil && reflect.DeepEqual(x, y)
}

func independentProcessingFixture(t *testing.T) *independentProcessing {
	t.Helper()
	f := setup(t)
	s := &Service{Custody: f.wf.Custody}
	wf := &workflow.Service{Custody: s.Custody, Processor: s}
	registered, err := s.Register(f.ctx, f.scope, "independent-source-policy", PolicyRequest{Definition: testPolicy(t)})
	if err != nil {
		t.Fatal(err)
	}
	var input store.Configuration
	if json.Unmarshal(registered.Resource, &input) != nil {
		t.Fatal("input policy")
	}
	mode := uint32(0777)
	if _, err = s.Custody.PathCommand(f.ctx, f.scope, "independent-directory", store.PathCommand{Operation: "mkdir", Path: "/processor", Mode: &mode}); err != nil {
		t.Fatal(err)
	}
	create := func(label, root string, grants []string) (store.Scope, store.AccountCommand) {
		account := store.AccountCommand{Operation: "create", ID: secure.NewID(), CredentialHash: secure.Digest([]byte(secure.NewID())), Policy: &store.AccountPolicy{Label: label, Root: root, Permissions: grants}}
		if _, e := s.Custody.DB.ChangeAccount(f.ctx, f.scope, "create-"+account.ID, account); e != nil {
			t.Fatal(e)
		}
		return store.Scope{Tenant: f.scope.Tenant, Partner: f.scope.Partner, TokenHash: account.CredentialHash}, account
	}
	worker, _ := create("Processing worker without approval", "/processor", []string{"read", "write", "check_run", "workflow_manage", "workflow_execute"})
	reviewer, reviewerAccount := create("Independent metadata reviewer", "/", []string{"inspect", "workflow_approve"})
	source, _, err := s.Custody.AcceptAt(f.ctx, worker, "independent-input", int64(len(goodCSV)), secure.Digest([]byte(goodCSV)), strings.NewReader(goodCSV), custody.UploadTarget{Path: "/input.csv"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Run(f.ctx, worker, source.ID, "independent-input-check"); err != nil {
		t.Fatal(err)
	}
	rules, err := NormalizeRecordProjection(testPolicy(t), RecordProjection{Schema: 1, Kind: "record_projection", SourcePolicyHash: input.Hash, OutputKind: "json_records", MaxBytes: 8192, Columns: []ProjectionColumn{{Source: "amount", Target: "total"}, {Source: "account", Target: "account"}, {Source: "day", Target: "day"}}})
	if err != nil {
		t.Fatal(err)
	}
	output, err := projectionOutputPolicy(testPolicy(t), rules)
	if err != nil {
		t.Fatal(err)
	}
	registered, err = s.Register(f.ctx, f.scope, "independent-output-policy", PolicyRequest{ExpectedVersion: 1, Definition: output})
	if err != nil {
		t.Fatal(err)
	}
	var policy store.Configuration
	if json.Unmarshal(registered.Resource, &policy) != nil {
		t.Fatal("output policy")
	}
	definition := workflow.Definition{Schema: 3, Name: "Independently reviewed settlement task", Processing: &workflow.ProcessingTask{ID: "project", Kind: "records.project", Definition: rules, OutputPolicy: workflow.Reference{ID: policy.ID, Version: policy.Version, Hash: policy.Hash}, Reason: "Create held output under this worker authority"}}
	drafted, err := wf.Draft(f.ctx, worker, "independent-draft", workflow.DraftRequest{Definition: definition})
	if err != nil {
		t.Fatal(err)
	}
	x := &independentProcessing{f: f, checks: s, workflows: wf, worker: worker, reviewer: reviewer, reviewerAccount: reviewerAccount, source: source}
	if json.Unmarshal(drafted.Resource, &x.cfg) != nil {
		t.Fatal("draft")
	}
	request := workflow.ProcessingReviewRequest{Workflow: workflow.Reference{ID: x.cfg.ID, Version: x.cfg.Version, Hash: x.cfg.Hash}, Revision: x.cfg.Revision, Reviewer: reviewerAccount.ID, ExpiresAt: time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond)}
	proposed, err := wf.RequestProcessingReview(f.ctx, worker, "independent-review", request)
	if err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(proposed.Resource, &x.review) != nil {
		t.Fatal("review")
	}
	replayed, err := wf.RequestProcessingReview(f.ctx, worker, "independent-review", request)
	if err != nil || !replayed.Replayed || !sameProcessingReceipt(replayed.Resource, proposed.Resource) {
		t.Fatal("original proposal changed on recovery", err)
	}
	return x
}
func approveIndependentProcessing(t *testing.T, x *independentProcessing) {
	t.Helper()
	decision := workflow.Decision{Hash: x.review.Hash, Revision: x.review.Revision}
	if _, err := x.workflows.DecideProcessingReview(x.f.ctx, x.worker, x.review.ID, "self-approval", "approve", decision); err == nil {
		t.Fatal("owner approved its own independent review")
	}
	approved, err := x.workflows.DecideProcessingReview(x.f.ctx, x.reviewer, x.review.ID, "independent-approval", "approve", decision)
	if err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(approved.Resource, &x.review) != nil || x.review.State != "approved" {
		t.Fatal("approval")
	}
	decision = workflow.Decision{Hash: x.review.Hash, Revision: x.review.Revision}
	adopted, err := x.workflows.DecideProcessingReview(x.f.ctx, x.worker, x.review.ID, "independent-adoption", "adopt", decision)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Review   store.ProcessingReview `json:"review"`
		Workflow store.Configuration    `json:"workflow"`
	}
	if json.Unmarshal(adopted.Resource, &result) != nil || result.Review.State != "adopted" || result.Review.Hash != x.review.Hash || result.Workflow.State != "approved" || result.Workflow.ID != x.cfg.ID || result.Workflow.Hash != x.cfg.Hash || result.Workflow.Version != x.cfg.Version || result.Workflow.Revision != x.cfg.Revision+1 {
		t.Fatal("adoption")
	}
	x.review, x.cfg = result.Review, result.Workflow
	replayed, err := x.workflows.DecideProcessingReview(x.f.ctx, x.worker, x.review.ID, "independent-adoption", "adopt", decision)
	if err != nil || !replayed.Replayed || !sameProcessingReceipt(replayed.Resource, adopted.Resource) {
		t.Fatal("original adoption changed on recovery", err)
	}
}
func independentRun(t *testing.T, x *independentProcessing, key string) store.WorkflowRun {
	t.Helper()
	result, err := x.workflows.Run(x.f.ctx, x.worker, key, workflow.RunRequest{Workflow: workflow.Reference{ID: x.cfg.ID, Version: x.cfg.Version, Hash: x.cfg.Hash}, FileID: x.source.ID})
	if err != nil {
		t.Fatal(err)
	}
	var run store.WorkflowRun
	if json.Unmarshal(result.Resource, &run) != nil {
		t.Fatal("run")
	}
	return run
}
func TestProcessingReviewActualIndependentReviewerAndConfinedWorkerKeepBytesAndReleaseSeparate(t *testing.T) {
	x := independentProcessingFixture(t)
	if _, err := x.workflows.Decide(x.f.ctx, x.worker, x.cfg.ID, x.cfg.Version, "worker-cannot-approve", "approve", workflow.Decision{Hash: x.cfg.Hash, Revision: 1}); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("worker acquired ordinary approval", err)
	}
	disclosed, err := x.workflows.ProcessingReview(x.f.ctx, x.reviewer, x.review.ID)
	if err != nil || disclosed.Definition.Workflow.Hash != x.cfg.Hash {
		t.Fatal("reviewer cannot inspect exact disclosed definition", err)
	}
	if _, err = x.workflows.Configuration(x.f.ctx, x.reviewer, x.cfg.ID, x.cfg.Version); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("review exposed another actor's configuration store", err)
	}
	if _, err = x.checks.Get(x.f.ctx, x.reviewer, x.source.ID); err == nil {
		t.Fatal("definition review granted payload/check access")
	}
	if _, err = x.workflows.ProcessingReview(x.f.ctx, x.f.scope, x.review.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("unrelated administrator discovered a private review", err)
	}
	approveIndependentProcessing(t, x)
	run := independentRun(t, x, "independently-approved-run")
	worked, err := x.workflows.Work(x.f.ctx, x.worker, run.ID, "independently-approved-work")
	if err != nil || worked.Processing == nil || worked.Status.ObservedReason != "output_held" {
		t.Fatal("independent task did not produce a held output", err)
	}
	checked, err := x.checks.Get(x.f.ctx, x.worker, worked.Processing.FileID)
	if err != nil || checked.Check.State != "held" || checked.Check.Attempts != 0 {
		t.Fatal("approval inherited output checks or release", err)
	}
	if _, err = x.checks.Release(x.f.ctx, x.worker, worked.Processing.FileID, "worker-cannot-release", releaseDecision(checked.Check)); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("review granted release", err)
	}
	if _, err = x.workflows.Work(x.f.ctx, x.reviewer, run.ID, "reviewer-cannot-work"); err == nil {
		t.Fatal("approval granted worker execution")
	}
}
func TestProcessingReviewActualWithdrawalBlocksNewAndDirectWorkWithoutErasingOriginalReceipts(t *testing.T) {
	x := independentProcessingFixture(t)
	approveIndependentProcessing(t, x)
	run := independentRun(t, x, "before-review-withdrawal")
	status, err := x.workflows.Status(x.f.ctx, x.worker, run.ID)
	if err != nil || status.Processing == nil {
		t.Fatal(err)
	}
	_, err = x.workflows.DecideProcessingReview(x.f.ctx, x.reviewer, x.review.ID, "withdraw-exact-review", "withdraw", workflow.Decision{Hash: x.review.Hash, Revision: x.review.Revision})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = x.workflows.Run(x.f.ctx, x.worker, "after-review-withdrawal", workflow.RunRequest{Workflow: workflow.Reference{ID: x.cfg.ID, Version: x.cfg.Version, Hash: x.cfg.Hash}, FileID: x.source.ID}); err == nil {
		t.Fatal("withdrawal fell back to ordinary approval")
	}
	if _, err = x.workflows.Work(x.f.ctx, x.worker, run.ID, "work-after-withdrawal"); err == nil {
		t.Fatal("withdrawn independent decision executed")
	}
	if _, err = x.checks.StartProjection(x.f.ctx, x.worker, status.Processing.ID, "direct-worker-bypass", ProjectionStartDecision{Hash: status.Processing.Hash, Revision: status.Processing.Revision}); err == nil {
		t.Fatal("direct projection worker bypassed withdrawal")
	}
	observed, err := x.workflows.Status(x.f.ctx, x.worker, run.ID)
	if err != nil || observed.Processing.Current || observed.ObservedReason != "processing_binding_changed" {
		t.Fatal("withdrawal lost honest current status", err)
	}
	replay, err := x.workflows.Run(x.f.ctx, x.worker, "before-review-withdrawal", workflow.RunRequest{Workflow: workflow.Reference{ID: x.cfg.ID, Version: x.cfg.Version, Hash: x.cfg.Hash}, FileID: x.source.ID})
	if err != nil || !replay.Replayed {
		t.Fatal("withdrawal erased original acceptance", err)
	}
	if _, err = x.workflows.Cancel(x.f.ctx, x.worker, run.ID, "cancel-after-withdrawal", workflow.Decision{Hash: run.WorkflowHash, Revision: run.Revision}); err != nil {
		t.Fatal("withdrawal blocked safe cancellation", err)
	}
}
func TestProcessingReviewActualSQLRequiresIndependentDecisionAndAtomicAdoption(t *testing.T) {
	x := independentProcessingFixture(t)
	t1, err := x.checks.Custody.DB.BeginApproval(x.f.ctx, x.worker)
	if err != nil {
		t.Fatal(err)
	}
	cfg := x.cfg
	cfg.State = "approved"
	cfg.Revision++
	cfg.ApprovalAuthority = t1.AuthorityRevision
	err = t1.SaveConfiguration(x.f.ctx, false, &cfg, 1)
	t1.Tx.Rollback(x.f.ctx)
	if err == nil {
		t.Fatal("SQL accepted owner-forged workflow approval")
	}
	t1, err = x.checks.Custody.DB.BeginApproval(x.f.ctx, x.worker)
	if err != nil {
		t.Fatal(err)
	}
	review := x.review
	review.State = "approved"
	review.Revision++
	err = t1.SaveProcessingReview(x.f.ctx, &review, 1)
	t1.Tx.Rollback(x.f.ctx)
	if err == nil {
		t.Fatal("SQL accepted owner-forged independent decision")
	}
	approved, err := x.workflows.DecideProcessingReview(x.f.ctx, x.reviewer, x.review.ID, "sql-independent-approval", "approve", workflow.Decision{Hash: x.review.Hash, Revision: 1})
	if err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(approved.Resource, &review) != nil {
		t.Fatal("approved review")
	}
	t1, err = x.checks.Custody.DB.BeginApproval(x.f.ctx, x.worker)
	if err != nil {
		t.Fatal(err)
	}
	review.State = "adopted"
	review.Revision++
	review.AdoptedRevision = review.Revision
	err = t1.SaveProcessingReview(x.f.ctx, &review, 2)
	if err == nil {
		err = t1.Tx.Commit(x.f.ctx)
	} else {
		t1.Tx.Rollback(x.f.ctx)
	}
	if err == nil {
		t.Fatal("adoption committed without matching workflow transition")
	}
	current, err := x.workflows.ProcessingReview(x.f.ctx, x.worker, x.review.ID)
	if err != nil || current.State != "approved" || current.AdoptedRevision != 0 {
		t.Fatal("failed adoption escaped transaction rollback", err)
	}
}
func TestProcessingReviewActualReviewerRevocationStopsQueuedWork(t *testing.T) {
	x := independentProcessingFixture(t)
	approveIndependentProcessing(t, x)
	run := independentRun(t, x, "reviewer-before-revoke")
	account, err := x.checks.Custody.DB.Account(x.f.ctx, x.f.scope, x.reviewerAccount.ID)
	if err != nil {
		t.Fatal(err)
	}
	command := store.AccountCommand{Operation: "revoke", ID: account.ID, ExpectedRevision: account.Revision}
	if _, err = x.checks.Custody.DB.ChangeAccount(x.f.ctx, x.f.scope, "revoke-processing-reviewer", command); err != nil {
		t.Fatal(err)
	}
	if _, err = x.workflows.Work(x.f.ctx, x.worker, run.ID, "after-reviewer-revoked"); err == nil {
		t.Fatal("revoked reviewer authorized queued processing")
	}
	observed, err := x.workflows.Status(x.f.ctx, x.worker, run.ID)
	if err != nil || observed.Processing.Current {
		t.Fatal("revoked reviewer shown current", err)
	}
}
