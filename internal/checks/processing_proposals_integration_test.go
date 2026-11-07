//go:build integration

package checks

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

type processingProposalFixture struct {
	f                                *fixture
	checks                           *Service
	wf                               *workflow.Service
	author, executor, reviewer       store.Scope
	authorID, executorID, reviewerID string
	request                          workflow.ProcessingProposalRequest
	source                           *store.File
}

func authoredProcessingFixture(t *testing.T) *processingProposalFixture {
	t.Helper()
	f := setup(t)
	s := &Service{Custody: f.wf.Custody}
	wf := &workflow.Service{Custody: s.Custody, Processor: s}
	registered, err := s.Register(f.ctx, f.scope, "authored-source-policy", PolicyRequest{Definition: testPolicy(t)})
	if err != nil {
		t.Fatal(err)
	}
	var input store.Configuration
	if json.Unmarshal(registered.Resource, &input) != nil {
		t.Fatal("source policy")
	}
	create := func(label, root string, permissions []string) (store.Scope, string) {
		t.Helper()
		mode := uint32(0777)
		if _, err := s.Custody.PathCommand(f.ctx, f.scope, "authored-directory-"+label, store.PathCommand{Operation: "mkdir", Path: root, Mode: &mode}); err != nil {
			t.Fatal(err)
		}
		command := store.AccountCommand{Operation: "create", ID: secure.NewID(), CredentialHash: secure.Digest([]byte(secure.NewID())), Policy: &store.AccountPolicy{Label: label, Root: root, Permissions: permissions}}
		if _, err := s.Custody.DB.ChangeAccount(f.ctx, f.scope, "authored-account-"+label, command); err != nil {
			t.Fatal(err)
		}
		return store.Scope{Tenant: f.scope.Tenant, Partner: f.scope.Partner, TokenHash: command.CredentialHash}, command.ID
	}
	author, authorID := create("designer", "/designer", []string{"workflow_manage"})
	executor, executorID := create("executor", "/processor", []string{"read", "write", "list", "check_run", "workflow_manage", "workflow_execute"})
	reviewer, reviewerID := create("reviewer", "/reviewer", []string{"inspect", "workflow_approve"})
	source, _, err := s.Custody.AcceptAt(f.ctx, executor, "authored-input", int64(len(goodCSV)), secure.Digest([]byte(goodCSV)), strings.NewReader(goodCSV), custody.UploadTarget{Path: "/input.csv"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Run(f.ctx, executor, source.ID, "authored-input-check"); err != nil {
		t.Fatal(err)
	}
	_, output := registerOutputFixture(t, f, s, store.AccountCommand{ID: executorID}, input)
	rules, err := NormalizeRecordProjection(testPolicy(t), RecordProjection{Schema: 1, Kind: "record_projection", SourcePolicyHash: input.Hash, OutputKind: "json_records", Columns: []ProjectionColumn{{Source: "account", Target: "account"}, {Source: "amount", Target: "total"}, {Source: "day", Target: "day"}}})
	if err != nil {
		t.Fatal(err)
	}
	definition := workflow.Definition{Schema: 3, Name: "Third-party authored settlement task", Processing: &workflow.ProcessingTask{ID: "project", Kind: "records.project", Definition: rules, OutputPolicy: workflow.Reference{ID: output.Policy.ID, Version: output.Policy.Version, Hash: output.Policy.Hash}, Reason: "Independently adopt and review bounded record rules"}}
	return &processingProposalFixture{f: f, checks: s, wf: wf, author: author, executor: executor, reviewer: reviewer, authorID: authorID, executorID: executorID, reviewerID: reviewerID, request: workflow.ProcessingProposalRequest{Executor: executorID, Definition: definition, ExpiresAt: time.Now().UTC().Truncate(time.Second).Add(time.Hour)}, source: source}
}

func proposeAuthoredTask(t *testing.T, x *processingProposalFixture, key string) *workflow.ProcessingProposalView {
	t.Helper()
	// Definition authorship opens no storage and needs no byte-processing port.
	metadata := &workflow.Service{Custody: &custody.Service{DB: x.checks.Custody.DB}}
	first, err := metadata.ProposeProcessingWorkflow(x.f.ctx, x.author, key, x.request)
	if err != nil {
		t.Fatal(err)
	}
	var receipt struct {
		Proposal store.ProcessingProposalSummary `json:"proposal"`
	}
	if json.Unmarshal(first.Resource, &receipt) != nil || receipt.Proposal.State != "pending" {
		t.Fatal("proposal receipt")
	}
	replay, err := metadata.ProposeProcessingWorkflow(x.f.ctx, x.author, key, x.request)
	if err != nil || !replay.Replayed || !sameJSON(first.Resource, replay.Resource) {
		t.Fatal("proposal replay changed original rules", err)
	}
	view, err := metadata.ProcessingProposal(x.f.ctx, x.author, receipt.Proposal.ID)
	if err != nil || !view.ParticipantsCurrent || view.Expired {
		t.Fatal("proposal metadata", err)
	}
	return view
}

func TestProcessingProposalActualAuthorWithoutBytesExecutorDraftAndIndependentApproval(t *testing.T) {
	x := authoredProcessingFixture(t)
	view := proposeAuthoredTask(t, x, "author-no-bytes-proposal")
	r := view.Proposal
	if _, _, err := x.checks.Custody.Download(x.f.ctx, x.author, x.source.ID); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("author gained source byte access", err)
	}
	if _, err := x.wf.ProcessingProposal(x.f.ctx, x.f.scope, r.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("unrelated administrator read private proposal", err)
	}
	decision := workflow.Decision{Hash: r.Hash, Revision: r.Revision}
	if _, err := x.wf.DecideProcessingProposal(x.f.ctx, x.author, r.ID, "author-cannot-adopt", "adopt", decision); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("author became executor", err)
	}
	adopted, err := x.wf.DecideProcessingProposal(x.f.ctx, x.executor, r.ID, "executor-adopts-draft", "adopt", decision)
	if err != nil {
		t.Fatal(err)
	}
	var receipt struct {
		Proposal store.ProcessingProposalSummary     `json:"proposal"`
		Workflow workflow.ProcessingReviewedWorkflow `json:"adopted_workflow"`
	}
	if json.Unmarshal(adopted.Resource, &receipt) != nil || receipt.Proposal.State != "adopted" || receipt.Workflow.State != "draft" || receipt.Workflow.ApprovalAuthority != 0 || receipt.Workflow.Hash != r.Definition.WorkflowHash {
		t.Fatal("adoption granted approval or changed task")
	}
	replay, err := x.wf.DecideProcessingProposal(x.f.ctx, x.executor, r.ID, "executor-adopts-draft", "adopt", decision)
	if err != nil || !replay.Replayed || !sameJSON(adopted.Resource, replay.Resource) {
		t.Fatal("adoption replay changed owned draft", err)
	}
	ref := workflow.Reference{ID: receipt.Workflow.ID, Version: receipt.Workflow.Version, Hash: receipt.Workflow.Hash}
	if _, err := x.wf.Configuration(x.f.ctx, x.author, ref.ID, ref.Version); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("author gained executor-owned configuration access", err)
	}
	if _, err := x.wf.Run(x.f.ctx, x.executor, "authored-not-approved", workflow.RunRequest{Workflow: ref, FileID: x.source.ID}); err == nil {
		t.Fatal("adoption authorized execution")
	}
	reviewed, err := x.wf.RequestProcessingReview(x.f.ctx, x.executor, "authored-independent-review", workflow.ProcessingReviewRequest{Workflow: ref, Revision: 1, Reviewer: x.reviewerID, ExpiresAt: x.request.ExpiresAt})
	if err != nil {
		t.Fatal(err)
	}
	var review store.ProcessingReview
	if json.Unmarshal(reviewed.Resource, &review) != nil {
		t.Fatal("review")
	}
	approved, err := x.wf.DecideProcessingReview(x.f.ctx, x.reviewer, review.ID, "authored-reviewer-approve", "approve", workflow.Decision{Hash: review.Hash, Revision: review.Revision})
	if err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(approved.Resource, &review) != nil {
		t.Fatal("review approval")
	}
	if _, err = x.wf.DecideProcessingReview(x.f.ctx, x.executor, review.ID, "authored-approval-adoption", "adopt", workflow.Decision{Hash: review.Hash, Revision: review.Revision}); err != nil {
		t.Fatal(err)
	}
	// Authorship is historical input,not ongoing approval authority. Revoking the
	// author cannot impersonate or replace the independent live reviewer.
	account, err := x.checks.Custody.DB.Account(x.f.ctx, x.f.scope, x.authorID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = x.checks.Custody.DB.ChangeAccount(x.f.ctx, x.f.scope, "authored-revoke-author", store.AccountCommand{Operation: "revoke", ID: account.ID, ExpectedRevision: account.Revision}); err != nil {
		t.Fatal(err)
	}
	current, err := x.wf.ProcessingProposal(x.f.ctx, x.executor, r.ID)
	if err != nil || current.ParticipantsCurrent {
		t.Fatal("revoked proposal participant remained current", err)
	}
	accepted, err := x.wf.Run(x.f.ctx, x.executor, "authored-approved-run", workflow.RunRequest{Workflow: ref, FileID: x.source.ID})
	if err != nil {
		t.Fatal(err)
	}
	var run store.WorkflowRun
	if json.Unmarshal(accepted.Resource, &run) != nil {
		t.Fatal("run")
	}
	worked, err := x.wf.Work(x.f.ctx, x.executor, run.ID, "authored-approved-work")
	if err != nil || worked.Processing == nil || worked.Processing.State != "completed" || worked.Status.Processing.Released {
		t.Fatal("independently approved authored task did not keep output held", err)
	}
	if _, _, err := x.checks.Custody.Download(x.f.ctx, x.executor, worked.Processing.FileID); !errors.Is(err, store.ErrState) {
		t.Fatal("authorship granted output release", err)
	}
}

func TestProcessingProposalActualWithdrawalAndRevokedBindingRefuseDraftAdoption(t *testing.T) {
	x := authoredProcessingFixture(t)
	view := proposeAuthoredTask(t, x, "withdraw-authored-proposal")
	r := view.Proposal
	if _, err := x.wf.DecideProcessingProposal(x.f.ctx, x.author, r.ID, "withdraw-authored", "withdraw", workflow.Decision{Hash: r.Hash, Revision: r.Revision}); err != nil {
		t.Fatal(err)
	}
	if _, err := x.wf.DecideProcessingProposal(x.f.ctx, x.executor, r.ID, "cannot-adopt-withdrawn", "adopt", workflow.Decision{Hash: r.Hash, Revision: 2}); err == nil {
		t.Fatal("withdrawn proposal created a draft")
	}
	second := proposeAuthoredTask(t, x, "revoke-author-before-adoption").Proposal
	account, err := x.checks.Custody.DB.Account(x.f.ctx, x.f.scope, x.authorID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = x.checks.Custody.DB.ChangeAccount(x.f.ctx, x.f.scope, "revoke-pending-author", store.AccountCommand{Operation: "revoke", ID: account.ID, ExpectedRevision: account.Revision}); err != nil {
		t.Fatal(err)
	}
	if _, err := x.wf.DecideProcessingProposal(x.f.ctx, x.executor, second.ID, "cannot-adopt-revoked", "adopt", workflow.Decision{Hash: second.Hash, Revision: second.Revision}); err == nil {
		t.Fatal("revoked participant authorized new adoption")
	}
	var drafts int
	if err = x.f.admin.QueryRow(x.f.ctx, `SELECT count(*) FROM workflow_revisions WHERE tenant_id=$1 AND partner_id=$2 AND actor_id=$3`, x.executor.Tenant, x.executor.Partner, x.executorID).Scan(&drafts); err != nil || drafts != 0 {
		t.Fatal("refused proposal left a partial draft", err)
	}
}
