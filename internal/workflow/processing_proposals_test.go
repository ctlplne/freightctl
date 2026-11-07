package workflow

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestProcessingProposalPinsDifferentAuthorAndExecutorWithoutFileOrApprovalAuthority(t *testing.T) {
	now := time.Date(2026, 11, 7, 6, 0, 0, 0, time.UTC)
	author := store.ExchangeParticipant{Tenant: secure.NewID(), Partner: secure.NewID(), Actor: secure.NewID(), AuthorityRevision: 1, RootPolicyDigest: secure.Digest([]byte("/designer"))}
	executor := author
	executor.Actor = secure.NewID()
	executor.RootPolicyDigest = secure.Digest([]byte("/processor"))
	d, err := Normalize(processingWorkflow(t))
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := processingProposalDefinition(d, author, executor, now.Add(time.Hour), now)
	if err != nil || proposal.Profile != "processing-workflow-proposal-v1" || proposal.Author != author || proposal.Executor != executor {
		t.Fatal("proposal lost independent participants", err)
	}
	var decoded Definition
	if Decode(proposal.Definition, &decoded) != nil {
		t.Fatal("proposal lost typed task")
	}
	raw, hash, err := digest(decoded)
	if err != nil || hash != proposal.WorkflowHash || string(raw) != string(proposal.Definition) {
		t.Fatal("proposal changed complete task meaning", err)
	}
	d.Processing.Definition.Columns[0].Target = "changed-after-proposal"
	if json.Unmarshal(proposal.Definition, &decoded) != nil || decoded.Processing.Definition.Columns[0].Target == "changed-after-proposal" {
		t.Fatal("caller changed proposed rules")
	}
	for _, change := range []func(*Definition, *store.ExchangeParticipant, *store.ExchangeParticipant, *time.Time){
		func(_ *Definition, a, e *store.ExchangeParticipant, _ *time.Time) { e.Actor = a.Actor },
		func(_ *Definition, _, e *store.ExchangeParticipant, _ *time.Time) { e.Tenant = secure.NewID() },
		func(_ *Definition, _, e *store.ExchangeParticipant, _ *time.Time) { e.Partner = secure.NewID() },
		func(_ *Definition, a, _ *store.ExchangeParticipant, _ *time.Time) { a.AuthorityRevision = 0 },
		func(_ *Definition, _, e *store.ExchangeParticipant, _ *time.Time) { e.RootPolicyDigest = "/untrusted" },
		func(d *Definition, _, _ *store.ExchangeParticipant, _ *time.Time) {
			d.Steps = []Step{{ID: "send", Kind: "sftp.deliver"}}
		},
		func(d *Definition, _, _ *store.ExchangeParticipant, _ *time.Time) {
			d.Processing.Definition.Engine = "shell"
		},
		func(_ *Definition, _, _ *store.ExchangeParticipant, t *time.Time) { *t = now },
		func(_ *Definition, _, _ *store.ExchangeParticipant, t *time.Time) { *t = now.Add(31 * 24 * time.Hour) },
	} {
		changed := processingWorkflow(t)
		a, e, until := author, executor, now.Add(time.Hour)
		change(&changed, &a, &e, &until)
		if _, err := processingProposalDefinition(changed, a, e, until, now); err == nil {
			t.Fatal("proposal accepted substituted scope,unbounded rules or implicit effect authority")
		}
	}
}

func TestProcessingProposalOwnDefinitionManagementDoesNotNeedByteAccessAndCannotBecomeApproval(t *testing.T) {
	now := time.Date(2026, 11, 7, 6, 0, 0, 0, time.UTC)
	a := store.ExchangeParticipant{Tenant: secure.NewID(), Partner: secure.NewID(), Actor: secure.NewID(), AuthorityRevision: 1, RootPolicyDigest: secure.Digest([]byte("/designer"))}
	e := a
	e.Actor = secure.NewID()
	e.RootPolicyDigest = secure.Digest([]byte("/processor"))
	d, err := processingProposalDefinition(processingWorkflow(t), a, e, now.Add(time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	_, hash, _ := digest(d)
	r := &store.ProcessingProposal{ID: secure.NewID(), Definition: d, Hash: hash, State: "pending", Revision: 1, CreatedAt: now}
	if err := normalizeProcessingProposal(r); err != nil {
		t.Fatal(err)
	}
	tx := &store.Transaction{Scope: store.Scope{Tenant: a.Tenant, Partner: a.Partner}, Actor: a.Actor, AuthorityRevision: 1, Root: "/designer", Permissions: []string{"workflow_manage"}}
	if err := proposalActor(tx, r); err != nil {
		t.Fatal("definition author needed file or execution authority", err)
	}
	if tx.Has("read") || tx.Has("write") || tx.Has("workflow_execute") || tx.Has("workflow_approve") {
		t.Fatal("proposal validation changed permissions")
	}
	for _, mutate := range []func(*store.Transaction){
		func(t *store.Transaction) { t.Actor = secure.NewID() },
		func(t *store.Transaction) { t.Root = "/other" },
		func(t *store.Transaction) { t.AuthorityRevision++ },
		func(t *store.Transaction) { t.Scope.Tenant = secure.NewID() },
	} {
		changed := *tx
		mutate(&changed)
		if err := proposalActor(&changed, r); err == nil {
			t.Fatal("changed actor scope accepted original proposal authority")
		}
	}
	without := *tx
	without.Permissions = []string{"read", "write", "workflow_execute"}
	if err := proposalActor(&without, r); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("execution acquired authorship control", err)
	}
	wire, _ := json.Marshal(r)
	for _, mutate := range []func(*store.ProcessingProposal){
		func(r *store.ProcessingProposal) { r.Definition.WorkflowHash = secure.Digest([]byte("other rules")) },
		func(r *store.ProcessingProposal) { r.Definition.Executor.AuthorityRevision++ },
		func(r *store.ProcessingProposal) { r.State = "approved" },
		func(r *store.ProcessingProposal) {
			r.Adopted = &store.OnboardingReference{ID: secure.NewID(), Version: 1, Hash: r.Definition.WorkflowHash}
		},
	} {
		var changed store.ProcessingProposal
		if json.Unmarshal(wire, &changed) != nil {
			t.Fatal("fixture")
		}
		mutate(&changed)
		if err := normalizeProcessingProposal(&changed); err == nil {
			t.Fatal("proposal changed under its original complete hash")
		}
	}
}

func TestProcessingProposalReplayBindsWholeHistoricalReceipt(t *testing.T) {
	now := time.Date(2026, 11, 7, 6, 0, 0, 0, time.UTC)
	a := store.ExchangeParticipant{Tenant: secure.NewID(), Partner: secure.NewID(), Actor: secure.NewID(), AuthorityRevision: 1, RootPolicyDigest: secure.Digest([]byte("/author"))}
	e := a
	e.Actor = secure.NewID()
	d, err := processingProposalDefinition(processingWorkflow(t), a, e, now.Add(time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	_, hash, _ := digest(d)
	r := &store.ProcessingProposal{ID: secure.NewID(), Definition: d, Hash: hash, State: "adopted", Revision: 2, CreatedAt: now, Adopted: &store.OnboardingReference{ID: secure.NewID(), Version: 1, Hash: d.WorkflowHash}}
	pending := processingProposalReceipt{Profile: ProcessingProposalProfile, Observation: "original-command-receipt", Proposal: processingProposalSummary(r)}
	pending.Proposal.State, pending.Proposal.Revision, pending.Proposal.Adopted = "pending", 1, nil
	adopted := processingProposalReceipt{Profile: ProcessingProposalProfile, Observation: "original-command-receipt", Proposal: processingProposalSummary(r), Workflow: &ProcessingReviewedWorkflow{ID: r.Adopted.ID, Version: 1, Hash: d.WorkflowHash, State: "draft", Revision: 1}}
	if !validProcessingProposalReceipt(pending, r) || !validProcessingProposalReceipt(adopted, r) {
		t.Fatal("historical pending or adoption receipt refused")
	}
	for _, mutate := range []func(*processingProposalReceipt){
		func(v *processingProposalReceipt) { v.Proposal.Author = secure.NewID() },
		func(v *processingProposalReceipt) { v.Proposal.Executor = secure.NewID() },
		func(v *processingProposalReceipt) { v.Proposal.ExpiresAt = v.Proposal.ExpiresAt.Add(time.Second) },
		func(v *processingProposalReceipt) { v.Proposal.State = "rejected" },
		func(v *processingProposalReceipt) { v.Proposal.Revision = 1 },
		func(v *processingProposalReceipt) { v.Proposal.Adopted.ID = secure.NewID() },
		func(v *processingProposalReceipt) { v.Workflow = nil },
		func(v *processingProposalReceipt) { v.Workflow.State = "approved" },
		func(v *processingProposalReceipt) { v.Workflow.ApprovalAuthority = 1 },
		func(v *processingProposalReceipt) { v.Workflow.Revision = 2 },
	} {
		raw, _ := json.Marshal(adopted)
		var v processingProposalReceipt
		if json.Unmarshal(raw, &v) != nil {
			t.Fatal("fixture")
		}
		mutate(&v)
		if validProcessingProposalReceipt(v, r) {
			t.Fatal("replay accepted substituted whole receipt meaning")
		}
	}
}
