package workflow

import (
	"context"
	"errors"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

const ProcessingProposalProfile = "processing-workflow-proposal-v1"

func processingProposalDefinition(d Definition, author, executor store.ExchangeParticipant, until, now time.Time) (store.ProcessingProposalDefinition, error) {
	bad := store.ProcessingProposalDefinition{}
	valid := func(p store.ExchangeParticipant) bool {
		return store.ValidID(p.Tenant) && store.ValidID(p.Partner) && store.ValidID(p.Actor) && p.AuthorityRevision > 0 && hashPattern.MatchString(p.RootPolicyDigest)
	}
	if !valid(author) || !valid(executor) || author.Actor == executor.Actor || author.Tenant != executor.Tenant || author.Partner != executor.Partner || now.IsZero() || !until.After(now) || until.After(now.Add(30*24*time.Hour)) || until.Nanosecond()%1000 != 0 {
		return bad, ErrInput
	}
	d, err := Normalize(d)
	if err != nil || d.Schema != 3 || d.Processing == nil || len(d.Steps) != 0 || d.Source != nil {
		return bad, ErrInput
	}
	raw, hash, err := digest(d)
	if err != nil || len(raw) > 24<<10 {
		return bad, ErrInput
	}
	return store.ProcessingProposalDefinition{Profile: ProcessingProposalProfile, Author: author, Executor: executor, Definition: raw, WorkflowHash: hash, ExpiresAt: until.UTC()}, nil
}

type ProcessingProposalRequest struct {
	Executor   string     `json:"executor_id"`
	Definition Definition `json:"definition"`
	ExpiresAt  time.Time  `json:"expires_at"`
}

type ProcessingProposalView struct {
	Profile             string                    `json:"profile"`
	Proposal            *store.ProcessingProposal `json:"proposal"`
	ParticipantsCurrent bool                      `json:"participant_bindings_current_at_observation"`
	Expired             bool                      `json:"expired_at_observation"`
	Effects             string                    `json:"effects"`
}

type processingProposalReceipt struct {
	Profile     string                          `json:"profile"`
	Observation string                          `json:"observation"`
	Proposal    store.ProcessingProposalSummary `json:"proposal"`
	Workflow    *ProcessingReviewedWorkflow     `json:"adopted_workflow,omitempty"`
}

func proposalParticipant(t *store.Transaction) store.ExchangeParticipant {
	return store.ExchangeParticipant{Tenant: t.Scope.Tenant, Partner: t.Scope.Partner, Actor: t.Actor, AuthorityRevision: t.AuthorityRevision, RootPolicyDigest: secure.Digest([]byte(t.Root))}
}

func proposalActor(t *store.Transaction, r *store.ProcessingProposal) error {
	if err := t.Require("workflow_manage"); err != nil {
		return err
	}
	actual := proposalParticipant(t)
	if r.Definition.Author.Tenant != t.Scope.Tenant || r.Definition.Author.Partner != t.Scope.Partner || r.Definition.Executor.Tenant != t.Scope.Tenant || r.Definition.Executor.Partner != t.Scope.Partner {
		return store.ErrIsolation
	}
	if actual != r.Definition.Author && actual != r.Definition.Executor {
		return store.ErrRevision
	}
	return nil
}

func normalizeProcessingProposal(r *store.ProcessingProposal) error {
	if r == nil || !store.ValidID(r.ID) || r.Revision < 1 || r.CreatedAt.IsZero() || r.Definition.Profile != ProcessingProposalProfile {
		return store.ErrIsolation
	}
	if (r.State == "adopted") != (r.Adopted != nil) {
		return store.ErrIsolation
	}
	switch r.State {
	case "pending", "adopted", "rejected", "withdrawn":
	default:
		return store.ErrIsolation
	}
	if r.State == "pending" && r.Revision != 1 || r.State != "pending" && r.Revision != 2 {
		return store.ErrIsolation
	}
	var d Definition
	if Decode(r.Definition.Definition, &d) != nil {
		return store.ErrIsolation
	}
	normalized, err := processingProposalDefinition(d, r.Definition.Author, r.Definition.Executor, r.Definition.ExpiresAt, r.CreatedAt)
	if err != nil || normalized.WorkflowHash != r.Definition.WorkflowHash {
		return store.ErrIsolation
	}
	if r.Adopted != nil && (!store.ValidID(r.Adopted.ID) || r.Adopted.Version < 1 || r.Adopted.Hash != normalized.WorkflowHash) {
		return store.ErrIsolation
	}
	_, hash, err := digest(normalized)
	if err != nil || hash != r.Hash {
		return store.ErrIsolation
	}
	r.Definition = normalized
	return nil
}

func processingProposalSummary(r *store.ProcessingProposal) store.ProcessingProposalSummary {
	return store.ProcessingProposalSummary{ID: r.ID, Author: r.Definition.Author.Actor, Executor: r.Definition.Executor.Actor, Hash: r.Hash, State: r.State, Revision: r.Revision, Adopted: r.Adopted, ExpiresAt: r.Definition.ExpiresAt}
}

func (s *Service) beginProcessingProposal(ctx context.Context, scope store.Scope) (*store.Transaction, error) {
	t, err := s.Custody.DB.BeginApproval(ctx, scope)
	if err != nil {
		return nil, err
	}
	if err = t.Require("workflow_manage"); err != nil {
		t.Tx.Rollback(ctx)
		return nil, err
	}
	return t, nil
}

func proposalBindings(ctx context.Context, t *store.Transaction, r *store.ProcessingProposal) (bool, error) {
	for _, party := range []struct {
		expected store.ExchangeParticipant
		executor bool
	}{{r.Definition.Author, false}, {r.Definition.Executor, true}} {
		actual, err := t.ProcessingProposalParticipant(ctx, party.expected.Actor, party.executor)
		if errors.Is(err, store.ErrNotFound) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if actual != party.expected {
			return false, nil
		}
	}
	return true, nil
}

func validProcessingProposalReceipt(receipt processingProposalReceipt, r *store.ProcessingProposal) bool {
	if receipt.Profile != ProcessingProposalProfile || receipt.Observation != "original-command-receipt" {
		return false
	}
	expected := processingProposalSummary(r)
	if receipt.Proposal.State == "pending" {
		// The original submission receipt remains pending after a later decision.
		expected.State, expected.Revision, expected.Adopted = "pending", 1, nil
	}
	a, b := receipt.Proposal, expected
	if a.ID != b.ID || a.Author != b.Author || a.Executor != b.Executor || a.Hash != b.Hash || a.State != b.State || a.Revision != b.Revision || !a.ExpiresAt.Equal(b.ExpiresAt) || (a.Adopted == nil) != (b.Adopted == nil) {
		return false
	}
	if a.Adopted != nil && *a.Adopted != *b.Adopted {
		return false
	}
	if (a.State == "adopted") != (receipt.Workflow != nil) {
		return false
	}
	if w := receipt.Workflow; w != nil && (w.ID != a.Adopted.ID || w.Version != a.Adopted.Version || w.Hash != a.Adopted.Hash || w.State != "draft" || w.Revision != 1 || w.ApprovalAuthority != 0) {
		return false
	}
	return true
}

func proposalReplay(ctx context.Context, t *store.Transaction, key, meaning, id string) (*Result, error) {
	prior, err := t.WorkflowReplay(ctx, key, meaning)
	if err != nil || prior == nil {
		return nil, err
	}
	var receipt processingProposalReceipt
	if Decode(prior, &receipt) != nil || receipt.Profile != ProcessingProposalProfile || receipt.Observation != "original-command-receipt" || (id != "" && receipt.Proposal.ID != id) {
		return nil, store.ErrIsolation
	}
	r, err := t.ProcessingProposal(ctx, receipt.Proposal.ID, false)
	if err != nil {
		return nil, err
	}
	if err = normalizeProcessingProposal(r); err != nil {
		return nil, err
	}
	if err = proposalActor(t, r); err != nil {
		return nil, err
	}
	if !validProcessingProposalReceipt(receipt, r) {
		return nil, store.ErrIsolation
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return &Result{Resource: prior, Replayed: true}, t.Tx.Commit(ctx)
}

func (s *Service) ProposeProcessingWorkflow(ctx context.Context, scope store.Scope, key string, request ProcessingProposalRequest) (*Result, error) {
	if !keyPattern.MatchString(key) || !store.ValidID(request.Executor) {
		return nil, ErrInput
	}
	normalized, err := Normalize(request.Definition)
	if err != nil || normalized.Schema != 3 {
		return nil, ErrInput
	}
	request.Definition = normalized
	request.ExpiresAt = request.ExpiresAt.UTC()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.beginProcessingProposal(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	_, meaning, _ := digest(struct {
		Kind    string
		Request ProcessingProposalRequest
	}{"propose_processing_workflow", request})
	if prior, err := proposalReplay(ctx, t, key, meaning, ""); err != nil || prior != nil {
		return prior, err
	}
	executor, err := t.ProcessingProposalParticipant(ctx, request.Executor, true)
	if err != nil {
		return nil, err
	}
	now, err := t.DatabaseTime(ctx)
	if err != nil {
		return nil, err
	}
	definition, err := processingProposalDefinition(normalized, proposalParticipant(t), executor, request.ExpiresAt, now)
	if err != nil {
		return nil, err
	}
	if err = t.ProcessingProposalAdmission(ctx, t.Actor, executor.Actor); err != nil {
		return nil, err
	}
	_, hash, err := digest(definition)
	if err != nil {
		return nil, err
	}
	r := &store.ProcessingProposal{ID: secure.NewID(), Definition: definition, Hash: hash, State: "pending", Revision: 1, CreatedAt: now}
	if err = t.SaveProcessingProposal(ctx, r, 0); err != nil {
		return nil, err
	}
	return result(t, ctx, key, meaning, r.ID, processingProposalReceipt{Profile: ProcessingProposalProfile, Observation: "original-command-receipt", Proposal: processingProposalSummary(r)})
}

func (s *Service) ProcessingProposal(ctx context.Context, scope store.Scope, id string) (*ProcessingProposalView, error) {
	if !store.ValidID(id) {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.beginProcessingProposal(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	r, err := t.ProcessingProposal(ctx, id, false)
	if err != nil {
		return nil, err
	}
	if err = normalizeProcessingProposal(r); err != nil {
		return nil, err
	}
	if err = proposalActor(t, r); err != nil {
		return nil, err
	}
	current, err := proposalBindings(ctx, t, r)
	if err != nil {
		return nil, err
	}
	now, err := t.DatabaseTime(ctx)
	if err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	v := &ProcessingProposalView{Profile: ProcessingProposalProfile, Proposal: r, ParticipantsCurrent: current, Expired: !now.Before(r.Definition.ExpiresAt), Effects: "Definition proposal only. Adoption validates the executor-owned output contract and creates a draft. Input validation,approval,file access,checks,release and execution remain separately authorized."}
	return v, t.Tx.Commit(ctx)
}

func (s *Service) ProcessingProposals(ctx context.Context, scope store.Scope, after string, limit int) (*store.ProcessingProposalPage, error) {
	if (after != "" && !store.ValidID(after)) || limit < 1 || limit > 100 {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.beginProcessingProposal(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	page, err := t.ProcessingProposals(ctx, after, limit)
	if err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return page, t.Tx.Commit(ctx)
}

func (s *Service) DecideProcessingProposal(ctx context.Context, scope store.Scope, id, key, action string, decision Decision) (*Result, error) {
	if !store.ValidID(id) || !keyPattern.MatchString(key) || !hashPattern.MatchString(decision.Hash) || decision.Revision < 1 || (action != "adopt" && action != "reject" && action != "withdraw") {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.beginProcessingProposal(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	_, meaning, _ := digest(struct {
		Kind, ID, Action string
		Decision         Decision
	}{"decide_processing_proposal", id, action, decision})
	if prior, err := proposalReplay(ctx, t, key, meaning, id); err != nil || prior != nil {
		return prior, err
	}
	r, err := t.ProcessingProposal(ctx, id, true)
	if err != nil {
		return nil, err
	}
	if err = normalizeProcessingProposal(r); err != nil {
		return nil, err
	}
	if err = proposalActor(t, r); err != nil {
		return nil, err
	}
	if r.Hash != decision.Hash || r.Revision != decision.Revision {
		return nil, store.ErrRevision
	}
	if r.State != "pending" {
		return nil, store.ErrState
	}
	var adopted *ProcessingReviewedWorkflow
	if action == "withdraw" {
		if t.Actor != r.Definition.Author.Actor {
			return nil, store.ErrForbidden
		}
		r.State = "withdrawn"
	} else {
		if t.Actor != r.Definition.Executor.Actor {
			return nil, store.ErrForbidden
		}
		if action == "reject" {
			r.State = "rejected"
		} else {
			now, err := t.DatabaseTime(ctx)
			if err != nil {
				return nil, err
			}
			if !now.Before(r.Definition.ExpiresAt) {
				return nil, store.ErrRevision
			}
			current, err := proposalBindings(ctx, t, r)
			if err != nil {
				return nil, err
			}
			if !current {
				return nil, store.ErrRevision
			}
			for _, grant := range []string{"read", "write", "check_run", "workflow_execute"} {
				if err = t.Require(grant); err != nil {
					return nil, err
				}
			}
			var d Definition
			if Decode(r.Definition.Definition, &d) != nil {
				return nil, store.ErrIsolation
			}
			c, err := StageDraft(ctx, t, DraftRequest{Definition: d})
			if err != nil {
				return nil, err
			}
			if c.State != "draft" || c.ApprovalAuthority != 0 || c.Hash != r.Definition.WorkflowHash {
				return nil, store.ErrIsolation
			}
			r.State = "adopted"
			r.Adopted = &store.OnboardingReference{ID: c.ID, Version: c.Version, Hash: c.Hash}
			adopted = &ProcessingReviewedWorkflow{ID: c.ID, Version: c.Version, Hash: c.Hash, State: c.State, Revision: c.Revision, ApprovalAuthority: c.ApprovalAuthority}
		}
	}
	before := r.Revision
	r.Revision++
	if err = t.SaveProcessingProposal(ctx, r, before); err != nil {
		return nil, err
	}
	return result(t, ctx, key, meaning, r.ID, processingProposalReceipt{Profile: ProcessingProposalProfile, Observation: "original-command-receipt", Proposal: processingProposalSummary(r), Workflow: adopted})
}
