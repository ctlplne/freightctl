package workflow

import (
	"context"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

type OnboardingApprovalPolicyChange struct {
	ExpectedRevision int64  `json:"expected_revision"`
	Mode             string `json:"mode"`
}
type OnboardingApprovalSelection struct {
	ReleaseID string `json:"release_id"`
	Decision
	ReviewerID string `json:"reviewer_id"`
}
type OnboardingApprovalProposal struct {
	Selection OnboardingApprovalSelection `json:"selection"`
	Hash      string                      `json:"definition_hash"`
}
type OnboardingApprovalPreview struct {
	Definition       store.OnboardingApprovalDefinition `json:"definition"`
	Hash             string                             `json:"definition_hash"`
	ExternalContact  bool                               `json:"external_contact"`
	GrantsFileAccess bool                               `json:"grants_file_access"`
}
type OnboardingApprovalResult struct {
	Kind   string                          `json:"kind"`
	Review store.OnboardingApprovalSummary `json:"review"`
}
type OnboardingApprovalPolicyResult struct {
	Kind   string                         `json:"kind"`
	Policy store.OnboardingApprovalPolicy `json:"policy"`
}

func (s *Service) approvalBegin(ctx context.Context, scope store.Scope) (*store.Transaction, error) {
	t, err := s.Custody.DB.BeginApproval(ctx, scope)
	if err != nil {
		return nil, err
	}
	if t.Root != "/" || (!t.Has("workflow_manage") && !t.Has("workflow_approve") && !t.Has("accounts_manage")) {
		t.Tx.Rollback(ctx)
		return nil, store.ErrForbidden
	}
	return t, nil
}
func (s *Service) OnboardingApprovalPolicy(ctx context.Context, scope store.Scope) (*store.OnboardingApprovalPolicy, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.approvalBegin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	p, err := t.OnboardingApprovalPolicy(ctx)
	if err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return p, t.Tx.Commit(ctx)
}
func (s *Service) ChangeOnboardingApprovalPolicy(ctx context.Context, scope store.Scope, key string, input OnboardingApprovalPolicyChange) (*Result, error) {
	if !keyPattern.MatchString(key) || input.ExpectedRevision < 0 || (input.Mode != "author" && input.Mode != "independent") {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.approvalBegin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	for _, p := range []string{"admin", "accounts_manage"} {
		if err = t.Require(p); err != nil {
			return nil, err
		}
	}
	_, meaning, err := digest(struct {
		Kind  string
		Input OnboardingApprovalPolicyChange
	}{"onboarding_approval_policy", input})
	if err != nil {
		return nil, err
	}
	if prior, err := replay(t, ctx, key, meaning); err != nil || prior != nil {
		return prior, err
	}
	if _, err = t.Tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, scope.Tenant+":"+scope.Partner+":onboarding-approval-policy"); err != nil {
		return nil, err
	}
	current, err := t.OnboardingApprovalPolicy(ctx)
	if err != nil {
		return nil, err
	}
	if current.Revision != input.ExpectedRevision {
		return nil, store.ErrRevision
	}
	p := &store.OnboardingApprovalPolicy{OnboardingApprovalBinding: store.OnboardingApprovalBinding{Revision: current.Revision + 1, Mode: input.Mode}, Author: t.Actor}
	if err = t.SaveOnboardingApprovalPolicy(ctx, p); err != nil {
		return nil, err
	}
	return approvalReceipt(ctx, t, key, meaning, t.Scope.Partner, OnboardingApprovalPolicyResult{Kind: "onboarding_approval_policy", Policy: *p})
}
func approvalReceipt(ctx context.Context, t *store.Transaction, key, meaning, id string, result any) (*Result, error) {
	if err := t.WorkflowReceipt(ctx, key, meaning, id, result); err != nil {
		return nil, err
	}
	data, err := t.WorkflowReplay(ctx, key, meaning)
	if err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return &Result{Resource: data}, t.Tx.Commit(ctx)
}
func validApprovalSelection(x OnboardingApprovalSelection) bool {
	return store.ValidID(x.ReleaseID) && store.ValidID(x.ReviewerID) && x.Revision == 1 && hashPattern.MatchString(x.Hash)
}
func (s *Service) approvalPreview(ctx context.Context, t *store.Transaction, x OnboardingApprovalSelection) (*OnboardingApprovalPreview, error) {
	if x.ReviewerID == t.Actor {
		return nil, store.ErrForbidden
	}
	if err := t.Require("workflow_manage"); err != nil {
		return nil, err
	}
	r, err := t.OnboardingRelease(ctx, x.ReleaseID, true)
	if err != nil {
		return nil, err
	}
	if r.State != "proposed" || r.Revision != x.Revision || r.Hash != x.Hash {
		return nil, store.ErrRevision
	}
	current, err := s.releasePreview(ctx, t, releaseSelection(r.Definition))
	if err != nil {
		return nil, err
	}
	if current.Hash != r.Hash {
		return nil, store.ErrRevision
	}
	policy, err := t.OnboardingApprovalPolicy(ctx)
	if err != nil {
		return nil, err
	}
	if policy.Mode != "independent" || r.Definition.ApprovalPolicy == nil || *r.Definition.ApprovalPolicy != policy.OnboardingApprovalBinding {
		return nil, store.ErrState
	}
	authority, err := t.OnboardingApprovalReviewer(ctx, x.ReviewerID)
	if err != nil {
		return nil, err
	}
	out := &OnboardingApprovalPreview{Definition: store.OnboardingApprovalDefinition{Schema: 1, Author: t.Actor, Reviewer: x.ReviewerID, ReviewerAuthority: authority, Policy: policy.OnboardingApprovalBinding, ReleaseID: r.ID, ReleaseRevision: r.Revision, ReleaseHash: r.Hash, Release: r.Definition, Effects: []store.OnboardingApprovalEffect{}}}
	for _, test := range current.Tests {
		out.Definition.Effects = append(out.Definition.Effects, store.OnboardingApprovalEffect{RequirementID: test.Definition.RequirementID, File: test.Definition.File, Effect: test.Definition.Effect})
	}
	b, hash, err := digest(out.Definition)
	if err != nil {
		return nil, err
	}
	if len(b) > 24<<10 {
		return nil, store.ErrLimit
	}
	out.Hash = hash
	return out, nil
}
func (s *Service) PreviewOnboardingApproval(ctx context.Context, scope store.Scope, x OnboardingApprovalSelection) (*OnboardingApprovalPreview, error) {
	if !validApprovalSelection(x) {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.testBegin(ctx, scope, false)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	p, err := s.approvalPreview(ctx, t, x)
	if err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return p, t.Tx.Commit(ctx)
}
func (s *Service) ProposeOnboardingApproval(ctx context.Context, scope store.Scope, key string, x OnboardingApprovalProposal) (*Result, error) {
	if !validApprovalSelection(x.Selection) || !hashPattern.MatchString(x.Hash) || !keyPattern.MatchString(key) {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.testBegin(ctx, scope, false)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if err = t.Require("workflow_manage"); err != nil {
		return nil, err
	}
	_, meaning, err := digest(struct {
		Kind  string
		Input OnboardingApprovalProposal
	}{"onboarding_approval_propose", x})
	if err != nil {
		return nil, err
	}
	if prior, err := replay(t, ctx, key, meaning); err != nil || prior != nil {
		return prior, err
	}
	if _, err = t.Tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, scope.Tenant+":"+scope.Partner+":"+t.Actor+":onboarding-approval-admission"); err != nil {
		return nil, err
	}
	var pending int
	if err = t.Tx.QueryRow(ctx, `SELECT count(*) FROM onboarding_approval_reviews WHERE actor_id=$1 AND state='pending'`, t.Actor).Scan(&pending); err != nil {
		return nil, err
	}
	if pending >= 128 {
		return nil, store.ErrLimit
	}
	p, err := s.approvalPreview(ctx, t, x.Selection)
	if err != nil {
		return nil, err
	}
	if p.Hash != x.Hash {
		return nil, store.ErrRevision
	}
	var exists bool
	if err = t.Tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM onboarding_approval_reviews WHERE release_id=$1 AND state IN ('pending','approved'))`, p.Definition.ReleaseID).Scan(&exists); err != nil {
		return nil, err
	}
	if exists {
		return nil, store.ErrState
	}
	now, err := t.DatabaseTime(ctx)
	if err != nil {
		return nil, err
	}
	r := &store.OnboardingApprovalReview{OnboardingApprovalSummary: store.OnboardingApprovalSummary{ID: secure.NewID(), Author: t.Actor, Reviewer: p.Definition.Reviewer, Hash: p.Hash, State: "pending", Revision: 1, CreatedAt: now}, Definition: p.Definition}
	if err = t.SaveOnboardingApprovalReview(ctx, r, 0); err != nil {
		return nil, err
	}
	return approvalReceipt(ctx, t, key, meaning, r.ID, OnboardingApprovalResult{Kind: "onboarding_approval", Review: r.OnboardingApprovalSummary})
}
func (s *Service) OnboardingApprovalStatus(ctx context.Context, scope store.Scope, id string) (*store.OnboardingApprovalReview, error) {
	if !store.ValidID(id) {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.approvalBegin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	r, err := t.OnboardingApprovalReview(ctx, id, false)
	if err != nil {
		return nil, err
	}
	if t.Actor == r.Reviewer {
		if err = t.Require("inspect"); err != nil {
			return nil, err
		}
		if err = t.Require("workflow_approve"); err != nil {
			return nil, err
		}
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return r, t.Tx.Commit(ctx)
}
func (s *Service) ListOnboardingApprovals(ctx context.Context, scope store.Scope, after string, limit int) (*store.OnboardingApprovalPage, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.approvalBegin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	p, err := t.OnboardingApprovalReviews(ctx, after, limit)
	if err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return p, t.Tx.Commit(ctx)
}
func (s *Service) DecideOnboardingApproval(ctx context.Context, scope store.Scope, id, action, key string, x Decision) (*Result, error) {
	if !store.ValidID(id) || !keyPattern.MatchString(key) || x.Revision < 1 || !hashPattern.MatchString(x.Hash) || (action != "approve" && action != "reject" && action != "withdraw") {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.approvalBegin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if action == "withdraw" {
		err = t.Require("workflow_manage")
	} else {
		err = t.Require("workflow_approve")
		if err == nil {
			err = t.Require("inspect")
		}
	}
	if err != nil {
		return nil, err
	}
	_, meaning, err := digest(struct {
		Kind, ID, Action string
		Decision         Decision
	}{"onboarding_approval_decide", id, action, x})
	if err != nil {
		return nil, err
	}
	if prior, err := replay(t, ctx, key, meaning); err != nil || prior != nil {
		return prior, err
	}
	if _, err = t.Tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, scope.Tenant+":"+scope.Partner+":onboarding-approval-policy"); err != nil {
		return nil, err
	}
	r, err := t.OnboardingApprovalReview(ctx, id, true)
	if err != nil {
		return nil, err
	}
	if r.Hash != x.Hash || r.Revision != x.Revision {
		return nil, store.ErrRevision
	}
	if action == "withdraw" {
		if t.Actor != r.Author {
			return nil, store.ErrForbidden
		}
		if r.State != "pending" && r.State != "approved" {
			return nil, store.ErrState
		}
		r.State = "withdrawn"
	} else {
		if t.Actor != r.Reviewer || t.Actor == r.Author {
			return nil, store.ErrForbidden
		}
		if r.State != "pending" {
			return nil, store.ErrState
		}
		p, err := t.OnboardingApprovalPolicy(ctx)
		if err != nil {
			return nil, err
		}
		authority, err := t.OnboardingApprovalReviewer(ctx, t.Actor)
		if err != nil {
			return nil, err
		}
		if p.OnboardingApprovalBinding != r.Definition.Policy || authority != r.Definition.ReviewerAuthority {
			return nil, store.ErrRevision
		}
		if action == "approve" {
			r.State = "approved"
		} else {
			r.State = "rejected"
		}
	}
	previous := r.Revision
	r.Revision++
	if err = t.SaveOnboardingApprovalReview(ctx, r, previous); err != nil {
		return nil, err
	}
	return approvalReceipt(ctx, t, key, meaning, r.ID, OnboardingApprovalResult{Kind: "onboarding_approval", Review: r.OnboardingApprovalSummary})
}
