package delivery

import (
	"context"
	"encoding/json"
	"path"
	"regexp"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

var dispatchHashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type DispatchDecision struct {
	Hash     string `json:"definition_hash"`
	Revision int64  `json:"expected_revision"`
}
type DispatchPolicyChange struct {
	ExpectedRevision int64  `json:"expected_revision"`
	Mode             string `json:"mode"`
}
type DispatchSelection struct {
	DeliveryID string `json:"delivery_id"`
	DispatchDecision
	ReviewerID string `json:"reviewer_id"`
}
type DispatchProposal struct {
	Selection DispatchSelection `json:"selection"`
	Hash      string            `json:"definition_hash"`
}
type DispatchPreview struct {
	Definition       store.OutboundDispatchDefinition `json:"definition"`
	Hash             string                           `json:"definition_hash"`
	ExternalContact  bool                             `json:"external_contact"`
	GrantsFileAccess bool                             `json:"grants_file_access"`
}
type DispatchResult struct {
	Resource json.RawMessage `json:"resource"`
	Replayed bool            `json:"replayed"`
}
type DispatchReviewResult struct {
	Kind   string                        `json:"kind"`
	Review store.OutboundDispatchSummary `json:"review"`
}
type DispatchPolicyResult struct {
	Kind   string                       `json:"kind"`
	Policy store.OutboundDispatchPolicy `json:"policy"`
}
type DispatchDeliveryView struct {
	ID              string                       `json:"id"`
	Hash            string                       `json:"definition_hash"`
	State           string                       `json:"state"`
	Revision        int64                        `json:"revision"`
	Attempts        int                          `json:"attempts"`
	Policy          store.ApprovalPolicyBinding  `json:"policy"`
	CurrentPolicy   store.ApprovalPolicyBinding  `json:"current_policy"`
	CurrentApproval bool                         `json:"current_approval"`
	Reviewable      bool                         `json:"reviewable"`
	Source          store.File                   `json:"source"`
	Effect          store.OutboundDispatchEffect `json:"effect"`
}

func dispatchDigest(v any) (json.RawMessage, string, error) {
	b, e := json.Marshal(v)
	return b, secure.Digest(b), e
}
func BindDispatchPolicy(ctx context.Context, t *store.Transaction, d *Definition) error {
	p, err := t.OutboundDispatchPolicy(ctx)
	if err != nil {
		return err
	}
	if p.Revision > 0 {
		b := p.ApprovalPolicyBinding
		d.DispatchPolicy = &b
	}
	return nil
}
func (s *Service) dispatchBegin(ctx context.Context, scope store.Scope) (*store.Transaction, error) {
	t, err := s.Custody.DB.BeginApproval(ctx, scope)
	if err != nil {
		return nil, err
	}
	if t.Root != "/" || (!(t.Has("read") && t.Has("deliver")) && !(t.Has("inspect") && t.Has("workflow_approve")) && !(t.Has("admin") && t.Has("accounts_manage"))) {
		t.Tx.Rollback(ctx)
		return nil, store.ErrForbidden
	}
	return t, nil
}
func dispatchReplay(ctx context.Context, t *store.Transaction, key, meaning string) (*DispatchResult, error) {
	b, err := t.WorkflowReplay(ctx, key, meaning)
	if err != nil || b == nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return &DispatchResult{Resource: b, Replayed: true}, t.Tx.Commit(ctx)
}
func dispatchReceipt(ctx context.Context, t *store.Transaction, key, meaning, id string, v any) (*DispatchResult, error) {
	if err := t.WorkflowReceipt(ctx, key, meaning, id, v); err != nil {
		return nil, err
	}
	b, err := t.WorkflowReplay(ctx, key, meaning)
	if err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return &DispatchResult{Resource: b}, t.Tx.Commit(ctx)
}
func (s *Service) DispatchPolicy(ctx context.Context, scope store.Scope) (*store.OutboundDispatchPolicy, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.dispatchBegin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	p, err := t.OutboundDispatchPolicy(ctx)
	if err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return p, t.Tx.Commit(ctx)
}
func (s *Service) ChangeDispatchPolicy(ctx context.Context, scope store.Scope, key string, x DispatchPolicyChange) (*DispatchResult, error) {
	if !keyPattern.MatchString(key) || x.ExpectedRevision < 0 || (x.Mode != "author" && x.Mode != "independent") {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.dispatchBegin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	for _, g := range []string{"admin", "accounts_manage"} {
		if err = t.Require(g); err != nil {
			return nil, err
		}
	}
	_, meaning, err := dispatchDigest(struct {
		Kind  string
		Input DispatchPolicyChange
	}{"outbound_dispatch_policy", x})
	if err != nil {
		return nil, err
	}
	if prior, err := dispatchReplay(ctx, t, key, meaning); err != nil || prior != nil {
		return prior, err
	}
	if _, err = t.Tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, scope.Tenant+":"+scope.Partner+":outbound-dispatch-policy"); err != nil {
		return nil, err
	}
	p, err := t.OutboundDispatchPolicy(ctx)
	if err != nil {
		return nil, err
	}
	if p.Revision != x.ExpectedRevision {
		return nil, store.ErrRevision
	}
	next := &store.OutboundDispatchPolicy{ApprovalPolicyBinding: store.ApprovalPolicyBinding{Revision: p.Revision + 1, Mode: x.Mode}, Author: t.Actor}
	if err = t.SaveOutboundDispatchPolicy(ctx, next); err != nil {
		return nil, err
	}
	return dispatchReceipt(ctx, t, key, meaning, scope.Partner, DispatchPolicyResult{Kind: "outbound_dispatch_policy", Policy: *next})
}
func dispatchDefinition(d *store.Delivery) (*Definition, error) {
	var spec Definition
	if json.Unmarshal(d.Definition, &spec) != nil || !validProtocolDefinition(&spec) || spec.Source.ID != d.FileID {
		return nil, store.ErrIsolation
	}
	b, err := json.Marshal(spec)
	if err != nil || secure.Digest(b) != d.DefinitionHash {
		return nil, store.ErrIsolation
	}
	return &spec, nil
}
func (s *Service) dispatchSource(ctx context.Context, t *store.Transaction, id string, lock bool) (*store.Delivery, *Definition, error) {
	if err := require(t, false); err != nil {
		return nil, nil, err
	}
	d, err := t.Delivery(ctx, id, lock)
	if err != nil {
		return nil, nil, err
	}
	spec, err := dispatchDefinition(d)
	if err != nil {
		return nil, nil, err
	}
	if spec.Authority != t.AuthorityRevision || spec.Root != t.Root {
		return nil, nil, store.ErrUnauthorized
	}
	if err = t.FileAccessible(ctx, d.FileID); err != nil {
		return nil, nil, err
	}
	f, err := t.File(ctx, d.FileID)
	if err != nil {
		return nil, nil, err
	}
	if *f != spec.Source {
		return nil, nil, store.ErrState
	}
	return d, spec, nil
}
func dispatchEffect(ctx context.Context, t *store.Transaction, d *store.Delivery, spec *Definition) (*store.OutboundDispatchEffect, error) {
	var effect *store.OutboundDispatchEffect
	if spec.FTPS != nil {
		effect = ftpsEffect(d, spec)
	} else {
		effect = &store.OutboundDispatchEffect{Protocol: "sftp", Address: spec.Destination.Address, User: spec.Destination.User, Directory: spec.Directory, Filename: spec.Filename, FinalPath: path.Join(spec.Directory, d.ID+"-"+spec.Filename), HostFingerprint: spec.Destination.Host.Fingerprint, KeyFingerprint: spec.Destination.KeyFingerprint, KeyReferenceHash: secure.Digest([]byte(spec.Destination.KeyFile)), Encryption: spec.Encryption, Workflow: spec.Binding}
	}
	if spec.Encryption != nil {
		k, err := t.EncryptionKey(ctx, *spec.Encryption)
		if err != nil {
			return nil, err
		}
		effect.RecipientFingerprint = k.Fingerprint
	}
	return effect, nil
}
func dispatchReviewable(ctx context.Context, t *store.Transaction, d *store.Delivery) (bool, error) {
	if (d.State != "draft" && d.State != "queued") || d.Attempts != 0 || d.Fence != 0 || d.LeaseOwner != "" || d.LeaseUntil != nil {
		return false, nil
	}
	var cipher bool
	err := t.Tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM delivery_ciphertexts WHERE tenant_id=$1 AND partner_id=$2 AND actor_id=$3 AND delivery_id=$4)`, t.Scope.Tenant, t.Scope.Partner, t.Actor, d.ID).Scan(&cipher)
	return !cipher, err
}
func (s *Service) DispatchDelivery(ctx context.Context, scope store.Scope, id string) (*DispatchDeliveryView, error) {
	if !store.ValidID(id) {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.dispatchBegin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	d, spec, err := s.dispatchSource(ctx, t, id, false)
	if err != nil {
		return nil, err
	}
	effect, err := dispatchEffect(ctx, t, d, spec)
	if err != nil {
		return nil, err
	}
	p, err := t.OutboundDispatchPolicy(ctx)
	if err != nil {
		return nil, err
	}
	policy := store.ApprovalPolicyBinding{Mode: "author"}
	if spec.DispatchPolicy != nil {
		policy = *spec.DispatchPolicy
	}
	reviewable, err := dispatchReviewable(ctx, t, d)
	if err != nil {
		return nil, err
	}
	current := t.CheckOutboundDispatch(ctx, id)
	if current != nil && current != store.ErrDispatchApproval {
		return nil, current
	}
	v := &DispatchDeliveryView{ID: d.ID, Hash: d.DefinitionHash, State: d.State, Revision: d.Revision, Attempts: d.Attempts, Policy: policy, CurrentPolicy: p.ApprovalPolicyBinding, CurrentApproval: current == nil, Reviewable: reviewable && policy == p.ApprovalPolicyBinding && policy.Mode == "independent", Source: spec.Source, Effect: *effect}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return v, t.Tx.Commit(ctx)
}
func validDispatchSelection(x DispatchSelection) bool {
	return store.ValidID(x.DeliveryID) && store.ValidID(x.ReviewerID) && x.Revision > 0 && len(x.Hash) == 64 && dispatchHashPattern.MatchString(x.Hash)
}
func (s *Service) dispatchPreview(ctx context.Context, t *store.Transaction, x DispatchSelection) (*DispatchPreview, error) {
	if x.ReviewerID == t.Actor {
		return nil, store.ErrForbidden
	}
	d, spec, err := s.dispatchSource(ctx, t, x.DeliveryID, true)
	if err != nil {
		return nil, err
	}
	if d.Revision != x.Revision || d.DefinitionHash != x.Hash {
		return nil, store.ErrRevision
	}
	if err = t.CheckExecutionBinding(ctx, spec.Binding); err != nil {
		return nil, err
	}
	if err = s.storage(spec); err != nil {
		return nil, err
	}
	if spec.Source.Size > s.Custody.MaxFile {
		return nil, store.ErrLimit
	}
	ok, err := dispatchReviewable(ctx, t, d)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, store.ErrState
	}
	effect, err := dispatchEffect(ctx, t, d, spec)
	if err != nil {
		return nil, err
	}
	p, err := t.OutboundDispatchPolicy(ctx)
	if err != nil {
		return nil, err
	}
	if p.Mode != "independent" || spec.DispatchPolicy == nil || *spec.DispatchPolicy != p.ApprovalPolicyBinding {
		return nil, store.ErrDispatchApproval
	}
	authority, err := t.OutboundDispatchReviewer(ctx, x.ReviewerID)
	if err != nil {
		return nil, err
	}
	out := &DispatchPreview{Definition: store.OutboundDispatchDefinition{Schema: spec.Schema, Author: t.Actor, Authority: t.AuthorityRevision, Reviewer: x.ReviewerID, ReviewerAuthority: authority, Policy: p.ApprovalPolicyBinding, DeliveryID: d.ID, DeliveryRevision: d.Revision, DeliveryHash: d.DefinitionHash, Source: spec.Source, StorageID: spec.StorageID, Root: spec.Root, Effect: *effect, AttemptLimit: 8}}
	b, h, err := dispatchDigest(out.Definition)
	if err != nil {
		return nil, err
	}
	if len(b) > 24<<10 {
		return nil, store.ErrLimit
	}
	out.Hash = h
	return out, nil
}
func (s *Service) PreviewDispatchReview(ctx context.Context, scope store.Scope, x DispatchSelection) (*DispatchPreview, error) {
	if !validDispatchSelection(x) {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.dispatchBegin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	p, err := s.dispatchPreview(ctx, t, x)
	if err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return p, t.Tx.Commit(ctx)
}
func (s *Service) ProposeDispatchReview(ctx context.Context, scope store.Scope, key string, x DispatchProposal) (*DispatchResult, error) {
	if !validDispatchSelection(x.Selection) || !dispatchHashPattern.MatchString(x.Hash) || !keyPattern.MatchString(key) {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.dispatchBegin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	for _, g := range []string{"read", "deliver"} {
		if err = t.Require(g); err != nil {
			return nil, err
		}
	}
	_, meaning, err := dispatchDigest(struct {
		Kind  string
		Input DispatchProposal
	}{"outbound_dispatch_propose", x})
	if err != nil {
		return nil, err
	}
	if prior, err := dispatchReplay(ctx, t, key, meaning); err != nil || prior != nil {
		return prior, err
	}
	var pending int
	if err = t.Tx.QueryRow(ctx, `SELECT count(*) FROM outbound_dispatch_reviews WHERE actor_id=$1 AND state='pending'`, t.Actor).Scan(&pending); err != nil {
		return nil, err
	}
	if pending >= 128 {
		return nil, store.ErrLimit
	}
	p, err := s.dispatchPreview(ctx, t, x.Selection)
	if err != nil {
		return nil, err
	}
	if p.Hash != x.Hash {
		return nil, store.ErrRevision
	}
	var exists bool
	if err = t.Tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM outbound_dispatch_reviews WHERE delivery_id=$1 AND state IN ('pending','approved'))`, x.Selection.DeliveryID).Scan(&exists); err != nil {
		return nil, err
	}
	if exists {
		return nil, store.ErrState
	}
	now, err := t.DatabaseTime(ctx)
	if err != nil {
		return nil, err
	}
	r := &store.OutboundDispatchReview{OutboundDispatchSummary: store.OutboundDispatchSummary{ID: secure.NewID(), Author: t.Actor, Reviewer: p.Definition.Reviewer, DeliveryID: p.Definition.DeliveryID, Hash: p.Hash, State: "pending", Revision: 1, CreatedAt: now}, Definition: p.Definition}
	if err = t.SaveOutboundDispatchReview(ctx, r, 0); err != nil {
		return nil, err
	}
	return dispatchReceipt(ctx, t, key, meaning, r.ID, DispatchReviewResult{Kind: "outbound_dispatch_review", Review: r.OutboundDispatchSummary})
}
func (s *Service) DispatchReview(ctx context.Context, scope store.Scope, id string) (*store.OutboundDispatchReview, error) {
	if !store.ValidID(id) {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.dispatchBegin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	r, err := t.OutboundDispatchReview(ctx, id, false)
	if err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return r, t.Tx.Commit(ctx)
}
func (s *Service) DispatchReviews(ctx context.Context, scope store.Scope, after string, limit int) (*store.OutboundDispatchPage, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.dispatchBegin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	p, err := t.OutboundDispatchReviews(ctx, after, limit)
	if err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return p, t.Tx.Commit(ctx)
}
func (s *Service) DecideDispatchReview(ctx context.Context, scope store.Scope, id, action, key string, x DispatchDecision) (*DispatchResult, error) {
	if !store.ValidID(id) || !keyPattern.MatchString(key) || x.Revision < 1 || !dispatchHashPattern.MatchString(x.Hash) || (action != "approve" && action != "reject" && action != "withdraw") {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.dispatchBegin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if action != "withdraw" {
		for _, g := range []string{"inspect", "workflow_approve"} {
			if err = t.Require(g); err != nil {
				return nil, err
			}
		}
	}
	_, meaning, err := dispatchDigest(struct {
		Kind, ID, Action string
		Input            DispatchDecision
	}{"outbound_dispatch_decide", id, action, x})
	if err != nil {
		return nil, err
	}
	if prior, err := dispatchReplay(ctx, t, key, meaning); err != nil || prior != nil {
		return prior, err
	}
	if _, err = t.Tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, scope.Tenant+":"+scope.Partner+":outbound-dispatch-policy"); err != nil {
		return nil, err
	}
	r, err := t.OutboundDispatchReview(ctx, id, true)
	if err != nil {
		return nil, err
	}
	if r.Hash != x.Hash || r.Revision != x.Revision {
		return nil, store.ErrRevision
	}
	if action == "withdraw" {
		if r.State != "pending" && r.State != "approved" {
			return nil, store.ErrState
		}
		if t.Actor == r.Author {
			for _, g := range []string{"read", "deliver"} {
				if err = t.Require(g); err != nil {
					return nil, err
				}
			}
		} else if t.Actor == r.Reviewer {
			for _, g := range []string{"inspect", "workflow_approve"} {
				if err = t.Require(g); err != nil {
					return nil, err
				}
			}
		} else {
			return nil, store.ErrForbidden
		}
		r.State = "withdrawn"
	} else {
		if t.Actor != r.Reviewer || t.Actor == r.Author {
			return nil, store.ErrForbidden
		}
		if r.State != "pending" {
			return nil, store.ErrState
		}
		p, err := t.OutboundDispatchPolicy(ctx)
		if err != nil {
			return nil, err
		}
		authority, err := t.OutboundDispatchReviewer(ctx, t.Actor)
		if err != nil {
			return nil, err
		}
		if p.ApprovalPolicyBinding != r.Definition.Policy || authority != r.Definition.ReviewerAuthority {
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
	if err = t.SaveOutboundDispatchReview(ctx, r, previous); err != nil {
		return nil, err
	}
	return dispatchReceipt(ctx, t, key, meaning, r.ID, DispatchReviewResult{Kind: "outbound_dispatch_review", Review: r.OutboundDispatchSummary})
}
