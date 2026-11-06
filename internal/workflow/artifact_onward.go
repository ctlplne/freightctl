package workflow

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
)

const OnwardProfile = "ordered-workflow-onward-v1"

type OnwardRequest struct {
	Schema   int                    `json:"schema_version"`
	Profile  string                 `json:"profile"`
	Workflow Reference              `json:"workflow"`
	Artifact store.ExchangeArtifact `json:"artifact"`
}
type OnwardStart struct {
	Request    OnwardRequest `json:"request"`
	ReviewHash string        `json:"review_hash"`
}

// Persist the exact review/approval revision with the ordinary run receipt.
// The embedded run retains the existing journal/resource shape.
type OnwardRunReceipt struct {
	store.WorkflowRun
	Profile          string `json:"onward_profile"`
	ReviewHash       string `json:"onward_review_hash"`
	WorkflowRevision int64  `json:"onward_workflow_revision"`
}
type OnwardLookup struct {
	Start      OnwardStart `json:"start"`
	ReceiptKey string      `json:"receipt_key"`
}
type OnwardEffect struct {
	Ordinal    int       `json:"ordinal"`
	Protocol   string    `json:"protocol"`
	Connection Reference `json:"connection"`
}
type OnwardReview struct {
	Request             OnwardRequest  `json:"request"`
	ReviewHash          string         `json:"review_hash"`
	Effects             []OnwardEffect `json:"effects"`
	State               string         `json:"state"`
	ExternalContact     bool           `json:"external_contact"`
	ReceiverPersistence string         `json:"receiver_persistence"`
	BusinessProcessing  string         `json:"business_processing"`
	workflowRevision    int64
}
type onwardBinding struct {
	Request          OnwardRequest `json:"request"`
	Tenant           string        `json:"tenant_id"`
	Partner          string        `json:"partner_id"`
	Actor            string        `json:"actor_id"`
	Authority        int64         `json:"authority_revision"`
	RootDigest       string        `json:"root_policy_digest"`
	WorkflowRevision int64         `json:"workflow_revision"`
	StorageDigest    string        `json:"storage_identity_digest"`
}

func validateOnwardRequest(r OnwardRequest, maxFile int64) error {
	policy := store.ValidArtifactPolicy(r.Artifact.Policy)
	if r.Schema != 1 || r.Profile != OnwardProfile || !store.ValidID(r.Workflow.ID) || r.Workflow.Version < 1 || r.Workflow.Version > 2147483647 || !hashPattern.MatchString(r.Workflow.Hash) || !store.ValidID(r.Artifact.ID) || r.Artifact.Size < 0 || maxFile < 0 || r.Artifact.Size > maxFile || !hashPattern.MatchString(r.Artifact.SHA256) || !policy {
		return ErrInput
	}
	return nil
}
func onwardBindingHash(b onwardBinding) (string, error) {
	if validateOnwardRequest(b.Request, 1<<63-1) != nil || !store.ValidID(b.Tenant) || !store.ValidID(b.Partner) || !store.ValidID(b.Actor) || b.Authority < 1 || b.WorkflowRevision < 1 || !hashPattern.MatchString(b.RootDigest) || !hashPattern.MatchString(b.StorageDigest) {
		return "", ErrInput
	}
	_, hash, err := digest(b)
	return hash, err
}

// Reuse ordinary approved configuration/source/intake/connection guards. This
// first profile has only ordered, preapproved sending steps; it cannot adopt a
// collection input, invent routing or convert a receive view into source access.
func (s *Service) onwardSnapshot(ctx context.Context, t *store.Transaction, r OnwardRequest) (*OnwardReview, *Definition, *store.File, error) {
	c, d, err := approved(ctx, t, r.Workflow)
	if err != nil {
		return nil, nil, nil, err
	}
	// Serialize the approval revision with its ordinary decision row. Acquiring
	// this after credential authentication preserves the management lock order.
	locked, err := t.Configuration(ctx, false, r.Workflow.ID, r.Workflow.Version, true)
	if err != nil {
		return nil, nil, nil, err
	}
	if locked.Hash != c.Hash || locked.State != "approved" || locked.ApprovalAuthority != t.AuthorityRevision {
		return nil, nil, nil, store.ErrState
	}
	c = locked
	if d.Schema != 1 || d.Source != nil || d.Program != nil || len(d.Steps) == 0 {
		return nil, nil, nil, ErrInput
	}
	source, err := t.AuthorizeExchangeSource(ctx, r.Artifact.ID)
	if err != nil {
		return nil, nil, nil, err
	}
	if r.Artifact != (store.ExchangeArtifact{ID: source.ID, Size: source.Size, SHA256: source.SHA256, Policy: source.Policy}) {
		return nil, nil, nil, store.ErrRevision
	}
	if s.Custody.Disk == nil {
		return nil, nil, nil, custody.ErrStorageIdentity
	}
	if err = s.checkStorage(s.Custody.Disk.Identity()); err != nil {
		return nil, nil, nil, err
	}
	if err = t.DeliveryCapacity(ctx, len(d.Steps)); err != nil {
		return nil, nil, nil, err
	}
	hash, err := onwardBindingHash(onwardBinding{Request: r, Tenant: t.Scope.Tenant, Partner: t.Scope.Partner, Actor: t.Actor, Authority: t.AuthorityRevision, RootDigest: secure.Digest([]byte(t.Root)), WorkflowRevision: c.Revision, StorageDigest: secure.Digest([]byte(s.Custody.Disk.Identity()))})
	if err != nil {
		return nil, nil, nil, err
	}
	effects := make([]OnwardEffect, 0, len(d.Steps))
	for i, step := range d.Steps {
		effects = append(effects, OnwardEffect{Ordinal: i + 1, Protocol: strings.TrimSuffix(step.Kind, ".deliver"), Connection: step.Connection})
	}
	return &OnwardReview{Request: r, ReviewHash: hash, Effects: effects, State: "review-only", ReceiverPersistence: "unknown", BusinessProcessing: "unknown", workflowRevision: c.Revision}, d, source, nil
}
func (s *Service) PrepareOnward(ctx context.Context, scope store.Scope, r OnwardRequest) (*OnwardReview, error) {
	if err := validateOnwardRequest(r, s.Custody.MaxFile); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.begin(ctx, scope, "workflow_execute", "read", "deliver")
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	review, _, _, err := s.onwardSnapshot(ctx, t, r)
	if err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return review, t.Tx.Rollback(ctx)
}

// StartOnward commits the ordinary run/intents and private retry receipt in one
// transaction. No peer contact occurs here. The reviewed binding is checked in
// that transaction, not in an earlier transport/model-only check.
func (s *Service) StartOnward(ctx context.Context, scope store.Scope, key string, start OnwardStart) (*Result, error) {
	if s.Custody.MaxFile < 0 || validateOnwardRequest(start.Request, 1<<63-1) != nil || !hashPattern.MatchString(start.ReviewHash) || !keyPattern.MatchString(key) {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.begin(ctx, scope, "workflow_execute", "read", "deliver")
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	_, meaning, err := digest(struct {
		Kind  string      `json:"kind"`
		Start OnwardStart `json:"start"`
	}{"reviewed-onward-run-v1", start})
	if err != nil {
		return nil, err
	}
	// A recorded receipt remains historical after configuration revocation. It
	// cannot stage work again or awaken a sender. Keep exact original authority
	// and current source receipt permission before disclosing it.
	prior, err := t.WorkflowReplay(ctx, key, meaning)
	if err != nil {
		return nil, err
	}
	if prior != nil {
		if _, err = authorizeOnwardReceipt(ctx, t, start, prior); err != nil {
			return nil, err
		}
		if err = t.Reauthorize(ctx); err != nil {
			return nil, err
		}
		return &Result{Resource: prior, Replayed: true}, t.Tx.Commit(ctx)
	}
	if err = validateOnwardRequest(start.Request, s.Custody.MaxFile); err != nil {
		return nil, err
	}

	review, definition, source, err := s.onwardSnapshot(ctx, t, start.Request)
	if err != nil {
		return nil, err
	}
	if review.ReviewHash != start.ReviewHash {
		return nil, store.ErrRevision
	}
	run, err := s.stageRun(ctx, t, RunRequest{Workflow: start.Request.Workflow, FileID: start.Request.Artifact.ID}, definition, source, s.Custody.Disk.Identity())
	if err != nil {
		return nil, err
	}
	receipt := OnwardRunReceipt{WorkflowRun: *run, Profile: OnwardProfile, ReviewHash: review.ReviewHash, WorkflowRevision: review.workflowRevision}
	return result(t, ctx, key, meaning, run.ID, receipt)
}

func authorizeOnwardReceipt(ctx context.Context, t *store.Transaction, start OnwardStart, raw json.RawMessage) (*store.WorkflowRun, error) {
	var receipt OnwardRunReceipt
	if json.Unmarshal(raw, &receipt) != nil || receipt.Profile != OnwardProfile || receipt.ReviewHash != start.ReviewHash || receipt.WorkflowRevision < 1 || receipt.FileID != start.Request.Artifact.ID || receipt.WorkflowID != start.Request.Workflow.ID || receipt.WorkflowVersion != start.Request.Workflow.Version || receipt.WorkflowHash != start.Request.Workflow.Hash || start.Request.Artifact != (store.ExchangeArtifact{ID: receipt.Source.ID, Size: receipt.Source.Size, SHA256: receipt.Source.SHA256, Policy: receipt.Source.Policy}) {
		return nil, store.ErrIsolation
	}
	expected, err := onwardBindingHash(onwardBinding{Request: start.Request, Tenant: t.Scope.Tenant, Partner: t.Scope.Partner, Actor: t.Actor, Authority: receipt.Authority, RootDigest: secure.Digest([]byte(receipt.Root)), WorkflowRevision: receipt.WorkflowRevision, StorageDigest: secure.Digest([]byte(receipt.StorageID))})
	if err != nil || expected != receipt.ReviewHash {
		return nil, store.ErrIsolation
	}
	run, err := t.WorkflowRun(ctx, receipt.ID, false)
	if err != nil {
		return nil, err
	}
	if run.Authority != t.AuthorityRevision || run.Root != t.Root {
		return nil, store.ErrUnauthorized
	}
	if err = t.FileReceiptAccessible(ctx, run.FileID); err != nil {
		return nil, err
	}
	return run, nil
}

// A lookup never creates a run. It proves the supplied key belongs to this
// exact reviewed-onward command, so a generic/collection/routing run cannot be
// smuggled into the narrower agent execution profile.
func (s *Service) OnwardReceipt(ctx context.Context, scope store.Scope, lookup OnwardLookup) (*Result, error) {
	start := lookup.Start
	if s.Custody.MaxFile < 0 || validateOnwardRequest(start.Request, 1<<63-1) != nil || !hashPattern.MatchString(start.ReviewHash) || !keyPattern.MatchString(lookup.ReceiptKey) {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.begin(ctx, scope, "workflow_execute", "read", "deliver")
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	_, meaning, err := digest(struct {
		Kind  string      `json:"kind"`
		Start OnwardStart `json:"start"`
	}{"reviewed-onward-run-v1", start})
	if err != nil {
		return nil, err
	}
	prior, err := t.WorkflowReplay(ctx, lookup.ReceiptKey, meaning)
	if err != nil {
		return nil, err
	}
	if prior == nil {
		return nil, store.ErrNotFound
	}
	if _, err = authorizeOnwardReceipt(ctx, t, start, prior); err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return &Result{Resource: prior, Replayed: true}, t.Tx.Commit(ctx)
}
