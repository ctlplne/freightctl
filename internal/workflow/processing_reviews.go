package workflow

import (
	"context"
	"encoding/json"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

type ProcessingReviewRequest struct {
	Workflow  Reference `json:"workflow"`
	Revision  int64     `json:"expected_revision"`
	Reviewer  string    `json:"reviewer_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

func processingReviewSummary(r *store.ProcessingReview) store.ProcessingReviewSummary {
	d := r.Definition
	return store.ProcessingReviewSummary{ID: r.ID, Author: d.Author.Actor, Reviewer: d.Reviewer.Actor, WorkflowID: d.Workflow.ID, Version: d.Workflow.Version, Hash: r.Hash, State: r.State, Revision: r.Revision, AdoptedRevision: r.AdoptedRevision, ExpiresAt: d.ExpiresAt}
}

type ProcessingReviewedWorkflow struct {
	ID                string `json:"id"`
	Version           int    `json:"version"`
	Hash              string `json:"definition_hash"`
	State             string `json:"state"`
	Revision          int64  `json:"revision"`
	ApprovalAuthority int64  `json:"approval_authority"`
}

func processingReviewDefinition(c *store.Configuration, a, r store.ProcessingReviewParticipant, until, now time.Time) (store.ProcessingReviewDefinition, error) {
	var d Definition
	bad := store.ProcessingReviewDefinition{}
	if c == nil || !store.ValidID(c.ID) || c.Version < 1 || c.Revision < 1 || c.State != "draft" || c.ApprovalAuthority != 0 || !store.ValidID(a.Actor) || !store.ValidID(r.Actor) || a.Actor == r.Actor || a.Authority < 1 || r.Authority < 1 || !hashPattern.MatchString(a.RootDigest) || !hashPattern.MatchString(r.RootDigest) || !until.After(now) || until.After(now.Add(30*24*time.Hour)) || until.Nanosecond()%1000 != 0 || Decode(c.Definition, &d) != nil {
		return bad, ErrInput
	}
	d, err := Normalize(d)
	if err != nil || d.Schema != 3 || d.Processing == nil {
		return bad, ErrInput
	}
	raw, hash, err := digest(d)
	if err != nil || hash != c.Hash {
		return bad, store.ErrRevision
	}
	return store.ProcessingReviewDefinition{Profile: "independent-processing-workflow-review-v1", Author: a, Reviewer: r, Workflow: store.ProcessingReviewWorkflow{ID: c.ID, Version: c.Version, Hash: hash}, WorkflowRevision: c.Revision, Definition: raw, ExpiresAt: until.UTC()}, nil
}
func (s *Service) beginProcessingReview(ctx context.Context, scope store.Scope) (*store.Transaction, error) {
	t, err := s.Custody.DB.BeginApproval(ctx, scope)
	if err != nil {
		return nil, err
	}
	if !t.Has("workflow_manage") && !t.Has("workflow_execute") && !t.Has("workflow_approve") {
		t.Tx.Rollback(ctx)
		return nil, store.ErrForbidden
	}
	return t, nil
}
func reviewParticipant(t *store.Transaction) store.ProcessingReviewParticipant {
	return store.ProcessingReviewParticipant{Actor: t.Actor, Authority: t.AuthorityRevision, RootDigest: secure.Digest([]byte(t.Root))}
}
func normalizeProcessingReview(r *store.ProcessingReview) error {
	if r == nil || !store.ValidID(r.ID) || r.Revision < 1 || r.AdoptedRevision < 0 || r.AdoptedRevision > r.Revision || r.CreatedAt.IsZero() {
		return store.ErrIsolation
	}
	switch r.State {
	case "pending", "approved", "rejected":
		if r.AdoptedRevision != 0 {
			return store.ErrIsolation
		}
	case "adopted":
		if r.AdoptedRevision < 1 || r.AdoptedRevision != r.Revision {
			return store.ErrIsolation
		}
	case "withdrawn":
	default:
		return store.ErrIsolation
	}
	d := r.Definition
	c := &store.Configuration{ID: d.Workflow.ID, Version: d.Workflow.Version, Hash: d.Workflow.Hash, Revision: d.WorkflowRevision, State: "draft", Definition: d.Definition}
	normalized, err := processingReviewDefinition(c, d.Author, d.Reviewer, d.ExpiresAt, r.CreatedAt)
	if err != nil || d.Profile != normalized.Profile {
		return store.ErrIsolation
	}
	_, hash, err := digest(normalized)
	if err != nil || hash != r.Hash {
		return store.ErrIsolation
	}
	r.Definition = normalized
	return nil
}
func loadProcessingReview(ctx context.Context, t *store.Transaction, id string, lock bool) (*store.ProcessingReview, error) {
	r, err := t.ProcessingReview(ctx, id, lock)
	if err != nil {
		return nil, err
	}
	if err = normalizeProcessingReview(r); err != nil {
		return nil, err
	}
	return r, nil
}
func checkReviewParticipant(t *store.Transaction, r *store.ProcessingReview) error {
	actual := reviewParticipant(t)
	if t.Actor == r.Definition.Author.Actor && actual == r.Definition.Author && (t.Has("workflow_manage") || t.Has("workflow_execute") || t.Has("workflow_approve")) {
		return nil
	}
	if t.Actor == r.Definition.Reviewer.Actor && actual == r.Definition.Reviewer && t.Has("inspect") && t.Has("workflow_approve") {
		return nil
	}
	return store.ErrForbidden
}
func (s *Service) RequestProcessingReview(ctx context.Context, scope store.Scope, key string, request ProcessingReviewRequest) (*Result, error) {
	if !keyPattern.MatchString(key) || !store.ValidID(request.Workflow.ID) || request.Workflow.Version < 1 || !hashPattern.MatchString(request.Workflow.Hash) || !store.ValidID(request.Reviewer) || request.Revision < 1 {
		return nil, ErrInput
	}
	t, err := s.beginProcessingReview(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if err = t.Require("workflow_manage"); err != nil {
		return nil, err
	}
	request.ExpiresAt = request.ExpiresAt.UTC()
	_, meaning, _ := digest(struct {
		Kind    string
		Request ProcessingReviewRequest
	}{"request_processing_workflow_review", request})
	prior, err := t.WorkflowReplay(ctx, key, meaning)
	if err != nil {
		return nil, err
	}
	if prior != nil {
		var original store.ProcessingReviewSummary
		if json.Unmarshal(prior, &original) != nil {
			return nil, store.ErrIsolation
		}
		current, err := loadProcessingReview(ctx, t, original.ID, false)
		if err != nil {
			return nil, err
		}
		if err = checkReviewParticipant(t, current); err != nil {
			return nil, err
		}
		if err = t.Reauthorize(ctx); err != nil {
			return nil, err
		}
		return &Result{Resource: prior, Replayed: true}, t.Tx.Commit(ctx)
	}
	c, err := t.Configuration(ctx, false, request.Workflow.ID, request.Workflow.Version, true)
	if err != nil {
		return nil, err
	}
	if c.Hash != request.Workflow.Hash || c.Revision != request.Revision {
		return nil, store.ErrRevision
	}
	reviewer, err := t.ProcessingReviewer(ctx, request.Reviewer)
	if err != nil {
		return nil, err
	}
	now, err := t.DatabaseTime(ctx)
	if err != nil {
		return nil, err
	}
	definition, err := processingReviewDefinition(c, reviewParticipant(t), reviewer, request.ExpiresAt, now)
	if err != nil {
		return nil, err
	}
	var d Definition
	if Decode(definition.Definition, &d) != nil {
		return nil, store.ErrState
	}
	if _, err = connections(ctx, t, d); err != nil {
		return nil, err
	}
	_, hash, _ := digest(definition)
	review := &store.ProcessingReview{ID: secure.NewID(), Definition: definition, Hash: hash, State: "pending", Revision: 1, CreatedAt: now}
	if err = t.SaveProcessingReview(ctx, review, 0); err != nil {
		return nil, err
	}
	return result(t, ctx, key, meaning, review.ID, processingReviewSummary(review))
}
func (s *Service) ProcessingReview(ctx context.Context, scope store.Scope, id string) (*store.ProcessingReview, error) {
	t, err := s.beginProcessingReview(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	review, err := loadProcessingReview(ctx, t, id, false)
	if err != nil {
		return nil, err
	}
	if err = checkReviewParticipant(t, review); err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return review, t.Tx.Commit(ctx)
}
func (s *Service) ProcessingReviews(ctx context.Context, scope store.Scope, after string, limit int) (*store.ProcessingReviewPage, error) {
	if (after != "" && !store.ValidID(after)) || limit < 1 || limit > 100 {
		return nil, ErrInput
	}
	t, err := s.beginProcessingReview(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	page, err := t.ProcessingReviews(ctx, after, limit)
	if err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return page, t.Tx.Commit(ctx)
}
func (s *Service) DecideProcessingReview(ctx context.Context, scope store.Scope, id, key, action string, decision Decision) (*Result, error) {
	if !store.ValidID(id) || !keyPattern.MatchString(key) || !hashPattern.MatchString(decision.Hash) || decision.Revision < 1 || (action != "approve" && action != "reject" && action != "withdraw" && action != "adopt") {
		return nil, ErrInput
	}
	t, err := s.beginProcessingReview(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	_, meaning, _ := digest(struct {
		Kind, ID, Action string
		Decision         Decision
	}{"decide_processing_workflow_review", id, action, decision})
	// A replay is still bound to this participant's current authority and root.
	current, err := loadProcessingReview(ctx, t, id, false)
	if err != nil {
		return nil, err
	}
	if err = checkReviewParticipant(t, current); err != nil {
		return nil, err
	}
	if prior, err := replay(t, ctx, key, meaning); err != nil || prior != nil {
		return prior, err
	}
	review, err := loadProcessingReview(ctx, t, id, true)
	if err != nil {
		return nil, err
	}
	if review.Hash != decision.Hash || review.Revision != decision.Revision {
		return nil, store.ErrRevision
	}
	old := review.Revision
	if action == "adopt" {
		if t.Actor != review.Definition.Author.Actor || !t.Has("workflow_manage") || review.State != "approved" || review.AdoptedRevision != 0 {
			return nil, store.ErrForbidden
		}
		ref := review.Definition.Workflow
		c, err := t.Configuration(ctx, false, ref.ID, ref.Version, true)
		if err != nil {
			return nil, err
		}
		if c.State != "draft" || c.Revision != review.Definition.WorkflowRevision || c.Hash != ref.Hash {
			return nil, store.ErrRevision
		}
		var d Definition
		if Decode(c.Definition, &d) != nil || d.Schema != 3 {
			return nil, store.ErrState
		}
		if _, err = connections(ctx, t, d); err != nil {
			return nil, err
		}
		review.State = "adopted"
		review.Revision++
		review.AdoptedRevision = review.Revision
		if err = t.SaveProcessingReview(ctx, review, old); err != nil {
			return nil, err
		}
		if err = t.CheckProcessingReview(ctx, c.ID, c.Version, c.Hash); err != nil {
			return nil, err
		}
		previous := c.Revision
		c.State = "approved"
		c.ApprovalAuthority = t.AuthorityRevision
		c.Revision++
		if err = t.SaveConfiguration(ctx, false, c, previous); err != nil {
			return nil, err
		}
		return result(t, ctx, key, meaning, id, struct {
			Review   store.ProcessingReviewSummary `json:"review"`
			Workflow ProcessingReviewedWorkflow    `json:"workflow"`
		}{processingReviewSummary(review), ProcessingReviewedWorkflow{ID: c.ID, Version: c.Version, Hash: c.Hash, State: c.State, Revision: c.Revision, ApprovalAuthority: c.ApprovalAuthority}})
	}
	if action == "withdraw" {
		if review.State != "pending" && review.State != "approved" && review.State != "adopted" {
			return nil, store.ErrState
		}
		if t.Actor == review.Definition.Author.Actor && !t.Has("workflow_manage") {
			return nil, store.ErrForbidden
		}
		review.State = "withdrawn"
	} else {
		if t.Actor != review.Definition.Reviewer.Actor || review.State != "pending" || !t.Has("inspect") || !t.Has("workflow_approve") {
			return nil, store.ErrForbidden
		}
		review.State = map[string]string{"approve": "approved", "reject": "rejected"}[action]
	}
	review.Revision++
	if err = t.SaveProcessingReview(ctx, review, old); err != nil {
		return nil, err
	}
	return result(t, ctx, key, meaning, id, processingReviewSummary(review))
}
