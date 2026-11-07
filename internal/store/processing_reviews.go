package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/jackc/pgx/v5"
)

type ProcessingReviewParticipant struct {
	Actor      string `json:"actor_id"`
	Authority  int64  `json:"authority_revision"`
	RootDigest string `json:"namespace_root_digest"`
}
type ProcessingReviewWorkflow struct {
	ID      string `json:"id"`
	Version int    `json:"version"`
	Hash    string `json:"hash"`
}
type ProcessingReviewDefinition struct {
	Profile          string                      `json:"profile"`
	Author           ProcessingReviewParticipant `json:"author"`
	Reviewer         ProcessingReviewParticipant `json:"reviewer"`
	Workflow         ProcessingReviewWorkflow    `json:"workflow"`
	WorkflowRevision int64                       `json:"workflow_revision"`
	Definition       json.RawMessage             `json:"definition"`
	ExpiresAt        time.Time                   `json:"expires_at"`
}
type ProcessingReview struct {
	ID              string                     `json:"id"`
	Definition      ProcessingReviewDefinition `json:"definition"`
	Hash            string                     `json:"definition_hash"`
	State           string                     `json:"state"`
	Revision        int64                      `json:"revision"`
	AdoptedRevision int64                      `json:"adopted_revision"`
	CreatedAt       time.Time                  `json:"created_at"`
	EventID         string                     `json:"changed_event_id,omitempty"`
}
type ProcessingReviewSummary struct {
	ID              string    `json:"id"`
	Author          string    `json:"author_id"`
	Reviewer        string    `json:"reviewer_id"`
	WorkflowID      string    `json:"workflow_id"`
	Version         int       `json:"workflow_version"`
	Hash            string    `json:"definition_hash"`
	State           string    `json:"state"`
	Revision        int64     `json:"revision"`
	AdoptedRevision int64     `json:"adopted_revision"`
	ExpiresAt       time.Time `json:"expires_at"`
}
type ProcessingReviewPage struct {
	Reviews []ProcessingReviewSummary `json:"reviews"`
	Next    string                    `json:"next,omitempty"`
}

func (t *Transaction) ProcessingReviewer(ctx context.Context, id string) (ProcessingReviewParticipant, error) {
	var p ProcessingReviewParticipant
	var root string
	err := t.Tx.QueryRow(ctx, `SELECT actor_id::text,authority_revision,namespace_root FROM credentials WHERE tenant_id=$1 AND partner_id=$2 AND actor_id=$3 AND permissions @> ARRAY['inspect','workflow_approve']::text[] AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>clock_timestamp())`, t.Scope.Tenant, t.Scope.Partner, id).Scan(&p.Actor, &p.Authority, &root)
	if errors.Is(err, pgx.ErrNoRows) {
		return p, ErrNotFound
	}
	p.RootDigest = secure.Digest([]byte(root))
	return p, err
}
func (t *Transaction) ProcessingReview(ctx context.Context, id string, lock bool) (*ProcessingReview, error) {
	if !ValidID(id) {
		return nil, ErrNotFound
	}
	query := `SELECT review_id::text,definition,definition_hash,state,revision,adopted_revision,created_at,changed_event_id::text FROM processing_workflow_reviews WHERE tenant_id=$1 AND partner_id=$2 AND review_id=$3 AND (actor_id=$4 OR reviewer_id=$4)`
	if lock {
		query += ` FOR UPDATE`
	}
	var r ProcessingReview
	var raw []byte
	err := t.Tx.QueryRow(ctx, query, t.Scope.Tenant, t.Scope.Partner, id, t.Actor).Scan(&r.ID, &raw, &r.Hash, &r.State, &r.Revision, &r.AdoptedRevision, &r.CreatedAt, &r.EventID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var trailing any
	if decoder.Decode(&r.Definition) != nil || decoder.Decode(&trailing) != io.EOF {
		return nil, ErrIsolation
	}
	// JSONB reorders the nested raw workflow. The workflow service must normalize
	// its typed definition before checking the complete review's canonical hash.
	r.CreatedAt = r.CreatedAt.UTC()
	return &r, nil
}
func (t *Transaction) SaveProcessingReview(ctx context.Context, r *ProcessingReview, previous int64) error {
	e, err := t.Append(ctx, "ProcessingWorkflowReviewChanged", r.ID, r)
	if err != nil {
		return err
	}
	r.EventID = e
	if previous == 0 {
		b, err := json.Marshal(r.Definition)
		if err != nil {
			return err
		}
		_, err = t.Tx.Exec(ctx, `INSERT INTO processing_workflow_reviews(tenant_id,partner_id,actor_id,reviewer_id,review_id,workflow_id,workflow_version,definition,definition_hash,state,revision,adopted_revision,created_at,expires_at,changed_event_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`, t.Scope.Tenant, t.Scope.Partner, r.Definition.Author.Actor, r.Definition.Reviewer.Actor, r.ID, r.Definition.Workflow.ID, r.Definition.Workflow.Version, b, r.Hash, r.State, r.Revision, r.AdoptedRevision, r.CreatedAt, r.Definition.ExpiresAt, e)
		return err
	}
	tag, err := t.Tx.Exec(ctx, `UPDATE processing_workflow_reviews SET state=$1,revision=$2,adopted_revision=$3,changed_event_id=$4 WHERE tenant_id=$5 AND partner_id=$6 AND review_id=$7 AND revision=$8`, r.State, r.Revision, r.AdoptedRevision, e, t.Scope.Tenant, t.Scope.Partner, r.ID, previous)
	if err == nil && tag.RowsAffected() != 1 {
		return ErrRevision
	}
	return err
}
func (t *Transaction) ProcessingReviews(ctx context.Context, after string, limit int) (*ProcessingReviewPage, error) {
	if (after != "" && !ValidID(after)) || limit < 1 || limit > 100 {
		return nil, ErrLimit
	}
	rows, err := t.Tx.Query(ctx, `SELECT review_id::text,actor_id::text,reviewer_id::text,workflow_id::text,workflow_version,definition_hash,state,revision,adopted_revision,expires_at FROM processing_workflow_reviews WHERE tenant_id=$1 AND partner_id=$2 AND (actor_id=$3 OR reviewer_id=$3) AND ($4='' OR review_id>nullif($4,'')::uuid) ORDER BY review_id LIMIT $5`, t.Scope.Tenant, t.Scope.Partner, t.Actor, after, limit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	page := &ProcessingReviewPage{Reviews: []ProcessingReviewSummary{}}
	for rows.Next() {
		var r ProcessingReviewSummary
		if err = rows.Scan(&r.ID, &r.Author, &r.Reviewer, &r.WorkflowID, &r.Version, &r.Hash, &r.State, &r.Revision, &r.AdoptedRevision, &r.ExpiresAt); err != nil {
			return nil, err
		}
		page.Reviews = append(page.Reviews, r)
	}
	if len(page.Reviews) > limit {
		page.Next = page.Reviews[limit-1].ID
		page.Reviews = page.Reviews[:limit]
	}
	return page, rows.Err()
}
func (t *Transaction) CheckProcessingReview(ctx context.Context, id string, version int, hash string) error {
	var current bool
	err := t.Tx.QueryRow(ctx, `SELECT freightctl_processing_review_current($1,$2,$3,$4,$5,$6)`, t.Scope.Tenant, t.Scope.Partner, t.Actor, id, version, hash).Scan(&current)
	if err == nil && !current {
		return ErrRevision
	}
	return err
}
