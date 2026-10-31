package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/jackc/pgx/v5"
)

type OnboardingApprovalBinding struct {
	Revision int64  `json:"revision"`
	Mode     string `json:"mode"`
}
type OnboardingApprovalPolicy struct {
	OnboardingApprovalBinding
	Author  string `json:"author_id,omitempty"`
	EventID string `json:"event_id,omitempty"`
}
type OnboardingApprovalEffect struct {
	RequirementID string               `json:"requirement_id"`
	File          File                 `json:"file"`
	Effect        OnboardingTestEffect `json:"effect"`
}
type OnboardingApprovalDefinition struct {
	Schema            int                         `json:"schema_version"`
	Author            string                      `json:"author_id"`
	Reviewer          string                      `json:"reviewer_id"`
	ReviewerAuthority int64                       `json:"reviewer_authority_revision"`
	Policy            OnboardingApprovalBinding   `json:"policy"`
	ReleaseID         string                      `json:"release_id"`
	ReleaseRevision   int64                       `json:"release_revision"`
	ReleaseHash       string                      `json:"release_hash"`
	Release           OnboardingReleaseDefinition `json:"release"`
	Effects           []OnboardingApprovalEffect  `json:"effects"`
}
type OnboardingApprovalSummary struct {
	ID        string    `json:"id"`
	Author    string    `json:"author_id"`
	Reviewer  string    `json:"reviewer_id"`
	Hash      string    `json:"definition_hash"`
	State     string    `json:"state"`
	Revision  int64     `json:"revision"`
	CreatedAt time.Time `json:"created_at"`
	EventID   string    `json:"changed_event_id"`
}
type OnboardingApprovalReview struct {
	OnboardingApprovalSummary
	Definition OnboardingApprovalDefinition `json:"definition"`
}
type OnboardingApprovalPage struct {
	Reviews []OnboardingApprovalSummary `json:"reviews"`
	Next    string                      `json:"next,omitempty"`
}

// Serialize approval decisions with account authority changes before taking
// policy/review locks. No manager role or file capability is granted here.
func (s *Store) BeginOnboardingApproval(ctx context.Context, scope Scope) (*Transaction, error) {
	return s.beginAuthenticated(ctx, scope, pgx.TxOptions{}, true)
}
func (t *Transaction) OnboardingApprovalPolicy(ctx context.Context) (*OnboardingApprovalPolicy, error) {
	if _, err := t.Tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0))`, t.Scope.Tenant+":"+t.Scope.Partner+":onboarding-approval-policy"); err != nil {
		return nil, err
	}
	p := &OnboardingApprovalPolicy{OnboardingApprovalBinding: OnboardingApprovalBinding{Mode: "author"}}
	err := t.Tx.QueryRow(ctx, `SELECT revision,mode,actor_id::text,event_id::text FROM onboarding_approval_policies WHERE tenant_id=$1 AND partner_id=$2 ORDER BY revision DESC LIMIT 1`, t.Scope.Tenant, t.Scope.Partner).Scan(&p.Revision, &p.Mode, &p.Author, &p.EventID)
	if errors.Is(err, pgx.ErrNoRows) {
		return p, nil
	}
	return p, err
}
func (t *Transaction) SaveOnboardingApprovalPolicy(ctx context.Context, p *OnboardingApprovalPolicy) error {
	e, err := t.Append(ctx, "OnboardingApprovalPolicyChanged", t.Scope.Partner, p)
	if err != nil {
		return err
	}
	p.EventID = e
	_, err = t.Tx.Exec(ctx, `INSERT INTO onboarding_approval_policies VALUES($1,$2,$3,$4,$5,$6)`, t.Scope.Tenant, t.Scope.Partner, p.Revision, p.Mode, t.Actor, e)
	return err
}
func (t *Transaction) OnboardingApprovalReviewer(ctx context.Context, id string) (int64, error) {
	var revision int64
	err := t.Tx.QueryRow(ctx, `SELECT authority_revision FROM credentials WHERE tenant_id=$1 AND partner_id=$2 AND actor_id=$3 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>clock_timestamp()) AND namespace_root='/' AND permissions @> ARRAY['workflow_approve','inspect']::text[]`, t.Scope.Tenant, t.Scope.Partner, id).Scan(&revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrNotFound
	}
	return revision, err
}
func (t *Transaction) OnboardingApprovalCurrent(ctx context.Context, id string) (bool, error) {
	var current bool
	err := t.Tx.QueryRow(ctx, `SELECT freightctl_onboarding_approval_current($1,$2,$3,$4)`, t.Scope.Tenant, t.Scope.Partner, t.Actor, id).Scan(&current)
	return current, err
}
func (t *Transaction) OnboardingApprovalReview(ctx context.Context, id string, lock bool) (*OnboardingApprovalReview, error) {
	if !ValidID(id) {
		return nil, ErrNotFound
	}
	q := `SELECT review_id::text,actor_id::text,reviewer_id::text,definition_hash,state,revision,created_at,changed_event_id::text,definition FROM onboarding_approval_reviews WHERE tenant_id=$1 AND partner_id=$2 AND review_id=$3 AND (actor_id=$4 OR reviewer_id=$4)`
	if lock {
		q += ` FOR UPDATE`
	}
	var r OnboardingApprovalReview
	var data []byte
	err := t.Tx.QueryRow(ctx, q, t.Scope.Tenant, t.Scope.Partner, id, t.Actor).Scan(&r.ID, &r.Author, &r.Reviewer, &r.Hash, &r.State, &r.Revision, &r.CreatedAt, &r.EventID, &data)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if json.Unmarshal(data, &r.Definition) != nil {
		return nil, ErrIsolation
	}
	b, err := json.Marshal(r.Definition)
	if err != nil || secure.Digest(b) != r.Hash || r.Definition.Author != r.Author || r.Definition.Reviewer != r.Reviewer || r.Definition.Schema != 1 {
		return nil, ErrIsolation
	}
	r.CreatedAt = r.CreatedAt.UTC()
	return &r, nil
}
func (t *Transaction) SaveOnboardingApprovalReview(ctx context.Context, r *OnboardingApprovalReview, previous int64) error {
	e, err := t.Append(ctx, "OnboardingApprovalReviewChanged", r.ID, r)
	if err != nil {
		return err
	}
	r.EventID = e
	if previous == 0 {
		d, err := json.Marshal(r.Definition)
		if err != nil {
			return err
		}
		_, err = t.Tx.Exec(ctx, `INSERT INTO onboarding_approval_reviews VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, t.Scope.Tenant, t.Scope.Partner, r.Author, r.ID, r.Reviewer, r.Definition.ReleaseID, d, r.Hash, r.State, r.Revision, r.CreatedAt, e, r.Definition.Policy.Revision)
		return err
	}
	tag, err := t.Tx.Exec(ctx, `UPDATE onboarding_approval_reviews SET state=$1,revision=$2,changed_event_id=$3 WHERE tenant_id=$4 AND partner_id=$5 AND review_id=$6 AND revision=$7`, r.State, r.Revision, e, t.Scope.Tenant, t.Scope.Partner, r.ID, previous)
	if err == nil && tag.RowsAffected() != 1 {
		return ErrRevision
	}
	return err
}
func (t *Transaction) OnboardingApprovalReviews(ctx context.Context, after string, limit int) (*OnboardingApprovalPage, error) {
	if (after != "" && !ValidID(after)) || limit < 1 || limit > 100 {
		return nil, ErrOnboardingInput
	}
	rows, err := t.Tx.Query(ctx, `SELECT review_id::text,actor_id::text,reviewer_id::text,definition_hash,state,revision,created_at,changed_event_id::text FROM onboarding_approval_reviews WHERE tenant_id=$1 AND partner_id=$2 AND (actor_id=$3 OR reviewer_id=$3) AND ($4='' OR review_id>nullif($4,'')::uuid) ORDER BY review_id LIMIT $5`, t.Scope.Tenant, t.Scope.Partner, t.Actor, after, limit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := &OnboardingApprovalPage{Reviews: []OnboardingApprovalSummary{}}
	for rows.Next() {
		var r OnboardingApprovalSummary
		if err = rows.Scan(&r.ID, &r.Author, &r.Reviewer, &r.Hash, &r.State, &r.Revision, &r.CreatedAt, &r.EventID); err != nil {
			return nil, err
		}
		r.CreatedAt = r.CreatedAt.UTC()
		out.Reviews = append(out.Reviews, r)
	}
	if len(out.Reviews) > limit {
		out.Next = out.Reviews[limit-1].ID
		out.Reviews = out.Reviews[:limit]
	}
	return out, rows.Err()
}
