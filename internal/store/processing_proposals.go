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

// A definition proposal transfers no file,approval or execution authority.
// Adoption creates an executor-owned draft through ordinary workflow controls.
type ProcessingProposalDefinition struct {
	Profile      string              `json:"profile"`
	Author       ExchangeParticipant `json:"author"`
	Executor     ExchangeParticipant `json:"executor"`
	Definition   json.RawMessage     `json:"definition"`
	WorkflowHash string              `json:"workflow_definition_hash"`
	ExpiresAt    time.Time           `json:"expires_at"`
}

type ProcessingProposal struct {
	ID         string                       `json:"id"`
	Definition ProcessingProposalDefinition `json:"definition"`
	Hash       string                       `json:"definition_hash"`
	State      string                       `json:"state"`
	Revision   int64                        `json:"revision"`
	Adopted    *OnboardingReference         `json:"adopted_workflow,omitempty"`
	CreatedAt  time.Time                    `json:"created_at"`
}

type ProcessingProposalSummary struct {
	ID        string               `json:"id"`
	Author    string               `json:"author_id"`
	Executor  string               `json:"executor_id"`
	Hash      string               `json:"definition_hash"`
	State     string               `json:"state"`
	Revision  int64                `json:"revision"`
	Adopted   *OnboardingReference `json:"adopted_workflow,omitempty"`
	ExpiresAt time.Time            `json:"expires_at"`
}

type ProcessingProposalPage struct {
	Proposals []ProcessingProposalSummary `json:"proposals"`
	Next      string                      `json:"next,omitempty"`
}

func (t *Transaction) ProcessingProposalParticipant(ctx context.Context, id string, executor bool) (ExchangeParticipant, error) {
	p := ExchangeParticipant{Tenant: t.Scope.Tenant, Partner: t.Scope.Partner}
	grants := []string{"workflow_manage"}
	if executor {
		grants = append(grants, "read", "write", "check_run", "workflow_execute")
	}
	var root string
	err := t.Tx.QueryRow(ctx, `SELECT actor_id::text,authority_revision,namespace_root FROM credentials WHERE tenant_id=$1 AND partner_id=$2 AND actor_id=$3 AND permissions @> $4::text[] AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>clock_timestamp())`, t.Scope.Tenant, t.Scope.Partner, id, grants).Scan(&p.Actor, &p.AuthorityRevision, &root)
	if errors.Is(err, pgx.ErrNoRows) {
		return p, ErrNotFound
	}
	if err != nil {
		return p, err
	}
	p.RootPolicyDigest = secure.Digest([]byte(root))
	return p, nil
}

func (t *Transaction) ProcessingProposalAdmission(ctx context.Context, author, executor string) error {
	if author != t.Actor || !ValidID(author) || !ValidID(executor) || author == executor {
		return ErrIsolation
	}
	if _, err := t.Tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, t.Scope.Tenant+":"+t.Scope.Partner+":processing-proposals:"+author); err != nil {
		return err
	}
	// Count only the author's visible rows. Recipient pagination remains bounded;
	// admission never bypasses private RLS to inspect other authors' proposals.
	var authored int
	err := t.Tx.QueryRow(ctx, `SELECT count(*) FROM processing_workflow_proposals WHERE state='pending' AND expires_at>clock_timestamp() AND actor_id=$1`, author).Scan(&authored)
	if err == nil && authored >= 16 {
		return ErrLimit
	}
	return err
}

func (t *Transaction) ProcessingProposal(ctx context.Context, id string, lock bool) (*ProcessingProposal, error) {
	if !ValidID(id) {
		return nil, ErrNotFound
	}
	query := `SELECT proposal_id::text,definition,definition_hash,state,revision,coalesce(adopted_workflow_id::text,''),coalesce(adopted_workflow_version,0),coalesce(adopted_workflow_hash,''),created_at FROM processing_workflow_proposals WHERE tenant_id=$1 AND partner_id=$2 AND proposal_id=$3 AND (actor_id=$4 OR executor_id=$4)`
	if lock {
		query += ` FOR UPDATE`
	}
	r := &ProcessingProposal{}
	var raw []byte
	var adopted OnboardingReference
	err := t.Tx.QueryRow(ctx, query, t.Scope.Tenant, t.Scope.Partner, id, t.Actor).Scan(&r.ID, &raw, &r.Hash, &r.State, &r.Revision, &adopted.ID, &adopted.Version, &adopted.Hash, &r.CreatedAt)
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
	if adopted.ID != "" {
		if !ValidID(adopted.ID) || adopted.Version < 1 || !browserSecretHash.MatchString(adopted.Hash) {
			return nil, ErrIsolation
		}
		r.Adopted = &adopted
	} else if adopted.Version != 0 || adopted.Hash != "" {
		return nil, ErrIsolation
	}
	r.CreatedAt = r.CreatedAt.UTC()
	return r, nil
}

func (t *Transaction) SaveProcessingProposal(ctx context.Context, r *ProcessingProposal, previous int64) error {
	event, err := t.Append(ctx, "ProcessingWorkflowProposalChanged", r.ID, r)
	if err != nil {
		return err
	}
	if previous == 0 {
		raw, err := json.Marshal(r.Definition)
		if err != nil {
			return err
		}
		_, err = t.Tx.Exec(ctx, `INSERT INTO processing_workflow_proposals(tenant_id,partner_id,actor_id,executor_id,proposal_id,definition,definition_hash,state,revision,created_at,expires_at,changed_event_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, t.Scope.Tenant, t.Scope.Partner, r.Definition.Author.Actor, r.Definition.Executor.Actor, r.ID, raw, r.Hash, r.State, r.Revision, r.CreatedAt, r.Definition.ExpiresAt, event)
		return err
	}
	var id, hash string
	var version int
	if r.Adopted != nil {
		id, version, hash = r.Adopted.ID, r.Adopted.Version, r.Adopted.Hash
	}
	tag, err := t.Tx.Exec(ctx, `UPDATE processing_workflow_proposals SET state=$1,revision=$2,adopted_workflow_id=nullif($3,'')::uuid,adopted_workflow_version=nullif($4,0),adopted_workflow_hash=nullif($5,''),changed_event_id=$6 WHERE tenant_id=$7 AND partner_id=$8 AND proposal_id=$9 AND revision=$10 AND (actor_id=$11 OR executor_id=$11)`, r.State, r.Revision, id, version, hash, event, t.Scope.Tenant, t.Scope.Partner, r.ID, previous, t.Actor)
	if err == nil && tag.RowsAffected() != 1 {
		return ErrRevision
	}
	return err
}

func (t *Transaction) ProcessingProposals(ctx context.Context, after string, limit int) (*ProcessingProposalPage, error) {
	if (after != "" && !ValidID(after)) || limit < 1 || limit > 100 {
		return nil, ErrLimit
	}
	rows, err := t.Tx.Query(ctx, `SELECT proposal_id::text,actor_id::text,executor_id::text,definition_hash,state,revision,coalesce(adopted_workflow_id::text,''),coalesce(adopted_workflow_version,0),coalesce(adopted_workflow_hash,''),expires_at FROM processing_workflow_proposals WHERE (actor_id=$1 OR executor_id=$1) AND ($2='' OR proposal_id>nullif($2,'')::uuid) ORDER BY proposal_id LIMIT $3`, t.Actor, after, limit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	page := &ProcessingProposalPage{Proposals: []ProcessingProposalSummary{}}
	for rows.Next() {
		var row ProcessingProposalSummary
		var adopted OnboardingReference
		if err = rows.Scan(&row.ID, &row.Author, &row.Executor, &row.Hash, &row.State, &row.Revision, &adopted.ID, &adopted.Version, &adopted.Hash, &row.ExpiresAt); err != nil {
			return nil, err
		}
		if adopted.ID != "" {
			row.Adopted = &adopted
		}
		page.Proposals = append(page.Proposals, row)
	}
	if len(page.Proposals) > limit {
		page.Next = page.Proposals[limit-1].ID
		page.Proposals = page.Proposals[:limit]
	}
	return page, rows.Err()
}
