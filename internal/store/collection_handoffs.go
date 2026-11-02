package store

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
)

// CollectionHandoff preserves the original assignment. PlannedRunID names an
// exact successor; it exists as a run only after the completed transaction.
type CollectionHandoff struct {
	ID                string          `json:"id"`
	JobID             string          `json:"job_id"`
	InputID           string          `json:"input_id"`
	SourceRunID       string          `json:"source_run_id"`
	PlannedRunID      string          `json:"planned_run_id"`
	Definition        json.RawMessage `json:"definition"`
	Hash              string          `json:"definition_hash"`
	State             string          `json:"state"`
	Revision          int64           `json:"revision"`
	ApprovalAuthority int64           `json:"approval_authority"`
}

const collectionHandoffColumns = `id::text,job_id::text,input_id::text,source_run_id::text,planned_run_id::text,definition,definition_hash,state,revision,approval_authority`

type CollectionHandoffPage struct {
	Handoffs []CollectionHandoff `json:"handoffs"`
	Next     string              `json:"next,omitempty"`
}

func (t *Transaction) CollectionHandoffHistory(ctx context.Context, job, after string, limit int) (*CollectionHandoffPage, error) {
	if !ValidID(job) || (after != "" && !ValidID(after)) || limit < 1 || limit > 100 {
		return nil, ErrLimit
	}
	rows, err := t.Tx.Query(ctx, `SELECT `+collectionHandoffColumns+` FROM workflow_collection_handoffs WHERE actor_id=$1 AND job_id=$2 AND ($3='' OR id>nullif($3,'')::uuid) ORDER BY id LIMIT $4`, t.Actor, job, after, limit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	page := &CollectionHandoffPage{Handoffs: []CollectionHandoff{}}
	for rows.Next() {
		var h CollectionHandoff
		if err := rows.Scan(&h.ID, &h.JobID, &h.InputID, &h.SourceRunID, &h.PlannedRunID, &h.Definition, &h.Hash, &h.State, &h.Revision, &h.ApprovalAuthority); err != nil {
			return nil, err
		}
		page.Handoffs = append(page.Handoffs, h)
	}
	if len(page.Handoffs) > limit {
		page.Handoffs = page.Handoffs[:limit]
		page.Next = page.Handoffs[limit-1].ID
	}
	return page, rows.Err()
}

func (t *Transaction) CollectionHandoff(ctx context.Context, job, id string, lock bool) (*CollectionHandoff, error) {
	if !ValidID(job) || !ValidID(id) {
		return nil, ErrNotFound
	}
	query := `SELECT ` + collectionHandoffColumns + ` FROM workflow_collection_handoffs WHERE actor_id=$1 AND job_id=$2 AND id=$3`
	if lock {
		query += ` FOR UPDATE`
	}
	h := &CollectionHandoff{}
	err := t.Tx.QueryRow(ctx, query, t.Actor, job, id).Scan(&h.ID, &h.JobID, &h.InputID, &h.SourceRunID, &h.PlannedRunID, &h.Definition, &h.Hash, &h.State, &h.Revision, &h.ApprovalAuthority)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return h, err
}

func (t *Transaction) SaveCollectionHandoff(ctx context.Context, h *CollectionHandoff, previous int64) error {
	event, err := t.Append(ctx, "WorkflowCollectionHandoffChanged", h.ID, h)
	if err != nil {
		return err
	}
	if previous == 0 {
		_, err = t.Tx.Exec(ctx, `INSERT INTO workflow_collection_handoffs(tenant_id,partner_id,actor_id,id,job_id,input_id,source_run_id,planned_run_id,definition,definition_hash,state,revision,approval_authority,changed_event_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, t.Scope.Tenant, t.Scope.Partner, t.Actor, h.ID, h.JobID, h.InputID, h.SourceRunID, h.PlannedRunID, h.Definition, h.Hash, h.State, h.Revision, h.ApprovalAuthority, event)
		return err
	}
	tag, err := t.Tx.Exec(ctx, `UPDATE workflow_collection_handoffs SET state=$1,revision=$2,approval_authority=$3,changed_event_id=$4 WHERE actor_id=$5 AND job_id=$6 AND id=$7 AND revision=$8`, h.State, h.Revision, h.ApprovalAuthority, event, t.Actor, h.JobID, h.ID, previous)
	if err == nil && tag.RowsAffected() != 1 {
		return ErrRevision
	}
	return err
}

func (t *Transaction) CollectionHandoffDefinition(ctx context.Context, job, input, source, workflow string, version int, hash string) (json.RawMessage, error) {
	var raw []byte
	err := t.Tx.QueryRow(ctx, `SELECT freightctl_collection_handoff_definition($1,$2,$3,$4,$5,$6,$7,$8,$9,false)`, t.Scope.Tenant, t.Scope.Partner, t.Actor, job, input, source, workflow, version, hash).Scan(&raw)
	if err == nil && len(raw) == 0 {
		return nil, ErrState
	}
	return raw, err
}
