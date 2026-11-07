package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

type ProcessingWorkflowBinding struct {
	WorkflowID string `json:"workflow_id"`
	Version    int    `json:"workflow_version"`
	Hash       string `json:"workflow_hash"`
	RunID      string `json:"run_id"`
	StepID     string `json:"step_id"`
}
type WorkflowProcessing struct {
	RunID        string `json:"run_id"`
	ProjectionID string `json:"projection_id"`
	Hash         string `json:"definition_hash"`
}

func (t *Transaction) WorkflowProcessing(ctx context.Context, id string) (*WorkflowProcessing, error) {
	b := &WorkflowProcessing{}
	err := t.Tx.QueryRow(ctx, `SELECT run_id::text,projection_id::text,definition_hash FROM workflow_processing WHERE run_id=$1 AND actor_id=$2`, id, t.Actor).Scan(&b.RunID, &b.ProjectionID, &b.Hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return b, err
}
func (t *Transaction) BindWorkflowProcessing(ctx context.Context, b *WorkflowProcessing) error {
	event, err := t.Append(ctx, "WorkflowProcessingBound", b.RunID, b)
	if err != nil {
		return err
	}
	_, err = t.Tx.Exec(ctx, `INSERT INTO workflow_processing VALUES($1,$2,$3,$4,$5,$6,$7)`, t.Scope.Tenant, t.Scope.Partner, t.Actor, b.RunID, b.ProjectionID, b.Hash, event)
	return err
}
