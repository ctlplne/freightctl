package store

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
)

const MaxWorkflowRunHistoryPage = 64

var workflowReasonCode = regexp.MustCompile(`^[a-z][a-z0-9_]{0,95}$`)

type WorkflowRunTransition struct {
	EventID  string    `json:"event_id"`
	Revision int64     `json:"revision"`
	State    string    `json:"state"`
	Reason   string    `json:"reason"`
	At       time.Time `json:"recorded_at"`
}

// WorkflowRunHistory reads a bounded, contiguous window from this actor's
// immutable run events. A head page also matches the live projection's event.
func (t *Transaction) WorkflowRunHistory(ctx context.Context, run *WorkflowRun, after, last int64) ([]WorkflowRunTransition, error) {
	if after < 0 || last <= after || last > run.Revision || last-after > MaxWorkflowRunHistoryPage {
		return nil, ErrRevision
	}
	identity, err := json.Marshal(map[string]any{
		"id": run.ID, "workflow_id": run.WorkflowID, "workflow_version": run.WorkflowVersion,
		"workflow_hash": run.WorkflowHash, "file_id": run.FileID, "source": run.Source,
		"authority_revision": run.Authority, "namespace_root": run.Root,
	})
	if err != nil {
		return nil, err
	}
	count := last - after
	rows, err := t.Tx.Query(ctx, `SELECT event_id::text, (payload->>'revision')::bigint, payload->>'state', payload->>'reason',
		happened_at, payload @> $6::jsonb FROM events
		WHERE tenant_id=$1 AND partner_id=$2 AND actor_id=$3 AND resource_id=$4 AND kind='WorkflowRunChanged'
		AND (payload->>'revision')::bigint BETWEEN $5::bigint + 1 AND $7
		ORDER BY (payload->>'revision')::bigint, event_id LIMIT $8`,
		t.Scope.Tenant, t.Scope.Partner, t.Actor, run.ID, after, identity, last, count+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]WorkflowRunTransition, 0, count)
	for rows.Next() {
		var entry WorkflowRunTransition
		var matching bool
		if err = rows.Scan(&entry.EventID, &entry.Revision, &entry.State, &entry.Reason, &entry.At, &matching); err != nil {
			return nil, err
		}
		if !matching || !ValidID(entry.EventID) || entry.Revision != after+int64(len(result))+1 ||
			entry.Revision > last || !workflowReasonCode.MatchString(entry.Reason) {
			return nil, ErrState
		}
		switch entry.State {
		case "queued", "running", "attention", "succeeded", "cancelled", "kept_local":
		default:
			return nil, ErrState
		}
		entry.At = entry.At.UTC()
		result = append(result, entry)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if int64(len(result)) != count {
		return nil, ErrState
	}
	if last == run.Revision {
		head := result[len(result)-1]
		if head.State != run.State || head.Reason != run.Reason {
			return nil, ErrState
		}
		var eventID string
		err = t.Tx.QueryRow(ctx, `SELECT changed_event_id::text FROM workflow_runs
			WHERE run_id=$1 AND actor_id=$2 AND revision=$3`, run.ID, t.Actor, last).Scan(&eventID)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrRevision
		}
		if err != nil {
			return nil, err
		}
		if eventID != head.EventID {
			return nil, ErrState
		}
	}
	return result, nil
}
