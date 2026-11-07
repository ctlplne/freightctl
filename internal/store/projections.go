package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// RecordProjection is a durable processing intent, not a publication verdict.
// The immutable definition owns exactly three private crash-recovery slots.
type RecordProjection struct {
	ID         string          `json:"id"`
	SourceID   string          `json:"source_file_id"`
	Definition json.RawMessage `json:"definition"`
	Hash       string          `json:"definition_hash"`
	State      string          `json:"state"`
	Revision   int64           `json:"revision"`
	Attempts   int             `json:"attempts"`
	WorkerID   string          `json:"worker_id"`
	LeaseUntil *time.Time      `json:"lease_until"`
	FileID     string          `json:"new_file_id"`
	Result     json.RawMessage `json:"result"`
}

func (s *Store) ProjectionSlot(ctx context.Context) (func() error, func(), error) {
	return s.encryptionLock(ctx, 721815045, true)
}

func (t *Transaction) RecordProjection(ctx context.Context, id string, lock bool) (*RecordProjection, error) {
	if !ValidID(id) {
		return nil, ErrNotFound
	}
	q := `SELECT projection_id::text,source_file_id::text,definition,definition_hash,state,revision,attempts,coalesce(worker_id::text,''),lease_until,coalesce(new_file_id::text,''),result FROM record_projections WHERE projection_id=$1 AND actor_id=$2`
	if lock {
		q += ` FOR UPDATE`
	}
	r := &RecordProjection{}
	err := t.Tx.QueryRow(ctx, q, id, t.Actor).Scan(&r.ID, &r.SourceID, &r.Definition, &r.Hash, &r.State, &r.Revision, &r.Attempts, &r.WorkerID, &r.LeaseUntil, &r.FileID, &r.Result)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return r, err
}

func (t *Transaction) SaveRecordProjection(ctx context.Context, r *RecordProjection, previous int64) error {
	event, err := t.Append(ctx, "RecordProjectionChanged", r.ID, r)
	if err != nil {
		return err
	}
	if previous == 0 {
		_, err = t.Tx.Exec(ctx, `INSERT INTO record_projections VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,nullif($11,'')::uuid,$12,nullif($13,'')::uuid,$14,$15)`, t.Scope.Tenant, t.Scope.Partner, t.Actor, r.ID, r.SourceID, r.Definition, r.Hash, r.State, r.Revision, r.Attempts, r.WorkerID, r.LeaseUntil, r.FileID, r.Result, event)
		if err != nil {
			return err
		}
		var d struct {
			Slots []string `json:"staging_slots"`
		}
		if json.Unmarshal(r.Definition, &d) != nil || len(d.Slots) != 3 {
			return ErrState
		}
		for i, id := range d.Slots {
			if _, err = t.Tx.Exec(ctx, `INSERT INTO record_projection_slots VALUES($1,$2,$3,$4,$5,$6)`, t.Scope.Tenant, t.Scope.Partner, t.Actor, r.ID, i+1, id); err != nil {
				return err
			}
		}
		return nil
	}
	tag, err := t.Tx.Exec(ctx, `UPDATE record_projections SET state=$1,revision=$2,attempts=$3,worker_id=nullif($4,'')::uuid,lease_until=$5,new_file_id=nullif($6,'')::uuid,result=$7,changed_event_id=$8 WHERE projection_id=$9 AND actor_id=$10 AND revision=$11`, r.State, r.Revision, r.Attempts, r.WorkerID, r.LeaseUntil, r.FileID, r.Result, event, r.ID, t.Actor, previous)
	if err == nil && tag.RowsAffected() != 1 {
		return ErrRevision
	}
	return err
}

// Acceptance is deliberately distinct from ordinary input/recheck/copy schemas.
// SQL requires a live fenced intent and atomic fresh held-check completion.
func (t *Transaction) AcceptProjectedFile(ctx context.Context, r *RecordProjection, f *File, storage string, report any, attempt any) error {
	if err := t.Reauthorize(ctx); err != nil {
		return err
	}
	var definition struct {
		Schema int `json:"schema_version"`
	}
	if json.Unmarshal(r.Definition, &definition) != nil {
		return ErrState
	}
	schema := 5
	if definition.Schema == 3 {
		schema = 6
	} else if definition.Schema == 4 {
		schema = 7
	}
	event, err := t.Append(ctx, "FileAccepted", f.ID, map[string]any{"schema_version": schema, "size_bytes": f.Size, "sha256": f.SHA256, "policy": f.Policy, "storage_id": storage, "record_projection": map[string]any{"id": r.ID, "definition_hash": r.Hash, "source_file_id": r.SourceID, "attempt": attempt, "report": report}})
	if err != nil {
		return err
	}
	f.EventID = event
	_, err = t.Tx.Exec(ctx, `INSERT INTO files VALUES($1,$2,$3,$4,$5,$6,$7)`, t.Scope.Tenant, t.Scope.Partner, f.ID, f.Size, f.SHA256, f.Policy, event)
	if err == nil {
		if t.PendingFiles == nil {
			t.PendingFiles = make(map[string]bool)
		}
		t.PendingFiles[f.ID] = true
	}
	return err
}
