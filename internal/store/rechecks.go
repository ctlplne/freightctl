package store

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
)

// FileRecheck is a private, immutable copy/assessment intent. It cannot change
// its source or policy after proposal, or carry a clean/publication verdict.
type FileRecheck struct {
	ID         string          `json:"id"`
	SourceID   string          `json:"source_file_id"`
	Definition json.RawMessage `json:"definition"`
	Hash       string          `json:"definition_hash"`
	State      string          `json:"state"`
	Revision   int64           `json:"revision"`
	FileID     string          `json:"new_file_id"`
	Result     json.RawMessage `json:"result"`
}
type RecheckSlot struct {
	FileID      string `json:"file_id"`
	SignatureID string `json:"signature_object_id,omitempty"`
}

func (s *Store) RecheckCopySlot(ctx context.Context) (func() error, func(), error) {
	return s.encryptionLock(ctx, 721815041, true)
}
func (t *Transaction) FileRecheck(ctx context.Context, id string, lock bool) (*FileRecheck, error) {
	if !ValidID(id) {
		return nil, ErrNotFound
	}
	q := `SELECT recheck_id::text,source_file_id::text,definition,definition_hash,state,revision,coalesce(new_file_id::text,''),result FROM file_rechecks WHERE recheck_id=$1 AND actor_id=$2`
	if lock {
		q += ` FOR UPDATE`
	}
	r := &FileRecheck{}
	err := t.Tx.QueryRow(ctx, q, id, t.Actor).Scan(&r.ID, &r.SourceID, &r.Definition, &r.Hash, &r.State, &r.Revision, &r.FileID, &r.Result)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return r, err
}
func (t *Transaction) SaveFileRecheck(ctx context.Context, r *FileRecheck, previous int64) error {
	event, err := t.Append(ctx, "FileRecheckChanged", r.ID, r)
	if err != nil {
		return err
	}
	if previous == 0 {
		_, err = t.Tx.Exec(ctx, `INSERT INTO file_rechecks VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,nullif($10,'')::uuid,$11,$12)`, t.Scope.Tenant, t.Scope.Partner, t.Actor, r.ID, r.SourceID, r.Definition, r.Hash, r.State, r.Revision, r.FileID, r.Result, event)
		if err != nil {
			return err
		}
		var d struct {
			Slots []RecheckSlot `json:"staging_slots"`
		}
		if json.Unmarshal(r.Definition, &d) != nil || len(d.Slots) != 3 {
			return ErrState
		}
		for i, slot := range d.Slots {
			if _, err = t.Tx.Exec(ctx, `INSERT INTO file_recheck_slots VALUES($1,$2,$3,$4,$5,$6,nullif($7,'')::uuid)`, t.Scope.Tenant, t.Scope.Partner, t.Actor, r.ID, i+1, slot.FileID, slot.SignatureID); err != nil {
				return err
			}
		}
		return nil
	}
	tag, err := t.Tx.Exec(ctx, `UPDATE file_rechecks SET state=$1,revision=$2,new_file_id=nullif($3,'')::uuid,result=$4,changed_event_id=$5 WHERE recheck_id=$6 AND actor_id=$7 AND revision=$8`, r.State, r.Revision, r.FileID, r.Result, event, r.ID, t.Actor, previous)
	if err == nil && tag.RowsAffected() != 1 {
		return ErrRevision
	}
	return err
}

// AcceptRecheckedFile is called only after exact intent-owned bytes are synced.
// Its SQL guard requires an approved intent and an atomic held-check completion.
func (t *Transaction) AcceptRecheckedFile(ctx context.Context, r *FileRecheck, f *File, storageID string) error {
	if err := t.Reauthorize(ctx); err != nil {
		return err
	}
	event, err := t.Append(ctx, "FileAccepted", f.ID, map[string]any{"schema_version": 3, "size_bytes": f.Size, "sha256": f.SHA256, "policy": f.Policy, "storage_id": storageID, "recheck_id": r.ID, "source_file_id": r.SourceID, "recheck_definition_hash": r.Hash})
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
