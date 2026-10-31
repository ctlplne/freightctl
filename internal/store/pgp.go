package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

type PGPReference struct {
	ID      string `json:"id"`
	Version int    `json:"version"`
	Hash    string `json:"hash"`
}
type PGPKey struct {
	Configuration
	ValidUntil *time.Time `json:"valid_until,omitempty"`
}
type FileSignature struct {
	FileID     string       `json:"file_id"`
	ObjectID   string       `json:"object_id"`
	StorageID  string       `json:"storage_id"`
	Size       int64        `json:"size_bytes"`
	SHA256     string       `json:"sha256"`
	DataSHA256 string       `json:"data_sha256"`
	PolicyHash string       `json:"policy_hash"`
	Key        PGPReference `json:"key"`
	EventID    string       `json:"attached_event_id,omitempty"`
}

func (t *Transaction) PGPKey(ctx context.Context, id string, version int, lock bool) (*PGPKey, error) {
	clause := " FOR SHARE"
	if lock {
		clause = " FOR UPDATE"
	}
	return t.pgpKey(ctx, id, version, clause)
}

// PGPKeySnapshot reads immutable public metadata without joining the execution
// guard's row lock. Historical inspection grants no encryption authority.
func (t *Transaction) PGPKeySnapshot(ctx context.Context, id string, version int) (*PGPKey, error) {
	return t.pgpKey(ctx, id, version, "")
}

func (t *Transaction) pgpKey(ctx context.Context, id string, version int, clause string) (*PGPKey, error) {
	if !ValidID(id) || version < 1 {
		return nil, ErrNotFound
	}
	q := `SELECT key_id::text,version,definition,definition_hash,state,revision,valid_until FROM pgp_keys WHERE key_id=$1 AND version=$2`
	q += clause
	k := &PGPKey{}
	err := t.Tx.QueryRow(ctx, q, id, version).Scan(&k.ID, &k.Version, &k.Definition, &k.Hash, &k.State, &k.Revision, &k.ValidUntil)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return k, err
}
func (t *Transaction) PGPKeyVersion(ctx context.Context, id string) (int, error) {
	if _, err := t.Tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, t.Scope.Tenant+":"+t.Scope.Partner+":pgp-key:"+id); err != nil {
		return 0, err
	}
	var version int
	err := t.Tx.QueryRow(ctx, `SELECT coalesce(max(version),0) FROM pgp_keys WHERE key_id=$1`, id).Scan(&version)
	return version, err
}
func (t *Transaction) SavePGPKey(ctx context.Context, k *PGPKey, previous int64) error {
	event, err := t.Append(ctx, "PGPKeyChanged", k.ID, k)
	if err != nil {
		return err
	}
	if previous == 0 {
		_, err = t.Tx.Exec(ctx, `INSERT INTO pgp_keys VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, t.Scope.Tenant, t.Scope.Partner, t.Actor, k.ID, k.Version, k.Definition, k.Hash, k.ValidUntil, k.State, k.Revision, event)
		return err
	}
	tag, err := t.Tx.Exec(ctx, `UPDATE pgp_keys SET state=$1,revision=$2,changed_event_id=$3 WHERE key_id=$4 AND version=$5 AND revision=$6`, k.State, k.Revision, event, k.ID, k.Version, previous)
	if err == nil && tag.RowsAffected() != 1 {
		return ErrRevision
	}
	return err
}
func (t *Transaction) FileSignature(ctx context.Context, id string) (*FileSignature, error) {
	if !ValidID(id) {
		return nil, ErrNotFound
	}
	s := &FileSignature{}
	err := t.Tx.QueryRow(ctx, `SELECT file_id::text,object_id::text,storage_id::text,size_bytes,sha256,data_sha256,policy_hash,key_id::text,key_version,key_hash,attached_event_id::text FROM file_signatures WHERE file_id=$1 AND actor_id=$2`, id, t.Actor).Scan(&s.FileID, &s.ObjectID, &s.StorageID, &s.Size, &s.SHA256, &s.DataSHA256, &s.PolicyHash, &s.Key.ID, &s.Key.Version, &s.Key.Hash, &s.EventID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return s, err
}
func (t *Transaction) SaveFileSignature(ctx context.Context, s *FileSignature) error {
	event, err := t.Append(ctx, "FileSignatureAttached", s.FileID, s)
	if err != nil {
		return err
	}
	s.EventID = event
	_, err = t.Tx.Exec(ctx, `INSERT INTO file_signatures VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, t.Scope.Tenant, t.Scope.Partner, t.Actor, s.FileID, s.ObjectID, s.StorageID, s.Size, s.SHA256, s.DataSHA256, s.PolicyHash, s.Key.ID, s.Key.Version, s.Key.Hash, event)
	return err
}
func releaseSignatureFields(report json.RawMessage) (PGPReference, string, *time.Time, error) {
	var r struct {
		Signature *struct {
			Key          PGPReference `json:"key"`
			SHA          string       `json:"sha256"`
			Verification struct {
				Until *time.Time `json:"valid_until"`
			} `json:"verification"`
		} `json:"signature"`
	}
	if err := json.Unmarshal(report, &r); err != nil {
		return PGPReference{}, "", nil, err
	}
	if r.Signature == nil {
		return PGPReference{}, "", nil, nil
	}
	return r.Signature.Key, r.Signature.SHA, r.Signature.Verification.Until, nil
}
