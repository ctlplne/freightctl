package store

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/jackc/pgx/v5"
)

type EncryptionPolicy struct {
	Key     PGPReference `json:"key"`
	Profile string       `json:"profile"`
}
type DeliveryCiphertext struct {
	DeliveryID     string               `json:"delivery_id"`
	ObjectID       string               `json:"object_id"`
	StorageID      string               `json:"storage_id"`
	Size           int64                `json:"size_bytes"`
	SHA256         string               `json:"sha256"`
	SourceID       string               `json:"source_file_id"`
	SourceSHA256   string               `json:"source_sha256"`
	DefinitionHash string               `json:"definition_hash"`
	Policy         EncryptionPolicy     `json:"encryption"`
	Proof          secure.PGPEncryption `json:"proof"`
	Fence          int64                `json:"prepared_fence"`
	Owner          string               `json:"prepared_owner"`
	EventID        string               `json:"prepared_event_id,omitempty"`
}

func (t *Transaction) EncryptionKey(ctx context.Context, p EncryptionPolicy) (*secure.PGPPublicKey, error) {
	if p.Profile != secure.PGPEncryptMDC && p.Profile != secure.PGPEncryptAEAD {
		return nil, ErrState
	}
	row, err := t.PGPKey(ctx, p.Key.ID, p.Key.Version, false)
	if err != nil {
		return nil, err
	}
	now, err := t.DatabaseTime(ctx)
	if err != nil {
		return nil, err
	}
	if row.State != "active" || row.Hash != p.Key.Hash || (row.ValidUntil != nil && !now.Before(*row.ValidUntil)) {
		return nil, ErrState
	}
	var key secure.PGPPublicKey
	if err = json.Unmarshal(row.Definition, &key); err != nil {
		return nil, ErrState
	}
	canonical, err := json.Marshal(key)
	if err != nil || secure.Digest(canonical) != row.Hash || key.Schema != 1 || key.Purpose != "encrypt" || key.Recipient == nil || !slices.Contains(key.Recipient.Profiles, p.Profile) {
		return nil, ErrState
	}
	return &key, nil
}
func (t *Transaction) DeliveryCiphertext(ctx context.Context, id string) (*DeliveryCiphertext, error) {
	a := &DeliveryCiphertext{}
	err := t.Tx.QueryRow(ctx, `SELECT delivery_id::text,object_id::text,storage_id::text,size_bytes,sha256,source_file_id::text,source_sha256,definition_hash,encryption,proof,prepared_fence,prepared_owner::text,prepared_event_id::text FROM delivery_ciphertexts WHERE delivery_id=$1 AND actor_id=$2`, id, t.Actor).Scan(&a.DeliveryID, &a.ObjectID, &a.StorageID, &a.Size, &a.SHA256, &a.SourceID, &a.SourceSHA256, &a.DefinitionHash, &a.Policy, &a.Proof, &a.Fence, &a.Owner, &a.EventID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return a, err
}
func (t *Transaction) SaveDeliveryCiphertext(ctx context.Context, a *DeliveryCiphertext) error {
	event, err := t.Append(ctx, "DeliveryCiphertextPrepared", a.DeliveryID, a)
	if err != nil {
		return err
	}
	a.EventID = event
	policy, err := json.Marshal(a.Policy)
	if err != nil {
		return err
	}
	proof, err := json.Marshal(a.Proof)
	if err != nil {
		return err
	}
	_, err = t.Tx.Exec(ctx, `INSERT INTO delivery_ciphertexts(tenant_id,partner_id,actor_id,delivery_id,object_id,storage_id,size_bytes,sha256,source_file_id,source_sha256,definition_hash,encryption,proof,prepared_fence,prepared_owner,prepared_event_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`, t.Scope.Tenant, t.Scope.Partner, t.Actor, a.DeliveryID, a.ObjectID, a.StorageID, a.Size, a.SHA256, a.SourceID, a.SourceSHA256, a.DefinitionHash, policy, proof, a.Fence, a.Owner, event)
	return err
}

// Encryption has separate process-wide PostgreSQL slots from transfer streams.
func (s *Store) EncryptionWorkerSlot(ctx context.Context) (func() error, func(), error) {
	return s.encryptionLock(ctx, 721815038, true)
}

// The single custody reservation also excludes ordinary upload admission. A
// session lock can survive short authorization transactions without holding key
// or delivery rows across cryptography; process death releases it automatically.
func (s *Store) CustodyGenerationSlot(ctx context.Context) (func() error, func(), error) {
	return s.encryptionLock(ctx, 721815034, false)
}
func (s *Store) encryptionLock(ctx context.Context, id int64, slots bool) (func() error, func(), error) {
	c, err := s.Pool.Acquire(ctx)
	if err != nil {
		return nil, nil, err
	}
	maximum := 1
	if slots {
		maximum = 2
	}
	for i := 0; i < maximum; i++ {
		var ok bool
		var query string
		var args []any
		if slots {
			query = `SELECT pg_try_advisory_lock($1::integer,$2::integer)`
			args = []any{int32(id), int32(i)}
		} else {
			query = `SELECT pg_try_advisory_lock($1::bigint)`
			args = []any{id}
		}
		if err = c.QueryRow(ctx, query, args...).Scan(&ok); err != nil {
			_ = c.Conn().Close(context.Background())
			c.Release()
			return nil, nil, err
		}
		if ok {
			check := func() error { return c.Conn().Ping(ctx) }
			unlock := "SELECT pg_advisory_unlock($1::bigint)"
			if slots {
				unlock = "SELECT pg_advisory_unlock($1::integer,$2::integer)"
			}
			release := func() {
				cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				if _, err := c.Exec(cleanup, unlock, args...); err != nil {
					_ = c.Conn().Close(cleanup)
				}
				c.Release()
			}
			return check, release, nil
		}
	}
	c.Release()
	return nil, nil, ErrLimit
}
