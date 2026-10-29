package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// Delivery is a projection of immutable transition events. Definition is frozen
// at draft creation. Worker identities and lease times are issued by PostgreSQL.
type Delivery struct {
	ID             string          `json:"id"`
	FileID         string          `json:"file_id"`
	Definition     json.RawMessage `json:"definition"`
	DefinitionHash string          `json:"definition_hash"`
	State          string          `json:"state"`
	Revision       int64           `json:"revision"`
	Fence          int64           `json:"fence"`
	Attempts       int             `json:"attempts"`
	LeaseOwner     string          `json:"lease_owner"`
	LeaseUntil     *time.Time      `json:"lease_until"`
	NextAt         time.Time       `json:"next_at"`
	Observation    json.RawMessage `json:"observation"`
}

// DeliveryWorkerSlot caps this initial database-wide worker profile at two
// streams across processes. A retained session lock disappears on process death.
func (s *Store) DeliveryWorkerSlot(ctx context.Context) (func() error, func(), error) {
	conn, err := s.Pool.Acquire(ctx)
	if err != nil {
		return nil, nil, err
	}
	for slot := int32(0); slot < 2; slot++ {
		var locked bool
		if err = conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(721815035,$1)`, slot).Scan(&locked); err != nil {
			conn.Release()
			return nil, nil, err
		}
		if locked {
			check := func() error { return conn.Conn().Ping(ctx) }
			release := func() {
				cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				if _, err := conn.Exec(cleanup, `SELECT pg_advisory_unlock(721815035,$1)`, slot); err != nil {
					_ = conn.Conn().Close(cleanup)
				}
				conn.Release()
			}
			return check, release, nil
		}
	}
	conn.Release()
	return nil, nil, ErrLimit
}

func (t *Transaction) Delivery(ctx context.Context, id string, lock bool) (*Delivery, error) {
	if !ValidID(id) {
		return nil, ErrNotFound
	}
	q := `SELECT delivery_id::text,file_id::text,definition,definition_hash,state,revision,fence,attempts,coalesce(lease_owner::text,''),lease_until,next_at,observation FROM delivery_intents WHERE delivery_id=$1 AND actor_id=$2`
	if lock {
		q += ` FOR UPDATE`
	}
	d := &Delivery{}
	err := t.Tx.QueryRow(ctx, q, id, t.Actor).Scan(&d.ID, &d.FileID, &d.Definition, &d.DefinitionHash, &d.State, &d.Revision, &d.Fence, &d.Attempts, &d.LeaseOwner, &d.LeaseUntil, &d.NextAt, &d.Observation)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return d, err
}
func (t *Transaction) DatabaseTime(ctx context.Context) (time.Time, error) {
	var now time.Time
	err := t.Tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now)
	return now.UTC().Truncate(time.Microsecond), err
}
func (t *Transaction) SaveDelivery(ctx context.Context, d *Delivery, previous int64) error {
	event, err := t.Append(ctx, "DeliveryTransitioned", d.ID, d)
	if err != nil {
		return err
	}
	if previous == 0 {
		_, err = t.Tx.Exec(ctx, `INSERT INTO delivery_intents(tenant_id,partner_id,actor_id,delivery_id,file_id,definition,definition_hash,state,revision,fence,attempts,lease_owner,lease_until,next_at,observation,changed_event_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,nullif($12,'')::uuid,$13,$14,$15,$16)`, t.Scope.Tenant, t.Scope.Partner, t.Actor, d.ID, d.FileID, d.Definition, d.DefinitionHash, d.State, d.Revision, d.Fence, d.Attempts, d.LeaseOwner, d.LeaseUntil, d.NextAt, d.Observation, event)
		return err
	}
	tag, err := t.Tx.Exec(ctx, `UPDATE delivery_intents SET state=$1,revision=$2,fence=$3,attempts=$4,lease_owner=nullif($5,'')::uuid,lease_until=$6,next_at=$7,observation=$8,changed_event_id=$9 WHERE delivery_id=$10 AND actor_id=$11 AND revision=$12`, d.State, d.Revision, d.Fence, d.Attempts, d.LeaseOwner, d.LeaseUntil, d.NextAt, d.Observation, event, d.ID, t.Actor, previous)
	if err == nil && tag.RowsAffected() != 1 {
		return ErrRevision
	}
	return err
}
func (t *Transaction) DeliveryReplay(ctx context.Context, key, meaning string) (*Delivery, error) {
	if _, err := t.Tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, t.Scope.Tenant+":"+t.Scope.Partner+":"+t.Actor+":delivery-receipt:"+key); err != nil {
		return nil, err
	}
	var prior string
	var data []byte
	err := t.Tx.QueryRow(ctx, `SELECT request_hash,result FROM delivery_receipts WHERE actor_id=$1 AND request_key=$2`, t.Actor, key).Scan(&prior, &data)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if prior != meaning {
		return nil, ErrConflict
	}
	var d Delivery
	err = json.Unmarshal(data, &d)
	return &d, err
}
func (t *Transaction) DeliveryReceipt(ctx context.Context, key, meaning string, d *Delivery) error {
	data, err := json.Marshal(d)
	if err != nil {
		return err
	}
	event, err := t.Append(ctx, "DeliveryCommandCompleted", d.ID, map[string]any{"request_key": key, "request_hash": meaning, "result": json.RawMessage(data)})
	if err != nil {
		return err
	}
	_, err = t.Tx.Exec(ctx, `INSERT INTO delivery_receipts VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, t.Scope.Tenant, t.Scope.Partner, t.Actor, key, meaning, d.ID, data, event)
	return err
}
