package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

type AIJob struct {
	ID             string          `json:"id"`
	ProfileID      string          `json:"profile_id"`
	ProfileVersion int             `json:"profile_version"`
	ProfileHash    string          `json:"profile_hash"`
	Authority      int64           `json:"authority_revision"`
	Root           string          `json:"namespace_root"`
	Kind           string          `json:"kind"`
	Bindings       json.RawMessage `json:"bindings"`
	Context        json.RawMessage `json:"context"`
	ContextHash    string          `json:"context_hash"`
	State          string          `json:"state"`
	Revision       int64           `json:"revision"`
	Attempts       int             `json:"attempts"`
	WorkerID       string          `json:"worker_id"`
	LeaseUntil     *time.Time      `json:"lease_until"`
	Result         json.RawMessage `json:"result"`
	OutputHash     string          `json:"output_hash"`
	Code           string          `json:"code"`
}

func (t *Transaction) AIProfile(ctx context.Context, id string, version int, lock bool) (*Configuration, error) {
	if !ValidID(id) || version < 1 {
		return nil, ErrNotFound
	}
	q := `SELECT profile_id::text,version,definition,definition_hash,state,revision FROM ai_profiles WHERE profile_id=$1 AND version=$2 AND actor_id=$3`
	if lock {
		q += ` FOR UPDATE`
	}
	p := &Configuration{}
	err := t.Tx.QueryRow(ctx, q, id, version, t.Actor).Scan(&p.ID, &p.Version, &p.Definition, &p.Hash, &p.State, &p.Revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return p, err
}
func (t *Transaction) AIProfileVersion(ctx context.Context, id string) (int, error) {
	if _, err := t.Tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, t.Scope.Tenant+":"+t.Scope.Partner+":"+t.Actor+":ai-profile:"+id); err != nil {
		return 0, err
	}
	var v int
	err := t.Tx.QueryRow(ctx, `SELECT coalesce(max(version),0) FROM ai_profiles WHERE profile_id=$1 AND actor_id=$2`, id, t.Actor).Scan(&v)
	return v, err
}
func (t *Transaction) SaveAIProfile(ctx context.Context, p *Configuration, previous int64) error {
	event, err := t.Append(ctx, "AIProfileChanged", p.ID, p)
	if err != nil {
		return err
	}
	if previous == 0 {
		_, err = t.Tx.Exec(ctx, `INSERT INTO ai_profiles VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, t.Scope.Tenant, t.Scope.Partner, t.Actor, p.ID, p.Version, p.Definition, p.Hash, p.State, p.Revision, event)
		return err
	}
	tag, err := t.Tx.Exec(ctx, `UPDATE ai_profiles SET state=$1,revision=$2,changed_event_id=$3 WHERE profile_id=$4 AND version=$5 AND actor_id=$6 AND revision=$7`, p.State, p.Revision, event, p.ID, p.Version, t.Actor, previous)
	if err == nil && tag.RowsAffected() != 1 {
		return ErrRevision
	}
	return err
}
func (t *Transaction) AIJob(ctx context.Context, id string, lock bool) (*AIJob, error) {
	if !ValidID(id) {
		return nil, ErrNotFound
	}
	q := `SELECT job_id::text,profile_id::text,profile_version,profile_hash,authority_revision,namespace_root,kind,bindings,context,context_hash,state,revision,attempts,coalesce(worker_id::text,''),lease_until,result,output_hash,code FROM ai_jobs WHERE job_id=$1 AND actor_id=$2`
	if lock {
		q += ` FOR UPDATE`
	}
	j := &AIJob{}
	err := t.Tx.QueryRow(ctx, q, id, t.Actor).Scan(&j.ID, &j.ProfileID, &j.ProfileVersion, &j.ProfileHash, &j.Authority, &j.Root, &j.Kind, &j.Bindings, &j.Context, &j.ContextHash, &j.State, &j.Revision, &j.Attempts, &j.WorkerID, &j.LeaseUntil, &j.Result, &j.OutputHash, &j.Code)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return j, err
}
func (t *Transaction) SaveAIJob(ctx context.Context, j *AIJob, previous int64) error {
	event, err := t.Append(ctx, "AIJobChanged", j.ID, j)
	if err != nil {
		return err
	}
	if previous == 0 {
		_, err = t.Tx.Exec(ctx, `INSERT INTO ai_jobs VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,nullif($17,'')::uuid,$18,$19,$20,$21,$22)`, t.Scope.Tenant, t.Scope.Partner, t.Actor, j.ID, j.ProfileID, j.ProfileVersion, j.ProfileHash, j.Authority, j.Root, j.Kind, j.Bindings, j.Context, j.ContextHash, j.State, j.Revision, j.Attempts, j.WorkerID, j.LeaseUntil, j.Result, j.OutputHash, j.Code, event)
		return err
	}
	tag, err := t.Tx.Exec(ctx, `UPDATE ai_jobs SET state=$1,revision=$2,attempts=$3,worker_id=nullif($4,'')::uuid,lease_until=$5,result=$6,output_hash=$7,code=$8,changed_event_id=$9 WHERE job_id=$10 AND actor_id=$11 AND revision=$12`, j.State, j.Revision, j.Attempts, j.WorkerID, j.LeaseUntil, j.Result, j.OutputHash, j.Code, event, j.ID, t.Actor, previous)
	if err == nil && tag.RowsAffected() != 1 {
		return ErrRevision
	}
	return err
}
func (t *Transaction) AIReplay(ctx context.Context, key, meaning string) (json.RawMessage, error) {
	if _, err := t.Tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, t.Scope.Tenant+":"+t.Scope.Partner+":"+t.Actor+":ai-receipt:"+key); err != nil {
		return nil, err
	}
	var hash string
	var data json.RawMessage
	err := t.Tx.QueryRow(ctx, `SELECT request_hash,result FROM ai_receipts WHERE request_key=$1 AND actor_id=$2`, key, t.Actor).Scan(&hash, &data)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if hash != meaning {
		return nil, ErrConflict
	}
	return data, nil
}
func (t *Transaction) AIReceipt(ctx context.Context, key, meaning, id string, result any) error {
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}
	event, err := t.Append(ctx, "AICommandCompleted", id, map[string]any{"request_key": key, "request_hash": meaning, "result": json.RawMessage(data)})
	if err != nil {
		return err
	}
	_, err = t.Tx.Exec(ctx, `INSERT INTO ai_receipts VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, t.Scope.Tenant, t.Scope.Partner, t.Actor, key, meaning, id, data, event)
	return err
}

// AISlot is independent of the outbound worker slots. It retains at most one
// database session for assistance across processes; no inference queue grows.
func (s *Store) AISlot(ctx context.Context) (func() error, func(), error) {
	conn, err := s.Pool.Acquire(ctx)
	if err != nil {
		return nil, nil, err
	}
	var locked bool
	if err = conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(721815036,0)`).Scan(&locked); err != nil || !locked {
		conn.Release()
		if err != nil {
			return nil, nil, err
		}
		return nil, nil, ErrLimit
	}
	return func() error { return conn.Conn().Ping(ctx) }, func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if _, err := conn.Exec(cleanup, `SELECT pg_advisory_unlock(721815036,0)`); err != nil {
			_ = conn.Conn().Close(cleanup)
		}
		conn.Release()
	}, nil
}
