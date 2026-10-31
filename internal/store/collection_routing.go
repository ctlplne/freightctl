package store

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
)

// CollectionRouting is an approval of exact plans for an existing captured job.
// It never replaces the job, its producer manifest or its original source claim.
type CollectionRouting struct {
	ID                string          `json:"id"`
	JobID             string          `json:"job_id"`
	Version           int             `json:"version"`
	Definition        json.RawMessage `json:"definition"`
	Hash              string          `json:"definition_hash"`
	State             string          `json:"state"`
	Revision          int64           `json:"revision"`
	ApprovalAuthority int64           `json:"approval_authority"`
}

const collectionRoutingColumns = `id::text,job_id::text,version,definition,definition_hash,state,revision,approval_authority`

func scanCollectionRouting(row collectionScanner) (*CollectionRouting, error) {
	r := &CollectionRouting{}
	err := row.Scan(&r.ID, &r.JobID, &r.Version, &r.Definition, &r.Hash, &r.State, &r.Revision, &r.ApprovalAuthority)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return r, err
}

func (t *Transaction) CollectionRouting(ctx context.Context, job, id string, lock bool) (*CollectionRouting, error) {
	if !ValidID(job) || !ValidID(id) {
		return nil, ErrNotFound
	}
	q := `SELECT ` + collectionRoutingColumns + ` FROM workflow_collection_routing WHERE actor_id=$1 AND job_id=$2 AND id=$3`
	if lock {
		q += ` FOR UPDATE`
	}
	return scanCollectionRouting(t.Tx.QueryRow(ctx, q, t.Actor, job, id))
}

// A pending proposal or withdrawal does not change execution. Revocation is an
// effective decision: callers must block, rather than silently using older rules.
func (t *Transaction) CurrentCollectionRouting(ctx context.Context, job string) (*CollectionRouting, error) {
	r, err := scanCollectionRouting(t.Tx.QueryRow(ctx, `SELECT `+collectionRoutingColumns+` FROM workflow_collection_routing WHERE actor_id=$1 AND job_id=$2 AND state IN ('approved','revoked') ORDER BY version DESC LIMIT 1`, t.Actor, job))
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	return r, err
}

func (t *Transaction) CollectionRoutingVersion(ctx context.Context, job string) (int, error) {
	var version int
	err := t.Tx.QueryRow(ctx, `SELECT coalesce(max(version),0) FROM workflow_collection_routing WHERE actor_id=$1 AND job_id=$2`, t.Actor, job).Scan(&version)
	return version, err
}

func (t *Transaction) SaveCollectionRouting(ctx context.Context, r *CollectionRouting, previous int64) error {
	event, err := t.Append(ctx, "WorkflowCollectionRoutingChanged", r.ID, r)
	if err != nil {
		return err
	}
	if previous == 0 {
		_, err = t.Tx.Exec(ctx, `INSERT INTO workflow_collection_routing(tenant_id,partner_id,actor_id,id,job_id,version,definition,definition_hash,state,revision,approval_authority,changed_event_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, t.Scope.Tenant, t.Scope.Partner, t.Actor, r.ID, r.JobID, r.Version, r.Definition, r.Hash, r.State, r.Revision, r.ApprovalAuthority, event)
		return err
	}
	tag, err := t.Tx.Exec(ctx, `UPDATE workflow_collection_routing SET state=$1,revision=$2,approval_authority=$3,changed_event_id=$4 WHERE actor_id=$5 AND job_id=$6 AND id=$7 AND revision=$8`, r.State, r.Revision, r.ApprovalAuthority, event, t.Actor, r.JobID, r.ID, previous)
	if err == nil && tag.RowsAffected() != 1 {
		return ErrRevision
	}
	return err
}

// CollectionOriginalRoutingFacts exposes only authoritative metadata. A target
// workflow does not need execution authority to preview these original facts.
func (t *Transaction) CollectionOriginalRoutingFacts(ctx context.Context, job, file string) (json.RawMessage, error) {
	var raw []byte
	err := t.Tx.QueryRow(ctx, `SELECT freightctl_collection_original_facts($1,$2,$3,$4,$5)`, t.Scope.Tenant, t.Scope.Partner, t.Actor, job, file).Scan(&raw)
	if err == nil && len(raw) == 0 {
		return nil, ErrCollection
	}
	return raw, err
}

type CollectionRoutingPage struct {
	Authorizations []CollectionRouting `json:"authorizations"`
	Next           int                 `json:"next,omitempty"`
}

func (t *Transaction) CollectionRoutingHistory(ctx context.Context, job string, after, limit int) (*CollectionRoutingPage, error) {
	if !ValidID(job) || after < 0 || after > 2147483647 || limit < 1 || limit > 100 {
		return nil, ErrLimit
	}
	rows, err := t.Tx.Query(ctx, `SELECT `+collectionRoutingColumns+` FROM workflow_collection_routing WHERE actor_id=$1 AND job_id=$2 AND version>$3 ORDER BY version LIMIT $4`, t.Actor, job, after, limit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	p := &CollectionRoutingPage{Authorizations: []CollectionRouting{}}
	for rows.Next() {
		r, err := scanCollectionRouting(rows)
		if err != nil {
			return nil, err
		}
		p.Authorizations = append(p.Authorizations, *r)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if len(p.Authorizations) > limit {
		p.Authorizations = p.Authorizations[:limit]
		p.Next = p.Authorizations[limit-1].Version
	}
	return p, nil
}
