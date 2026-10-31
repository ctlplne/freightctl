package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

var ErrArrival = errors.New("current arrival source, cutoff and original probe lease required")

type ScheduleArrival struct {
	ID           string          `json:"occurrence_id"`
	ScheduleID   string          `json:"schedule_id"`
	Version      int             `json:"schedule_version"`
	Definition   json.RawMessage `json:"definition"`
	Hash         string          `json:"definition_hash"`
	State        string          `json:"state"`
	Revision     int64           `json:"revision"`
	Fence        int64           `json:"fence"`
	Probes       int             `json:"probes"`
	Owner        string          `json:"lease_owner"`
	Until        *time.Time      `json:"lease_until"`
	Next         time.Time       `json:"next_probe_at"`
	Observed     *time.Time      `json:"observed_at"`
	Manifest     json.RawMessage `json:"manifest"`
	ManifestHash *string         `json:"manifest_hash"`
	JobID        *string         `json:"collection_id"`
	Reason       string          `json:"reason"`
}

const arrivalColumns = `occurrence_id::text,schedule_id::text,schedule_version,definition,definition_hash,state,revision,fence,probes,coalesce(lease_owner::text,''),lease_until,next_probe_at,observed_at,manifest,manifest_hash,collection_id::text,reason`

func scanArrival(row collectionScanner) (*ScheduleArrival, error) {
	a := &ScheduleArrival{}
	err := row.Scan(&a.ID, &a.ScheduleID, &a.Version, &a.Definition, &a.Hash, &a.State, &a.Revision, &a.Fence, &a.Probes, &a.Owner, &a.Until, &a.Next, &a.Observed, &a.Manifest, &a.ManifestHash, &a.JobID, &a.Reason)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	a.Next = a.Next.UTC()
	if a.Until != nil {
		v := a.Until.UTC()
		a.Until = &v
	}
	if a.Observed != nil {
		v := a.Observed.UTC()
		a.Observed = &v
	}
	return a, nil
}
func (t *Transaction) ScheduleArrival(ctx context.Context, id string, lock bool) (*ScheduleArrival, error) {
	if !ValidID(id) {
		return nil, ErrNotFound
	}
	q := `SELECT ` + arrivalColumns + ` FROM workflow_schedule_arrivals WHERE actor_id=$1 AND occurrence_id=$2`
	if lock {
		q += " FOR UPDATE"
	}
	return scanArrival(t.Tx.QueryRow(ctx, q, t.Actor, id))
}
func (t *Transaction) SaveScheduleArrival(ctx context.Context, a *ScheduleArrival, previous int64) error {
	event, err := t.Append(ctx, "WorkflowScheduleArrivalChanged", a.ID, a)
	if err != nil {
		return err
	}
	if a.State == "ready" {
		// The event trigger owns the verified observation instant. Read it back
		// before projecting so a caller cannot backdate late input into an
		// on-time result, even with direct access to the runtime SQL role.
		var observed time.Time
		if err = t.Tx.QueryRow(ctx, `SELECT happened_at FROM events WHERE event_id=$1`, event).Scan(&observed); err != nil {
			return err
		}
		observed = observed.UTC()
		a.Observed = &observed
	}
	if previous == 0 {
		_, err = t.Tx.Exec(ctx, `INSERT INTO workflow_schedule_arrivals VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,nullif($13,'')::uuid,$14,$15,$16,$17,$18,$19,$20,$21)`, t.Scope.Tenant, t.Scope.Partner, t.Actor, a.ID, a.ScheduleID, a.Version, a.Definition, a.Hash, a.State, a.Revision, a.Fence, a.Probes, a.Owner, a.Until, a.Next, a.Observed, a.Manifest, a.ManifestHash, a.JobID, a.Reason, event)
		return err
	}
	tag, err := t.Tx.Exec(ctx, `UPDATE workflow_schedule_arrivals SET state=$1,revision=$2,fence=$3,probes=$4,lease_owner=nullif($5,'')::uuid,lease_until=$6,next_probe_at=$7,observed_at=$8,manifest=$9,manifest_hash=$10,collection_id=$11,reason=$12,changed_event_id=$13 WHERE actor_id=$14 AND occurrence_id=$15 AND revision=$16`, a.State, a.Revision, a.Fence, a.Probes, a.Owner, a.Until, a.Next, a.Observed, a.Manifest, a.ManifestHash, a.JobID, a.Reason, event, t.Actor, a.ID, previous)
	if err == nil && tag.RowsAffected() != 1 {
		return ErrRevision
	}
	return err
}
func (t *Transaction) ScheduleArrivals(ctx context.Context, id string, version, limit int) ([]ScheduleArrival, error) {
	if !ValidID(id) || version < 1 || limit < 1 || limit > 100 {
		return nil, ErrLimit
	}
	rows, err := t.Tx.Query(ctx, `SELECT `+arrivalColumns+` FROM workflow_schedule_arrivals WHERE actor_id=$1 AND schedule_id=$2 AND schedule_version=$3 ORDER BY (definition->>'due_at')::timestamptz DESC,occurrence_id LIMIT $4`, t.Actor, id, version, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ScheduleArrival{}
	for rows.Next() {
		a, e := scanArrival(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}
func (t *Transaction) ScheduleCollectionActive(ctx context.Context, id string) (int, error) {
	var count int
	err := t.Tx.QueryRow(ctx, `SELECT count(*) FROM workflow_schedule_arrivals a JOIN workflow_schedules s ON (s.tenant_id,s.partner_id,s.actor_id,s.schedule_id,s.version)=(a.tenant_id,a.partner_id,a.actor_id,a.schedule_id,a.schedule_version) LEFT JOIN workflow_collection_jobs j ON (j.tenant_id,j.partner_id,j.id)=(a.tenant_id,a.partner_id,a.collection_id) WHERE a.actor_id=$1 AND a.schedule_id=$2 AND s.state='active' AND (a.definition->>'deadline_at')::timestamptz>clock_timestamp() AND (((a.state='ready' OR (a.state IN ('waiting','probing','attention') AND (a.definition->>'arrival_deadline_at')::timestamptz>clock_timestamp()))) OR (a.state='admitted' AND j.state NOT IN ('cancelled','expired') AND (NOT j.captured OR (freightctl_collection_needs_routing(j.tenant_id,j.partner_id,j.actor_id,j.definition) AND EXISTS(SELECT 1 FROM workflow_collection_inputs i LEFT JOIN workflow_runs r ON (r.tenant_id,r.partner_id,r.run_id)=(i.tenant_id,i.partner_id,i.run_id) WHERE (i.tenant_id,i.partner_id,i.actor_id,i.first_job_id)=(a.tenant_id,a.partner_id,a.actor_id,a.collection_id) AND (i.state<>'queued' OR r.state NOT IN ('succeeded','cancelled','kept_local')))))))`, t.Actor, id).Scan(&count)
	return count, err
}

func (t *Transaction) ScheduleArrivalPending(ctx context.Context, id string, version int) ([]string, error) {
	if !ValidID(id) || version < 1 {
		return nil, ErrLimit
	}
	rows, err := t.Tx.Query(ctx, `SELECT a.occurrence_id::text FROM workflow_schedule_arrivals a LEFT JOIN workflow_collection_jobs j ON (j.tenant_id,j.partner_id,j.id)=(a.tenant_id,a.partner_id,a.collection_id) WHERE a.actor_id=$1 AND a.schedule_id=$2 AND a.schedule_version=$3 AND (a.state IN ('waiting','probing','attention','ready') OR (a.state='admitted' AND (a.definition->>'deadline_at')::timestamptz>clock_timestamp() AND j.state NOT IN ('cancelled','expired') AND (NOT j.captured OR (freightctl_collection_needs_routing(j.tenant_id,j.partner_id,j.actor_id,j.definition) AND EXISTS(SELECT 1 FROM workflow_collection_inputs i LEFT JOIN workflow_runs r ON (r.tenant_id,r.partner_id,r.run_id)=(i.tenant_id,i.partner_id,i.run_id) WHERE (i.tenant_id,i.partner_id,i.actor_id,i.first_job_id)=(a.tenant_id,a.partner_id,a.actor_id,a.collection_id) AND (i.state<>'queued' OR r.state NOT IN ('succeeded','cancelled','kept_local'))))))) ORDER BY (a.definition->>'due_at')::timestamptz,a.occurrence_id LIMIT 64`, t.Actor, id, version)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
