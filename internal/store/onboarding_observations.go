package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/jackc/pgx/v5"
)

type OnboardingObservationEffect struct {
	Address         string `json:"address"`
	User            string `json:"user"`
	Directory       string `json:"directory"`
	Path            string `json:"path"`
	HostFingerprint string `json:"host_fingerprint"`
	KeyFingerprint  string `json:"key_fingerprint"`
}
type OnboardingObservationWire struct {
	SHA256     string                       `json:"sha256"`
	Size       int64                        `json:"size_bytes"`
	Ciphertext *OnboardingHandoffCiphertext `json:"ciphertext"`
}
type OnboardingObservationDefinition struct {
	Schema             int                           `json:"schema_version"`
	Profile            string                        `json:"profile"`
	Source             OnboardingHandoffSource       `json:"source"`
	OriginalConnection OnboardingReference           `json:"original_connection"`
	File               File                          `json:"authorized_file"`
	SourceRecheckID    string                        `json:"source_recheck_id"`
	Probe              OnboardingActivationReference `json:"probe"`
	Observer           OnboardingProbeDefinition     `json:"observer"`
	Effect             OnboardingObservationEffect   `json:"effect"`
	Wire               OnboardingObservationWire     `json:"wire"`
	RequiredReceipt    string                        `json:"required_receipt"`
	StorageID          string                        `json:"storage_id"`
	Root               string                        `json:"namespace_root"`
	Authority          int64                         `json:"authority_revision"`
}
type OnboardingObservationResult struct {
	Code                string `json:"code"`
	Integrity           bool   `json:"integrity_confirmed"`
	SHA256              string `json:"sha256"`
	Size                int64  `json:"size_bytes"`
	FileFsync           bool   `json:"file_fsync_acknowledged"`
	Reconciled          bool   `json:"reconciled"`
	Business            string `json:"business_acceptance"`
	DirectoryDurability string `json:"directory_power_loss_durability"`
}
type OnboardingObservationSummary struct {
	ID          string                      `json:"id"`
	Author      string                      `json:"author_id"`
	SourceRunID string                      `json:"source_run_id"`
	Hash        string                      `json:"definition_hash"`
	State       string                      `json:"state"`
	Revision    int64                       `json:"revision"`
	WorkerKey   string                      `json:"worker_key"`
	Owner       string                      `json:"lease_owner"`
	LeaseUntil  *time.Time                  `json:"lease_until"`
	StartedAt   *time.Time                  `json:"started_at"`
	CompletedAt *time.Time                  `json:"completed_at"`
	Result      OnboardingObservationResult `json:"result"`
	CreatedAt   time.Time                   `json:"created_at"`
	EventID     string                      `json:"changed_event_id"`
}
type OnboardingObservation struct {
	OnboardingObservationSummary
	Definition OnboardingObservationDefinition `json:"definition"`
}
type OnboardingObservationPage struct {
	Observations []OnboardingObservationSummary `json:"observations"`
	Next         string                         `json:"next,omitempty"`
}
type OnboardingTransportOutcome struct {
	State       string                        `json:"state"`
	Observation *OnboardingObservationSummary `json:"observation,omitempty"`
}

const observationColumns = `observation_id::text,actor_id::text,source_run_id::text,definition_hash,state,revision,worker_key,coalesce(lease_owner::text,''),lease_until,started_at,completed_at,result,created_at,changed_event_id::text`

func scanObservation(row pgx.Row, definition bool) (*OnboardingObservation, error) {
	var o OnboardingObservation
	var data []byte
	args := []any{&o.ID, &o.Author, &o.SourceRunID, &o.Hash, &o.State, &o.Revision, &o.WorkerKey, &o.Owner, &o.LeaseUntil, &o.StartedAt, &o.CompletedAt, &o.Result, &o.CreatedAt, &o.EventID}
	if definition {
		args = append(args, &data)
	}
	if err := row.Scan(args...); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	o.CreatedAt = o.CreatedAt.UTC()
	for _, p := range []*time.Time{o.LeaseUntil, o.StartedAt, o.CompletedAt} {
		if p != nil {
			*p = p.UTC()
		}
	}
	if definition {
		if json.Unmarshal(data, &o.Definition) != nil {
			return nil, ErrIsolation
		}
		encoded, err := json.Marshal(o.Definition)
		if err != nil || secure.Digest(encoded) != o.Hash || o.Definition.Schema != 1 || o.Definition.Profile != "sftp-published-observation-v1" || o.SourceRunID != o.Definition.Source.Dispatch.ID {
			return nil, ErrIsolation
		}
	}
	return &o, nil
}
func (t *Transaction) OnboardingObservation(ctx context.Context, id string, lock bool) (*OnboardingObservation, error) {
	if !ValidID(id) {
		return nil, ErrNotFound
	}
	q := `SELECT ` + observationColumns + `,definition FROM onboarding_observations WHERE tenant_id=$1 AND partner_id=$2 AND actor_id=$3 AND observation_id=$4`
	if lock {
		q += ` FOR UPDATE`
	}
	return scanObservation(t.Tx.QueryRow(ctx, q, t.Scope.Tenant, t.Scope.Partner, t.Actor, id), true)
}
func (t *Transaction) SaveOnboardingObservation(ctx context.Context, o *OnboardingObservation, previous int64) error {
	event, err := t.Append(ctx, "OnboardingObservationChanged", o.ID, o)
	if err != nil {
		return err
	}
	o.EventID = event
	data, err := json.Marshal(o.Definition)
	if err != nil {
		return err
	}
	result, err := json.Marshal(o.Result)
	if err != nil {
		return err
	}
	if previous == 0 {
		_, err = t.Tx.Exec(ctx, `INSERT INTO onboarding_observations(tenant_id,partner_id,actor_id,observation_id,source_run_id,source_delivery_id,plan_id,definition,definition_hash,state,revision,worker_key,lease_owner,lease_until,started_at,completed_at,result,created_at,changed_event_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,nullif($13,'')::uuid,$14,$15,$16,$17,$18,$19)`, t.Scope.Tenant, t.Scope.Partner, t.Actor, o.ID, o.SourceRunID, o.Definition.Source.Delivery.ID, o.Definition.Observer.Plan.ID, data, o.Hash, o.State, o.Revision, o.WorkerKey, o.Owner, o.LeaseUntil, o.StartedAt, o.CompletedAt, result, o.CreatedAt, event)
		return err
	}
	tag, err := t.Tx.Exec(ctx, `UPDATE onboarding_observations SET state=$1,revision=$2,worker_key=$3,lease_owner=nullif($4,'')::uuid,lease_until=$5,started_at=$6,completed_at=$7,result=$8,changed_event_id=$9 WHERE tenant_id=$10 AND partner_id=$11 AND actor_id=$12 AND observation_id=$13 AND revision=$14`, o.State, o.Revision, o.WorkerKey, o.Owner, o.LeaseUntil, o.StartedAt, o.CompletedAt, result, event, t.Scope.Tenant, t.Scope.Partner, t.Actor, o.ID, previous)
	if err == nil && tag.RowsAffected() != 1 {
		return ErrRevision
	}
	return err
}
func (t *Transaction) OnboardingObservations(ctx context.Context, plan, after string, limit int) (*OnboardingObservationPage, error) {
	if !ValidID(plan) || (after != "" && !ValidID(after)) || limit < 1 || limit > 100 {
		return nil, ErrOnboardingInput
	}
	rows, err := t.Tx.Query(ctx, `SELECT `+observationColumns+` FROM onboarding_observations WHERE tenant_id=$1 AND partner_id=$2 AND actor_id=$3 AND plan_id=$4 AND ($5='' OR observation_id>nullif($5,'')::uuid) ORDER BY observation_id LIMIT $6`, t.Scope.Tenant, t.Scope.Partner, t.Actor, plan, after, limit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	page := &OnboardingObservationPage{Observations: []OnboardingObservationSummary{}}
	for rows.Next() {
		o, err := scanObservation(rows, false)
		if err != nil {
			return nil, err
		}
		page.Observations = append(page.Observations, o.OnboardingObservationSummary)
	}
	if len(page.Observations) > limit {
		page.Next = page.Observations[limit-1].ID
		page.Observations = page.Observations[:limit]
	}
	return page, rows.Err()
}
func (t *Transaction) OnboardingObservationAdmission(ctx context.Context) error {
	if _, err := t.Tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, t.Scope.Tenant+":"+t.Scope.Partner+":"+t.Actor+":observation-admission"); err != nil {
		return err
	}
	var n int
	err := t.Tx.QueryRow(ctx, `SELECT count(*) FROM (SELECT 1 FROM onboarding_observations WHERE tenant_id=$1 AND partner_id=$2 AND actor_id=$3 AND state IN ('proposed','approved','running') LIMIT 128) pending`, t.Scope.Tenant, t.Scope.Partner, t.Actor).Scan(&n)
	if err == nil && n >= 128 {
		return ErrLimit
	}
	return err
}
func (s *Store) OnboardingObservationWorkerSlot(ctx context.Context) (func() error, func(), error) {
	return s.encryptionLock(ctx, 721815042, true)
}
func (t *Transaction) OnboardingTransportOutcome(ctx context.Context, run string) (*OnboardingTransportOutcome, error) {
	out := &OnboardingTransportOutcome{State: "unresolved"}
	o, err := scanObservation(t.Tx.QueryRow(ctx, `SELECT `+observationColumns+`,definition FROM onboarding_observations WHERE tenant_id=$1 AND partner_id=$2 AND actor_id=$3 AND source_run_id=$4 AND state='succeeded' ORDER BY completed_at DESC,observation_id DESC LIMIT 1`, t.Scope.Tenant, t.Scope.Partner, t.Actor, run), true)
	if errors.Is(err, ErrNotFound) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	out.State = "integrity_confirmed"
	out.Observation = &o.OnboardingObservationSummary
	return out, nil
}
