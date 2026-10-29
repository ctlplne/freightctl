package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/jackc/pgx/v5"
)

type OnboardingReference struct {
	ID      string `json:"id"`
	Version int    `json:"version"`
	Hash    string `json:"hash"`
}
type OnboardingProbeRequest struct {
	Plan              OnboardingReference `json:"plan"`
	RequirementID     string              `json:"requirement_id"`
	Connection        OnboardingReference `json:"connection"`
	ExpectedAuthority int64               `json:"expected_authority_revision"`
}
type OnboardingProbeDefinition struct {
	Schema        int                 `json:"schema_version"`
	Profile       string              `json:"profile"`
	Plan          OnboardingReference `json:"plan"`
	RequirementID string              `json:"requirement_id"`
	Connection    OnboardingReference `json:"connection"`
	Authority     int64               `json:"authority_revision"`
}

// These observations contain no peer text, directory contents or payload data.
// A positive result proves only this read-only connectivity profile.
type OnboardingProbeObservation struct {
	Code       string `json:"code"`
	SSH        bool   `json:"ssh_identity_and_authentication"`
	SFTP       bool   `json:"sftp_negotiated"`
	Extensions bool   `json:"required_extensions"`
	Directory  bool   `json:"directory_traversable"`
}
type OnboardingProbe struct {
	ID          string                     `json:"id"`
	Author      string                     `json:"author_id"`
	Definition  OnboardingProbeDefinition  `json:"definition"`
	Hash        string                     `json:"definition_hash"`
	State       string                     `json:"state"`
	Revision    int64                      `json:"revision"`
	WorkerKey   string                     `json:"worker_key"`
	Owner       string                     `json:"lease_owner"`
	LeaseUntil  *time.Time                 `json:"lease_until"`
	StartedAt   *time.Time                 `json:"started_at"`
	CompletedAt *time.Time                 `json:"completed_at"`
	Observation OnboardingProbeObservation `json:"observation"`
	CreatedAt   time.Time                  `json:"created_at"`
}

type OnboardingProbePage struct {
	Probes []OnboardingProbe `json:"probes"`
	Next   string            `json:"next,omitempty"`
}

const onboardingProbeColumns = `probe_id::text,actor_id::text,definition,definition_hash,state,revision,worker_key,coalesce(lease_owner::text,''),lease_until,started_at,completed_at,observation,created_at`

func (s *Store) OnboardingProbeWorkerSlot(ctx context.Context) (func() error, func(), error) {
	// An independent two-slot namespace; tests cannot consume transfer/scan slots.
	return s.encryptionLock(ctx, 721815040, true)
}
func (t *Transaction) OnboardingProbe(ctx context.Context, id string, lock bool) (*OnboardingProbe, error) {
	if !ValidID(id) {
		return nil, ErrNotFound
	}
	q := `SELECT ` + onboardingProbeColumns + ` FROM onboarding_probes WHERE tenant_id=$1 AND partner_id=$2 AND actor_id=$3 AND probe_id=$4`
	if lock {
		q += ` FOR UPDATE`
	}
	return scanOnboardingProbe(t.Tx.QueryRow(ctx, q, t.Scope.Tenant, t.Scope.Partner, t.Actor, id))
}

func scanOnboardingProbe(row pgx.Row) (*OnboardingProbe, error) {
	p := &OnboardingProbe{}
	var definition, observation []byte
	err := row.Scan(&p.ID, &p.Author, &definition, &p.Hash, &p.State, &p.Revision, &p.WorkerKey, &p.Owner, &p.LeaseUntil, &p.StartedAt, &p.CompletedAt, &observation, &p.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if json.Unmarshal(definition, &p.Definition) != nil || json.Unmarshal(observation, &p.Observation) != nil {
		return nil, ErrIsolation
	}
	canonical, _ := json.Marshal(p.Definition)
	if secure.Digest(canonical) != p.Hash || p.Definition.Schema != 1 || p.Definition.Profile != "sftp-readonly-v1" {
		return nil, ErrIsolation
	}
	// PostgreSQL preserves the instant, not the JSON offset spelling. Emit one
	// canonical timezone so a first completion and later receipt replay agree.
	p.CreatedAt = p.CreatedAt.UTC()
	for _, value := range []**time.Time{&p.LeaseUntil, &p.StartedAt, &p.CompletedAt} {
		if *value != nil {
			utc := (*value).UTC()
			*value = &utc
		}
	}
	return p, nil
}

func (t *Transaction) OnboardingProbes(ctx context.Context, plan, after string, limit int) (*OnboardingProbePage, error) {
	if !ValidID(plan) || (after != "" && !ValidID(after)) || limit < 1 || limit > 100 {
		return nil, ErrOnboardingInput
	}
	rows, err := t.Tx.Query(ctx, `SELECT `+onboardingProbeColumns+` FROM onboarding_probes WHERE tenant_id=$1 AND partner_id=$2 AND actor_id=$3 AND plan_id=$4 AND ($5='' OR probe_id>nullif($5,'')::uuid) ORDER BY probe_id LIMIT $6`, t.Scope.Tenant, t.Scope.Partner, t.Actor, plan, after, limit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	page := &OnboardingProbePage{Probes: []OnboardingProbe{}}
	for rows.Next() {
		p, err := scanOnboardingProbe(rows)
		if err != nil {
			return nil, err
		}
		page.Probes = append(page.Probes, *p)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if len(page.Probes) > limit {
		page.Probes = page.Probes[:limit]
		page.Next = page.Probes[limit-1].ID
	}
	return page, nil
}
func (t *Transaction) SaveOnboardingProbe(ctx context.Context, p *OnboardingProbe, previous int64) error {
	if p.Author != t.Actor {
		return ErrForbidden
	}
	event, err := t.Append(ctx, "OnboardingProbeChanged", p.ID, p)
	if err != nil {
		return err
	}
	definition, err := json.Marshal(p.Definition)
	if err != nil {
		return err
	}
	observation, err := json.Marshal(p.Observation)
	if err != nil {
		return err
	}
	if previous == 0 {
		_, err = t.Tx.Exec(ctx, `INSERT INTO onboarding_probes(tenant_id,partner_id,actor_id,probe_id,plan_id,plan_version,requirement_id,connection_id,connection_version,definition,definition_hash,state,revision,worker_key,lease_owner,lease_until,started_at,completed_at,observation,created_at,changed_event_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,nullif($15,'')::uuid,$16,$17,$18,$19,$20,$21)`, t.Scope.Tenant, t.Scope.Partner, t.Actor, p.ID, p.Definition.Plan.ID, p.Definition.Plan.Version, p.Definition.RequirementID, p.Definition.Connection.ID, p.Definition.Connection.Version, definition, p.Hash, p.State, p.Revision, p.WorkerKey, p.Owner, p.LeaseUntil, p.StartedAt, p.CompletedAt, observation, p.CreatedAt, event)
		return err
	}
	tag, err := t.Tx.Exec(ctx, `UPDATE onboarding_probes SET state=$1,revision=$2,worker_key=$3,lease_owner=nullif($4,'')::uuid,lease_until=$5,started_at=$6,completed_at=$7,observation=$8,changed_event_id=$9 WHERE tenant_id=$10 AND partner_id=$11 AND actor_id=$12 AND probe_id=$13 AND revision=$14`, p.State, p.Revision, p.WorkerKey, p.Owner, p.LeaseUntil, p.StartedAt, p.CompletedAt, observation, event, t.Scope.Tenant, t.Scope.Partner, t.Actor, p.ID, previous)
	if err == nil && tag.RowsAffected() != 1 {
		return ErrRevision
	}
	return err
}

func (t *Transaction) OnboardingProbeAdmission(ctx context.Context) error {
	var count int
	// The shared onboarding/account-management lock serializes this admission.
	err := t.Tx.QueryRow(ctx, `SELECT count(*) FROM onboarding_probes WHERE tenant_id=$1 AND partner_id=$2 AND actor_id=$3 AND (state='queued' OR (state='running' AND lease_until>clock_timestamp()))`, t.Scope.Tenant, t.Scope.Partner, t.Actor).Scan(&count)
	if err != nil {
		return err
	}
	if count >= 16 {
		return ErrLimit
	}
	return nil
}
