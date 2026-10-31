package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/jackc/pgx/v5"
)

// Proofs refer to immutable test records and exact completed receipt snapshots.
// Full readable effects are resolved from the hashed test, never invented here.
type OnboardingReleaseProof struct {
	RequirementID    string `json:"requirement_id"`
	TestID           string `json:"test_id"`
	TestHash         string `json:"test_hash"`
	SnapshotHash     string `json:"snapshot_hash"`
	DeliveryID       string `json:"delivery_id"`
	DeliveryRevision int64  `json:"delivery_revision"`
	ReceiptHash      string `json:"receipt_hash"`
}
type OnboardingReleaseDefinition struct {
	Schema         int                        `json:"schema_version"`
	Profile        string                     `json:"profile"`
	Plan           OnboardingReference        `json:"plan"`
	Authority      int64                      `json:"authority_revision"`
	StorageID      string                     `json:"storage_id"`
	Root           string                     `json:"namespace_root"`
	Proofs         []OnboardingReleaseProof   `json:"proofs"`
	ApprovalPolicy *OnboardingApprovalBinding `json:"approval_policy,omitempty"`
}
type OnboardingReleaseSummary struct {
	ID               string              `json:"id"`
	Plan             OnboardingReference `json:"plan"`
	Author           string              `json:"author_id"`
	Hash             string              `json:"definition_hash"`
	State            string              `json:"state"`
	Revision         int64               `json:"revision"`
	ApprovedRevision int64               `json:"approved_revision"`
	CreatedAt        time.Time           `json:"created_at"`
	EventID          string              `json:"changed_event_id"`
}
type OnboardingRelease struct {
	OnboardingReleaseSummary
	Definition OnboardingReleaseDefinition `json:"definition"`
}
type OnboardingReleasePage struct {
	Releases []OnboardingReleaseSummary `json:"releases"`
	Next     string                     `json:"next,omitempty"`
}
type OnboardingActivationReference struct {
	ID       string `json:"id"`
	Revision int64  `json:"revision"`
	Hash     string `json:"hash"`
}
type OnboardingDispatchDefinition struct {
	Schema        int                           `json:"schema_version"`
	Release       OnboardingActivationReference `json:"release"`
	RequirementID string                        `json:"requirement_id"`
	TestID        string                        `json:"test_id"`
	TestHash      string                        `json:"test_hash"`
	Workflow      OnboardingReference           `json:"workflow"`
	File          File                          `json:"file"`
	StorageID     string                        `json:"storage_id"`
	Root          string                        `json:"namespace_root"`
	Authority     int64                         `json:"authority_revision"`
	Effect        OnboardingTestEffect          `json:"effect"`
}
type OnboardingDispatch struct {
	ID         string                       `json:"id"`
	Author     string                       `json:"author_id"`
	Definition OnboardingDispatchDefinition `json:"definition"`
	Hash       string                       `json:"definition_hash"`
	EventID    string                       `json:"created_event_id"`
}

const releaseColumns = `release_id::text,plan_id::text,plan_version,plan_hash,actor_id::text,definition_hash,state,revision,approved_revision,created_at,changed_event_id::text`

func scanReleaseSummary(row pgx.Row) (*OnboardingReleaseSummary, error) {
	var r OnboardingReleaseSummary
	err := row.Scan(&r.ID, &r.Plan.ID, &r.Plan.Version, &r.Plan.Hash, &r.Author, &r.Hash, &r.State, &r.Revision, &r.ApprovedRevision, &r.CreatedAt, &r.EventID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	r.CreatedAt = r.CreatedAt.UTC()
	return &r, err
}
func (t *Transaction) OnboardingRelease(ctx context.Context, id string, lock bool) (*OnboardingRelease, error) {
	if !ValidID(id) {
		return nil, ErrNotFound
	}
	q := `SELECT ` + releaseColumns + `,definition FROM onboarding_releases WHERE tenant_id=$1 AND partner_id=$2 AND actor_id=$3 AND release_id=$4`
	if lock {
		q += ` FOR UPDATE`
	}
	var r OnboardingRelease
	var data []byte
	err := t.Tx.QueryRow(ctx, q, t.Scope.Tenant, t.Scope.Partner, t.Actor, id).Scan(&r.ID, &r.Plan.ID, &r.Plan.Version, &r.Plan.Hash, &r.Author, &r.Hash, &r.State, &r.Revision, &r.ApprovedRevision, &r.CreatedAt, &r.EventID, &data)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if json.Unmarshal(data, &r.Definition) != nil {
		return nil, ErrIsolation
	}
	encoded, err := json.Marshal(r.Definition)
	if err != nil || secure.Digest(encoded) != r.Hash || r.Plan != r.Definition.Plan || r.Definition.Schema != 1 || r.Definition.Profile != "sftp-outbound-production-v1" {
		return nil, ErrIsolation
	}
	r.CreatedAt = r.CreatedAt.UTC()
	return &r, nil
}
func (t *Transaction) SaveOnboardingRelease(ctx context.Context, r *OnboardingRelease, previous int64) error {
	event, err := t.Append(ctx, "OnboardingReleaseChanged", r.ID, r)
	if err != nil {
		return err
	}
	r.EventID = event
	if previous == 0 {
		data, err := json.Marshal(r.Definition)
		if err != nil {
			return err
		}
		_, err = t.Tx.Exec(ctx, `INSERT INTO onboarding_releases VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`, t.Scope.Tenant, t.Scope.Partner, t.Actor, r.ID, r.Plan.ID, r.Plan.Version, r.Plan.Hash, data, r.Hash, r.State, r.Revision, r.ApprovedRevision, r.CreatedAt, event, r.Definition.StorageID)
		return err
	}
	tag, err := t.Tx.Exec(ctx, `UPDATE onboarding_releases SET state=$1,revision=$2,approved_revision=$3,changed_event_id=$4 WHERE tenant_id=$5 AND partner_id=$6 AND actor_id=$7 AND release_id=$8 AND revision=$9`, r.State, r.Revision, r.ApprovedRevision, event, t.Scope.Tenant, t.Scope.Partner, t.Actor, r.ID, previous)
	if err == nil && tag.RowsAffected() != 1 {
		return ErrRevision
	}
	return err
}
func (t *Transaction) OnboardingReleases(ctx context.Context, plan, after string, limit int) (*OnboardingReleasePage, error) {
	if !ValidID(plan) || (after != "" && !ValidID(after)) || limit < 1 || limit > 100 {
		return nil, ErrOnboardingInput
	}
	rows, err := t.Tx.Query(ctx, `SELECT `+releaseColumns+` FROM onboarding_releases WHERE tenant_id=$1 AND partner_id=$2 AND actor_id=$3 AND plan_id=$4 AND ($5='' OR release_id>nullif($5,'')::uuid) ORDER BY release_id LIMIT $6`, t.Scope.Tenant, t.Scope.Partner, t.Actor, plan, after, limit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	page := &OnboardingReleasePage{Releases: []OnboardingReleaseSummary{}}
	for rows.Next() {
		r, e := scanReleaseSummary(rows)
		if e != nil {
			return nil, e
		}
		page.Releases = append(page.Releases, *r)
	}
	if len(page.Releases) > limit {
		page.Next = page.Releases[limit-1].ID
		page.Releases = page.Releases[:limit]
	}
	return page, rows.Err()
}
func (t *Transaction) SaveOnboardingDispatch(ctx context.Context, d *OnboardingDispatch) error {
	event, err := t.Append(ctx, "OnboardingProductionQueued", d.ID, d)
	if err != nil {
		return err
	}
	d.EventID = event
	data, err := json.Marshal(d.Definition)
	if err != nil {
		return err
	}
	_, err = t.Tx.Exec(ctx, `INSERT INTO onboarding_dispatches VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, t.Scope.Tenant, t.Scope.Partner, t.Actor, d.ID, d.Definition.Release.ID, d.Definition.Release.Revision, d.Definition.RequirementID, data, d.Hash, event)
	return err
}
func (t *Transaction) checkOnboardingProofAvailability(ctx context.Context, run string) error {
	rows, err := t.Tx.Query(ctx, `SELECT DISTINCT tests.definition->'file'->>'id' FROM onboarding_dispatches dispatch JOIN onboarding_releases r USING(tenant_id,partner_id,release_id) CROSS JOIN LATERAL jsonb_array_elements(r.definition->'proofs') proof JOIN onboarding_tests tests ON (tests.tenant_id,tests.partner_id,tests.test_id)=(r.tenant_id,r.partner_id,(proof->>'test_id')::uuid) WHERE (dispatch.tenant_id,dispatch.partner_id,dispatch.actor_id,dispatch.run_id)=($1,$2,$3,$4)`, t.Scope.Tenant, t.Scope.Partner, t.Actor, run)
	if err != nil {
		return err
	}
	var files []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		files = append(files, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if len(files) > 64 {
		return ErrIsolation
	}
	for _, id := range files {
		if err = t.FileAccessible(ctx, id); err != nil {
			return err
		}
	}
	return nil
}

type OnboardingDispatchSummary struct {
	ID            string                        `json:"id"`
	Release       OnboardingActivationReference `json:"release"`
	RequirementID string                        `json:"requirement_id"`
	FileID        string                        `json:"file_id"`
	Hash          string                        `json:"definition_hash"`
}
type OnboardingDispatchPage struct {
	Dispatches []OnboardingDispatchSummary `json:"dispatches"`
	Next       string                      `json:"next,omitempty"`
}

func (t *Transaction) OnboardingDispatch(ctx context.Context, id string) (*OnboardingDispatch, error) {
	if !ValidID(id) {
		return nil, ErrNotFound
	}
	var d OnboardingDispatch
	var raw []byte
	err := t.Tx.QueryRow(ctx, `SELECT run_id::text,actor_id::text,definition,definition_hash,created_event_id::text FROM onboarding_dispatches WHERE tenant_id=$1 AND partner_id=$2 AND actor_id=$3 AND run_id=$4`, t.Scope.Tenant, t.Scope.Partner, t.Actor, id).Scan(&d.ID, &d.Author, &raw, &d.Hash, &d.EventID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if json.Unmarshal(raw, &d.Definition) != nil {
		return nil, ErrIsolation
	}
	encoded, err := json.Marshal(d.Definition)
	if err != nil || secure.Digest(encoded) != d.Hash {
		return nil, ErrIsolation
	}
	return &d, nil
}
func (t *Transaction) OnboardingDispatches(ctx context.Context, release, after string, limit int) (*OnboardingDispatchPage, error) {
	if !ValidID(release) || (after != "" && !ValidID(after)) || limit < 1 || limit > 100 {
		return nil, ErrOnboardingInput
	}
	rows, err := t.Tx.Query(ctx, `SELECT run_id::text,release_id::text,release_revision,definition->'release'->>'hash',requirement_id::text,definition->'file'->>'id',definition_hash FROM onboarding_dispatches WHERE tenant_id=$1 AND partner_id=$2 AND actor_id=$3 AND release_id=$4 AND ($5='' OR run_id>nullif($5,'')::uuid) ORDER BY run_id LIMIT $6`, t.Scope.Tenant, t.Scope.Partner, t.Actor, release, after, limit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	page := &OnboardingDispatchPage{Dispatches: []OnboardingDispatchSummary{}}
	for rows.Next() {
		var d OnboardingDispatchSummary
		if err = rows.Scan(&d.ID, &d.Release.ID, &d.Release.Revision, &d.Release.Hash, &d.RequirementID, &d.FileID, &d.Hash); err != nil {
			return nil, err
		}
		page.Dispatches = append(page.Dispatches, d)
	}
	if len(page.Dispatches) > limit {
		page.Next = page.Dispatches[limit-1].ID
		page.Dispatches = page.Dispatches[:limit]
	}
	return page, rows.Err()
}
