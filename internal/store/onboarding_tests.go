package store

import (
	"context"
	"encoding/json"
	"errors"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/jackc/pgx/v5"
	"time"
)

type OnboardingTestProbe struct {
	ID       string `json:"id"`
	Revision int64  `json:"revision"`
	Hash     string `json:"hash"`
}
type OnboardingTestEffect struct {
	Address              string            `json:"address"`
	User                 string            `json:"user"`
	Directory            string            `json:"directory"`
	Filename             string            `json:"filename"`
	HostFingerprint      string            `json:"host_fingerprint"`
	KeyFingerprint       string            `json:"key_fingerprint"`
	Encryption           *EncryptionPolicy `json:"encryption,omitempty"`
	RecipientFingerprint string            `json:"recipient_fingerprint"`
}
type OnboardingTestDefinition struct {
	Schema           int                  `json:"schema_version"`
	Profile          string               `json:"profile"`
	Plan             OnboardingReference  `json:"plan"`
	RequirementID    string               `json:"requirement_id"`
	Probe            OnboardingTestProbe  `json:"probe"`
	Workflow         OnboardingReference  `json:"workflow"`
	WorkflowRevision int64                `json:"workflow_revision"`
	StepID           string               `json:"step_id"`
	Connection       OnboardingReference  `json:"connection"`
	Effect           OnboardingTestEffect `json:"effect"`
	File             File                 `json:"file"`
	StorageID        string               `json:"storage_id"`
	Root             string               `json:"namespace_root"`
	Authority        int64                `json:"authority_revision"`
	RequiredReceipt  string               `json:"required_receipt"`
}
type OnboardingTest struct {
	ID         string                   `json:"id"`
	RunID      string                   `json:"run_id"`
	Author     string                   `json:"author_id"`
	Definition OnboardingTestDefinition `json:"definition"`
	Hash       string                   `json:"definition_hash"`
	CreatedAt  time.Time                `json:"created_at"`
	EventID    string                   `json:"created_event_id"`
}
type OnboardingTestPage struct {
	Tests []OnboardingTest `json:"tests"`
	Next  string           `json:"next,omitempty"`
}

func scanOnboardingTest(row pgx.Row) (*OnboardingTest, error) {
	var p OnboardingTest
	var d []byte
	err := row.Scan(&p.ID, &p.RunID, &p.Author, &d, &p.Hash, &p.CreatedAt, &p.EventID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if json.Unmarshal(d, &p.Definition) != nil {
		return nil, ErrIsolation
	}
	b, err := json.Marshal(p.Definition)
	if err != nil || secure.Digest(b) != p.Hash || p.ID != p.RunID || p.Definition.Schema != 1 || p.Definition.Profile != "single-sftp-test-v1" {
		return nil, ErrIsolation
	}
	p.CreatedAt = p.CreatedAt.UTC()
	return &p, nil
}

const onboardingTestColumns = `test_id::text,run_id::text,actor_id::text,definition,definition_hash,created_at,created_event_id::text`

func (t *Transaction) OnboardingTest(ctx context.Context, id string) (*OnboardingTest, error) {
	if !ValidID(id) {
		return nil, ErrNotFound
	}
	return scanOnboardingTest(t.Tx.QueryRow(ctx, `SELECT `+onboardingTestColumns+` FROM onboarding_tests WHERE tenant_id=$1 AND partner_id=$2 AND actor_id=$3 AND test_id=$4`, t.Scope.Tenant, t.Scope.Partner, t.Actor, id))
}
func (t *Transaction) SaveOnboardingTest(ctx context.Context, p *OnboardingTest) error {
	var err error
	p.EventID, err = t.Append(ctx, "OnboardingTestRecorded", p.ID, p)
	if err != nil {
		return err
	}
	d, err := json.Marshal(p.Definition)
	if err != nil {
		return err
	}
	_, err = t.Tx.Exec(ctx, `INSERT INTO onboarding_tests VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, t.Scope.Tenant, t.Scope.Partner, t.Actor, p.ID, p.RunID, p.Definition.Plan.ID, p.Definition.Plan.Version, d, p.Hash, p.CreatedAt, p.EventID)
	return err
}
func (t *Transaction) OnboardingTests(ctx context.Context, plan, after string, limit int) (*OnboardingTestPage, error) {
	if !ValidID(plan) || (after != "" && !ValidID(after)) || limit < 1 || limit > 100 {
		return nil, ErrOnboardingInput
	}
	rows, err := t.Tx.Query(ctx, `SELECT `+onboardingTestColumns+` FROM onboarding_tests WHERE tenant_id=$1 AND partner_id=$2 AND actor_id=$3 AND plan_id=$4 AND ($5='' OR test_id>nullif($5,'')::uuid) ORDER BY test_id LIMIT $6`, t.Scope.Tenant, t.Scope.Partner, t.Actor, plan, after, limit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	page := &OnboardingTestPage{Tests: []OnboardingTest{}}
	for rows.Next() {
		p, err := scanOnboardingTest(rows)
		if err != nil {
			return nil, err
		}
		page.Tests = append(page.Tests, *p)
	}
	if len(page.Tests) > limit {
		page.Next = page.Tests[limit-1].ID
		page.Tests = page.Tests[:limit]
	}
	return page, rows.Err()
}
func (t *Transaction) OnboardingRunCurrent(ctx context.Context, id string) (bool, error) {
	var current bool
	err := t.Tx.QueryRow(ctx, `SELECT freightctl_onboarding_run_current($1,$2,$3,$4,$5,$6)`, t.Scope.Tenant, t.Scope.Partner, t.Actor, id, t.AuthorityRevision, t.Root).Scan(&current)
	if err == nil && current {
		err = t.checkOnboardingProofAvailability(ctx, id)
		if err != nil {
			if errors.Is(err, ErrState) || errors.Is(err, ErrNotFound) || errors.Is(err, ErrForbidden) || errors.Is(err, ErrUnauthorized) {
				return false, nil
			}
			return false, err
		}
	}
	return current, err
}
