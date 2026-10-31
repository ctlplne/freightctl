package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/jackc/pgx/v5"
)

// The old run and intent are frozen by revision. Their original immutable
// definitions stay intact; completion creates a separately identified successor.
type OnboardingHandoffSource struct {
	Dispatch    OnboardingDispatch            `json:"dispatch"`
	Plan        OnboardingReference           `json:"plan"`
	RunRevision int64                         `json:"run_revision"`
	Delivery    OnboardingActivationReference `json:"delivery"`
	State       string                        `json:"state"`
	Attempts    int                           `json:"attempts"`
	Fence       int64                         `json:"fence"`
}
type OnboardingHandoffDefinition struct {
	Schema          int                          `json:"schema_version"`
	Profile         string                       `json:"profile"`
	Source          OnboardingHandoffSource      `json:"source"`
	Target          OnboardingDispatchDefinition `json:"target"`
	TargetHash      string                       `json:"target_hash"`
	SourceRecheckID string                       `json:"source_recheck_id"`
}
type OnboardingHandoffSummary struct {
	ID          string                        `json:"id"`
	Author      string                        `json:"author_id"`
	SourceRunID string                        `json:"source_run_id"`
	Target      OnboardingActivationReference `json:"target_release"`
	Hash        string                        `json:"definition_hash"`
	State       string                        `json:"state"`
	Revision    int64                         `json:"revision"`
	NewRunID    string                        `json:"replacement_run_id"`
	CreatedAt   time.Time                     `json:"created_at"`
	EventID     string                        `json:"changed_event_id"`
}
type OnboardingHandoff struct {
	OnboardingHandoffSummary
	Definition OnboardingHandoffDefinition `json:"definition"`
}
type OnboardingHandoffPage struct {
	Handoffs []OnboardingHandoffSummary `json:"handoffs"`
	Next     string                     `json:"next,omitempty"`
}

const handoffColumns = `handoff_id::text,actor_id::text,source_run_id::text,definition->'target'->'release'->>'id',(definition->'target'->'release'->>'revision')::bigint,definition->'target'->'release'->>'hash',definition_hash,state,revision,coalesce(replacement_run_id::text,''),created_at,changed_event_id::text`

func (t *Transaction) OnboardingHandoff(ctx context.Context, id string, lock bool) (*OnboardingHandoff, error) {
	if !ValidID(id) {
		return nil, ErrNotFound
	}
	q := `SELECT ` + handoffColumns + `,definition FROM onboarding_handoffs WHERE tenant_id=$1 AND partner_id=$2 AND actor_id=$3 AND handoff_id=$4`
	if lock {
		q += ` FOR UPDATE`
	}
	var h OnboardingHandoff
	var data []byte
	err := t.Tx.QueryRow(ctx, q, t.Scope.Tenant, t.Scope.Partner, t.Actor, id).Scan(&h.ID, &h.Author, &h.SourceRunID, &h.Target.ID, &h.Target.Revision, &h.Target.Hash, &h.Hash, &h.State, &h.Revision, &h.NewRunID, &h.CreatedAt, &h.EventID, &data)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if json.Unmarshal(data, &h.Definition) != nil {
		return nil, ErrIsolation
	}
	encoded, err := json.Marshal(h.Definition)
	if err != nil || secure.Digest(encoded) != h.Hash || h.SourceRunID != h.Definition.Source.Dispatch.ID || h.Target != h.Definition.Target.Release || h.Definition.Schema != 1 || h.Definition.Profile != "untouched-production-handoff-v1" {
		return nil, ErrIsolation
	}
	h.CreatedAt = h.CreatedAt.UTC()
	return &h, nil
}
func (t *Transaction) SaveOnboardingHandoff(ctx context.Context, h *OnboardingHandoff, previous int64) error {
	event, err := t.Append(ctx, "OnboardingHandoffChanged", h.ID, h)
	if err != nil {
		return err
	}
	h.EventID = event
	if previous == 0 {
		data, err := json.Marshal(h.Definition)
		if err != nil {
			return err
		}
		_, err = t.Tx.Exec(ctx, `INSERT INTO onboarding_handoffs VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,nullif($13,'')::uuid,$14,$15)`, t.Scope.Tenant, t.Scope.Partner, t.Actor, h.ID, h.SourceRunID, h.Definition.Source.Delivery.ID, h.Definition.Source.Plan.ID, h.Definition.Source.Plan.Version, data, h.Hash, h.State, h.Revision, h.NewRunID, h.CreatedAt, event)
		return err
	}
	tag, err := t.Tx.Exec(ctx, `UPDATE onboarding_handoffs SET state=$1,revision=$2,replacement_run_id=nullif($3,'')::uuid,changed_event_id=$4 WHERE tenant_id=$5 AND partner_id=$6 AND actor_id=$7 AND handoff_id=$8 AND revision=$9`, h.State, h.Revision, h.NewRunID, event, t.Scope.Tenant, t.Scope.Partner, t.Actor, h.ID, previous)
	if err == nil && tag.RowsAffected() != 1 {
		return ErrRevision
	}
	return err
}
func (t *Transaction) OnboardingHandoffs(ctx context.Context, plan, after string, limit int) (*OnboardingHandoffPage, error) {
	if !ValidID(plan) || (after != "" && !ValidID(after)) || limit < 1 || limit > 100 {
		return nil, ErrOnboardingInput
	}
	rows, err := t.Tx.Query(ctx, `SELECT `+handoffColumns+` FROM onboarding_handoffs WHERE tenant_id=$1 AND partner_id=$2 AND actor_id=$3 AND plan_id=$4 AND ($5='' OR handoff_id>nullif($5,'')::uuid) ORDER BY handoff_id LIMIT $6`, t.Scope.Tenant, t.Scope.Partner, t.Actor, plan, after, limit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	page := &OnboardingHandoffPage{Handoffs: []OnboardingHandoffSummary{}}
	for rows.Next() {
		var h OnboardingHandoffSummary
		if err = rows.Scan(&h.ID, &h.Author, &h.SourceRunID, &h.Target.ID, &h.Target.Revision, &h.Target.Hash, &h.Hash, &h.State, &h.Revision, &h.NewRunID, &h.CreatedAt, &h.EventID); err != nil {
			return nil, err
		}
		h.CreatedAt = h.CreatedAt.UTC()
		page.Handoffs = append(page.Handoffs, h)
	}
	if len(page.Handoffs) > limit {
		page.Next = page.Handoffs[limit-1].ID
		page.Handoffs = page.Handoffs[:limit]
	}
	return page, rows.Err()
}
func (t *Transaction) HandoffSourceRecheck(ctx context.Context, old, new string) (string, error) {
	if old == new {
		return "", nil
	}
	var id string
	err := t.Tx.QueryRow(ctx, `SELECT recheck_id::text FROM file_rechecks WHERE tenant_id=$1 AND partner_id=$2 AND actor_id=$3 AND source_file_id=$4 AND new_file_id=$5 AND state='copied'`, t.Scope.Tenant, t.Scope.Partner, t.Actor, old, new).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrRevision
	}
	return id, err
}
