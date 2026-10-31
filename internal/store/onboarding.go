package store

import (
	"context"
	"encoding/json"
	"errors"
	"net/mail"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/jackc/pgx/v5"
	"golang.org/x/text/unicode/norm"
)

var ErrOnboardingInput = errors.New("invalid partner onboarding plan")

// Contact roles describe people, not application permissions. Contact details
// and requirements cannot select an endpoint, grant access or execute a task.
type OnboardingContact struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Role  string `json:"role"`
	Email string `json:"email"`
	Phone string `json:"phone"`
}
type OnboardingRequirement struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	ContactID       string `json:"contact_id"`
	Direction       string `json:"direction"`
	Protocol        string `json:"protocol"`
	Receipt         string `json:"required_receipt"`
	ReceiptContract string `json:"receipt_contract"`
	Notes           string `json:"notes"`
}
type OnboardingDefinition struct {
	Schema       int                     `json:"schema_version"`
	Name         string                  `json:"name"`
	Contacts     []OnboardingContact     `json:"contacts"`
	Requirements []OnboardingRequirement `json:"requirements"`
}
type OnboardingCommand struct {
	ID                string               `json:"plan_id"`
	ExpectedVersion   int                  `json:"expected_version"`
	ExpectedAuthority int64                `json:"expected_authority_revision"`
	Definition        OnboardingDefinition `json:"definition"`
}
type OnboardingSummary struct {
	ID        string    `json:"id"`
	Version   int       `json:"version"`
	Hash      string    `json:"definition_hash"`
	State     string    `json:"state"`
	Name      string    `json:"name"`
	Author    string    `json:"author_id"`
	Event     string    `json:"event_id"`
	CreatedAt time.Time `json:"created_at"`
}
type OnboardingPlan struct {
	OnboardingSummary
	Definition OnboardingDefinition `json:"definition"`
}
type OnboardingResult struct {
	Plan     OnboardingPlan `json:"plan"`
	Replayed bool           `json:"replayed"`
}
type OnboardingView struct {
	Plan      OnboardingPlan `json:"plan"`
	Authority int64          `json:"authority_revision"`
}
type OnboardingPage struct {
	Plans     []OnboardingSummary `json:"plans"`
	Next      string              `json:"next,omitempty"`
	Authority int64               `json:"authority_revision"`
}

func onboardingText(value string, maximum int, required, multiline bool) bool {
	if !utf8.ValidString(value) || len(value) > maximum || (!multiline && strings.TrimSpace(value) != value) || !norm.NFC.IsNormalString(value) || (required && value == "") {
		return false
	}
	return strings.IndexFunc(value, func(r rune) bool {
		return unicode.IsControl(r) && !(multiline && (r == '\n' || r == '\t' || r == '\r'))
	}) < 0
}
func normalizeOnboarding(c OnboardingCommand) (OnboardingCommand, error) {
	d := c.Definition
	d.Contacts = slices.Clone(d.Contacts)
	d.Requirements = slices.Clone(d.Requirements)
	if !ValidID(c.ID) || c.ExpectedVersion < 0 || c.ExpectedVersion >= 2147483647 || c.ExpectedAuthority < 1 || d.Schema != 1 || !onboardingText(d.Name, 128, true, false) || len(d.Contacts) < 1 || len(d.Contacts) > 64 || len(d.Requirements) < 1 || len(d.Requirements) > 64 {
		return c, ErrOnboardingInput
	}
	contacts := map[string]bool{}
	for _, contact := range d.Contacts {
		address, err := mail.ParseAddress(contact.Email)
		if !ValidID(contact.ID) || contacts[contact.ID] || !onboardingText(contact.Name, 128, true, false) || !onboardingText(contact.Role, 64, true, false) || !onboardingText(contact.Email, 254, true, false) || err != nil || address.Name != "" || address.Address != contact.Email || !onboardingText(contact.Phone, 64, false, false) {
			return c, ErrOnboardingInput
		}
		contacts[contact.ID] = true
	}
	requirements := map[string]bool{}
	for _, requirement := range d.Requirements {
		if !ValidID(requirement.ID) || requirements[requirement.ID] || !contacts[requirement.ContactID] || !onboardingText(requirement.Name, 128, true, false) || !slices.Contains([]string{"send", "receive"}, requirement.Direction) || !slices.Contains([]string{"sftp", "https", "ftps-explicit", "ftps-implicit", "webdav", "as1", "as2", "as3", "as4", "oftp2", "pesit", "smtp", "queue", "other"}, requirement.Protocol) || !slices.Contains([]string{"transport", "integrity", "business"}, requirement.Receipt) || !onboardingText(requirement.ReceiptContract, 512, false, true) || !onboardingText(requirement.Notes, 2048, false, true) {
			return c, ErrOnboardingInput
		}
		requirements[requirement.ID] = true
	}
	data, _ := json.Marshal(d)
	if len(data) > 24<<10 {
		return c, ErrOnboardingInput
	}
	c.Definition = d
	return c, nil
}

func (s *Store) SaveOnboarding(ctx context.Context, scope Scope, key string, command OnboardingCommand) (*OnboardingResult, error) {
	c, err := normalizeOnboarding(command)
	if err != nil || !ValidBrowserOperationKey(key) {
		return nil, ErrOnboardingInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	// Use the account management lock before authentication/session locks. A
	// concurrent credential change must not cross the frozen review or deadlock.
	t, err := s.beginAuthenticated(ctx, scope, pgx.TxOptions{}, true)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if err = t.requireAccountManager(); err != nil {
		return nil, err
	}
	data, _ := json.Marshal(c)
	meaning := secure.Digest(data)
	var prior string
	var result []byte
	err = t.Tx.QueryRow(ctx, `SELECT request_hash,result FROM onboarding_commands WHERE tenant_id=$1 AND partner_id=$2 AND actor_id=$3 AND request_key=$4`, scope.Tenant, scope.Partner, t.Actor, key).Scan(&prior, &result)
	if err == nil {
		if prior != meaning {
			return nil, ErrConflict
		}
		r := &OnboardingResult{Replayed: true}
		if json.Unmarshal(result, &r.Plan) != nil {
			return nil, ErrIsolation
		}
		if err = t.Reauthorize(ctx); err != nil {
			return nil, err
		}
		return r, t.Tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	if c.ExpectedAuthority != t.AuthorityRevision {
		return nil, ErrRevision
	}
	var version int
	if err = t.Tx.QueryRow(ctx, `SELECT coalesce(max(version),0) FROM onboarding_plans WHERE tenant_id=$1 AND partner_id=$2 AND plan_id=$3`, scope.Tenant, scope.Partner, c.ID).Scan(&version); err != nil {
		return nil, err
	}
	if version != c.ExpectedVersion {
		return nil, ErrRevision
	}
	now, err := t.DatabaseTime(ctx)
	if err != nil {
		return nil, err
	}
	definition, _ := json.Marshal(c.Definition)
	p := OnboardingPlan{OnboardingSummary: OnboardingSummary{ID: c.ID, Version: version + 1, Hash: secure.Digest(definition), State: "draft", Name: c.Definition.Name, Author: t.Actor, Event: secure.NewID(), CreatedAt: now.UTC()}, Definition: c.Definition}
	payload, _ := json.Marshal(p)
	if _, err = t.Tx.Exec(ctx, `INSERT INTO events(tenant_id,partner_id,event_id,actor_id,kind,resource_id,payload,happened_at) VALUES($1,$2,$3,$4,'OnboardingPlanRecorded',$5,$6,$7)`, scope.Tenant, scope.Partner, p.Event, t.Actor, p.ID, payload, p.CreatedAt); err != nil {
		return nil, err
	}
	if _, err = t.Tx.Exec(ctx, `INSERT INTO onboarding_plans(tenant_id,partner_id,plan_id,version,definition_hash,definition,actor_id,event_id,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, scope.Tenant, scope.Partner, p.ID, p.Version, p.Hash, definition, t.Actor, p.Event, p.CreatedAt); err != nil {
		return nil, err
	}
	event, err := t.Append(ctx, "OnboardingCommandCompleted", p.ID, map[string]any{"request_key": key, "request_hash": meaning, "result": p})
	if err != nil {
		return nil, err
	}
	if _, err = t.Tx.Exec(ctx, `INSERT INTO onboarding_commands(tenant_id,partner_id,actor_id,request_key,request_hash,plan_id,version,result,event_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, scope.Tenant, scope.Partner, t.Actor, key, meaning, p.ID, p.Version, payload, event); err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return &OnboardingResult{Plan: p}, t.Tx.Commit(ctx)
}

func (s *Store) Onboarding(ctx context.Context, scope Scope, id string, version int) (*OnboardingView, error) {
	if !ValidID(id) || version < 0 || version > 2147483647 {
		return nil, ErrOnboardingInput
	}
	t, err := s.Begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	p, err := t.OnboardingPlan(ctx, id, version)
	if err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return &OnboardingView{Plan: *p, Authority: t.AuthorityRevision}, t.Tx.Commit(ctx)
}

// BeginOnboardingManagement preserves the account/session lock order while
// composing a recorded onboarding decision with other scoped services.
func (s *Store) BeginOnboardingManagement(ctx context.Context, scope Scope) (*Transaction, error) {
	t, err := s.beginAuthenticated(ctx, scope, pgx.TxOptions{}, true)
	if err != nil {
		return nil, err
	}
	if err = t.requireAccountManager(); err != nil {
		t.Tx.Rollback(ctx)
		return nil, err
	}
	return t, nil
}

func (t *Transaction) OnboardingPlan(ctx context.Context, id string, version int) (*OnboardingPlan, error) {
	if !ValidID(id) || version < 0 || version > 2147483647 {
		return nil, ErrOnboardingInput
	}
	if err := t.requireAccountManager(); err != nil {
		return nil, err
	}
	var p OnboardingPlan
	var definition []byte
	err := t.Tx.QueryRow(ctx, `SELECT plan_id::text,version,definition_hash,definition,actor_id::text,event_id::text,created_at FROM onboarding_plans WHERE tenant_id=$1 AND partner_id=$2 AND plan_id=$3 AND ($4=0 OR version=$4) ORDER BY version DESC LIMIT 1`, t.Scope.Tenant, t.Scope.Partner, id, version).Scan(&p.ID, &p.Version, &p.Hash, &definition, &p.Author, &p.Event, &p.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}
	if json.Unmarshal(definition, &p.Definition) != nil {
		return nil, ErrIsolation
	}
	validated, err := normalizeOnboarding(OnboardingCommand{ID: p.ID, ExpectedVersion: p.Version - 1, ExpectedAuthority: t.AuthorityRevision, Definition: p.Definition})
	if err != nil {
		return nil, ErrIsolation
	}
	canonical, _ := json.Marshal(validated.Definition)
	if secure.Digest(canonical) != p.Hash {
		return nil, ErrIsolation
	}
	p.Name, p.State = p.Definition.Name, "draft"
	return &p, nil
}

func (s *Store) OnboardingPlans(ctx context.Context, scope Scope, after string, limit int) (*OnboardingPage, error) {
	if (after != "" && !ValidID(after)) || limit < 1 || limit > 100 {
		return nil, ErrOnboardingInput
	}
	t, err := s.Begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if err = t.requireAccountManager(); err != nil {
		return nil, err
	}
	rows, err := t.Tx.Query(ctx, `SELECT DISTINCT ON(plan_id) plan_id::text,version,definition_hash,definition->>'name',actor_id::text,event_id::text,created_at FROM onboarding_plans WHERE tenant_id=$1 AND partner_id=$2 AND ($3='' OR plan_id>nullif($3,'')::uuid) ORDER BY plan_id,version DESC LIMIT $4`, scope.Tenant, scope.Partner, after, limit+1)
	if err != nil {
		return nil, err
	}
	page := &OnboardingPage{Plans: []OnboardingSummary{}, Authority: t.AuthorityRevision}
	for rows.Next() {
		p := OnboardingSummary{State: "draft"}
		if err = rows.Scan(&p.ID, &p.Version, &p.Hash, &p.Name, &p.Author, &p.Event, &p.CreatedAt); err != nil {
			break
		}
		if !onboardingText(p.Name, 128, true, false) {
			err = ErrIsolation
			break
		}
		page.Plans = append(page.Plans, p)
	}
	rows.Close()
	if err != nil {
		return nil, err
	}
	if rows.Err() != nil {
		return nil, rows.Err()
	}
	if len(page.Plans) > limit {
		page.Plans = page.Plans[:limit]
		page.Next = page.Plans[limit-1].ID
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return page, t.Tx.Commit(ctx)
}

// Ordinary event feeds and signed audit exports show a digest, not contact
// details or free-form requirements. The protected journal retains the source.
func redactOnboardingEvent(e Event) Event {
	if e.Kind == "OutboundDispatchPolicyChanged" || e.Kind == "OutboundDispatchReviewChanged" || e.Kind == "OnboardingApprovalPolicyChanged" || e.Kind == "OnboardingApprovalReviewChanged" || e.Kind == "OnboardingTestRecorded" || e.Kind == "OnboardingReleaseChanged" || e.Kind == "OnboardingProductionQueued" || e.Kind == "OnboardingHandoffChanged" || e.Kind == "OnboardingObservationChanged" {
		e.Payload, _ = json.Marshal(map[string]any{"schema_version": 1, "redacted": true, "source_payload_sha256": secure.Digest(e.Payload), "reason": "actor_private_onboarding_test"})
		return e
	}
	if e.Kind == "WorkflowCommandCompleted" {
		var p struct {
			Result struct {
				Kind string `json:"kind"`
			} `json:"result"`
		}
		if json.Unmarshal(e.Payload, &p) == nil && (p.Result.Kind == "outbound_dispatch_review" || p.Result.Kind == "outbound_dispatch_policy" || p.Result.Kind == "onboarding_approval" || p.Result.Kind == "onboarding_approval_policy" || p.Result.Kind == "onboarding_test" || p.Result.Kind == "onboarding_release" || p.Result.Kind == "onboarding_production" || p.Result.Kind == "onboarding_handoff" || p.Result.Kind == "onboarding_observation") {
			e.Payload, _ = json.Marshal(map[string]any{"schema_version": 1, "redacted": true, "source_payload_sha256": secure.Digest(e.Payload), "reason": "actor_private_onboarding_test"})
			return e
		}
	}
	privateRecheck := e.Kind == "FileRecheckChanged"
	if e.Kind == "CheckCommandCompleted" {
		var payload struct {
			Result struct {
				Kind string `json:"kind"`
			} `json:"result"`
		}
		if json.Unmarshal(e.Payload, &payload) == nil && payload.Result.Kind == "file_recheck" {
			privateRecheck = true
		}
	}
	if privateRecheck {
		e.Payload, _ = json.Marshal(map[string]any{"schema_version": 1, "redacted": true, "source_payload_sha256": secure.Digest(e.Payload), "reason": "actor_private_file_recheck"})
		return e
	}
	if e.Kind == "OnboardingPlanRecorded" || e.Kind == "OnboardingCommandCompleted" {
		e.Payload, _ = json.Marshal(map[string]any{"schema_version": 1, "redacted": true, "source_payload_sha256": secure.Digest(e.Payload), "reason": "partner_contacts_and_requirements"})
	}
	return e
}
