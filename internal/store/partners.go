package store

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"golang.org/x/text/unicode/norm"
)

var ErrPartnerInput = errors.New("invalid partner enrollment")
var ErrPartnerExists = errors.New("partner ID already exists")

type PartnerCommand struct {
	Partner           string   `json:"partner_id"`
	Admin             string   `json:"admin_id"`
	Label             string   `json:"label"`
	AdminLabel        string   `json:"admin_label"`
	Credential        string   `json:"credential_sha256"`
	Permissions       []string `json:"permissions"`
	ExpectedAuthority int64    `json:"expected_authority_revision"`
	ExpectedTenant    int64    `json:"expected_tenant_revision"`
}
type Partner struct {
	ID           string     `json:"id"`
	Label        string     `json:"label"`
	Admin        string     `json:"admin_id,omitempty"`
	AdminLabel   string     `json:"admin_label,omitempty"`
	Root         string     `json:"namespace_root"`
	Permissions  []string   `json:"permissions"`
	Event        string     `json:"event_id,omitempty"`
	RegisteredAt *time.Time `json:"registered_at"`
}
type PartnerResult struct {
	Partner  Partner `json:"partner"`
	Replayed bool    `json:"replayed"`
}
type PartnerPage struct {
	Partners       []Partner `json:"partners"`
	Next           string    `json:"next,omitempty"`
	Authority      int64     `json:"authority_revision"`
	TenantRevision int64     `json:"tenant_administration_revision"`
}

func normalizePartner(c PartnerCommand) (PartnerCommand, error) {
	if !ValidID(c.Partner) || !ValidID(c.Admin) || !browserSecretHash.MatchString(c.Credential) || c.ExpectedAuthority < 1 || c.ExpectedTenant < 1 {
		return c, ErrPartnerInput
	}
	for _, label := range []string{c.Label, c.AdminLabel} {
		if label == "" || !utf8.ValidString(label) || len(label) > 128 || strings.TrimSpace(label) != label || !norm.NFC.IsNormalString(label) || strings.IndexFunc(label, unicode.IsControl) >= 0 {
			return c, ErrPartnerInput
		}
	}
	a, err := normalizeAccount(AccountCommand{Operation: "create", ID: c.Admin, CredentialHash: c.Credential, Policy: &AccountPolicy{Label: c.AdminLabel, Root: "/", Permissions: c.Permissions}})
	if err != nil || !slices.Contains(c.Permissions, "admin") || !slices.Contains(c.Permissions, "accounts_manage") {
		return c, ErrPartnerInput
	}
	c.Permissions = a.Policy.Permissions
	return c, nil
}

func (s *Store) Partners(ctx context.Context, scope Scope, after string, limit int) (*PartnerPage, error) {
	if (after != "" && !ValidID(after)) || limit < 1 || limit > 100 {
		return nil, ErrPartnerInput
	}
	t, err := s.Begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	revision, err := t.tenantAdministrator(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := t.Tx.Query(ctx, `SELECT p.partner_id::text,r.result FROM partners p LEFT JOIN partner_registrations r ON r.tenant_id=p.tenant_id AND r.target_partner_id=p.partner_id WHERE ($1='' OR p.partner_id>nullif($1,'')::uuid) ORDER BY p.partner_id LIMIT $2`, after, limit+1)
	if err != nil {
		return nil, err
	}
	page := &PartnerPage{Partners: []Partner{}, Authority: t.AuthorityRevision, TenantRevision: revision}
	for rows.Next() {
		var id string
		var result []byte
		if err = rows.Scan(&id, &result); err != nil {
			break
		}
		p := Partner{ID: id, Root: "/", Permissions: []string{}}
		if result != nil && json.Unmarshal(result, &p) != nil {
			err = ErrIsolation
			break
		}
		page.Partners = append(page.Partners, p)
	}
	rows.Close()
	if err != nil {
		return nil, err
	}
	if rows.Err() != nil {
		return nil, rows.Err()
	}
	if len(page.Partners) > limit {
		page.Partners = page.Partners[:limit]
		page.Next = page.Partners[limit-1].ID
	}
	if _, err = t.tenantAdministrator(ctx); err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return page, t.Tx.Commit(ctx)
}

func (s *Store) RegisterPartner(ctx context.Context, scope Scope, key string, request PartnerCommand) (*PartnerResult, error) {
	c, err := normalizePartner(request)
	if err != nil || !ValidBrowserOperationKey(key) {
		return nil, ErrPartnerInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	// The tenant lock serializes authority changes before caller/session checks.
	tx, err := s.scopedTransaction(ctx, scope, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, scope.Tenant+":partner-directory"); err != nil {
		return nil, err
	}
	t := &Transaction{Tx: tx, Scope: scope}
	if err = t.authenticate(ctx); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, `SELECT set_config('freightctl.actor_id',$1,true)`, t.Actor); err != nil {
		return nil, err
	}
	tenantRevision, err := t.tenantAdministrator(ctx)
	if err != nil {
		return nil, err
	}
	for _, permission := range c.Permissions {
		if !t.Has(permission) {
			return nil, ErrForbidden
		}
	}
	data, _ := json.Marshal(c)
	meaning := secure.Digest(data)
	var previous string
	var result []byte
	err = tx.QueryRow(ctx, `SELECT request_hash,result FROM partner_registrations WHERE partner_id=$1 AND actor_id=$2 AND request_key=$3`, scope.Partner, t.Actor, key).Scan(&previous, &result)
	if err == nil {
		if previous != meaning {
			return nil, ErrConflict
		}
		r := &PartnerResult{Replayed: true}
		if json.Unmarshal(result, &r.Partner) != nil {
			return nil, ErrIsolation
		}
		if err = t.Reauthorize(ctx); err != nil {
			return nil, err
		}
		return r, tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	if c.ExpectedAuthority != t.AuthorityRevision || c.ExpectedTenant != tenantRevision {
		return nil, ErrRevision
	}
	now, err := t.DatabaseTime(ctx)
	if err != nil {
		return nil, err
	}
	now = now.UTC()
	p := Partner{ID: c.Partner, Admin: c.Admin, Label: c.Label, AdminLabel: c.AdminLabel, Root: "/", Permissions: c.Permissions, Event: secure.NewID(), RegisteredAt: &now}
	result, _ = json.Marshal(p)
	enrollmentEvent := secure.NewID()
	payload, _ := json.Marshal(map[string]any{"request_key": key, "request_hash": meaning, "definition": c, "partner": p, "enrollment_event_id": enrollmentEvent})
	if _, err = tx.Exec(ctx, `INSERT INTO events(tenant_id,partner_id,event_id,actor_id,kind,resource_id,payload,happened_at) VALUES($1,$2,$3,$4,'PartnerRegistered',$5,$6,$7)`, scope.Tenant, scope.Partner, p.Event, t.Actor, c.Partner, payload, now); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO partner_registrations(tenant_id,partner_id,actor_id,target_partner_id,admin_id,request_key,request_hash,definition,event_id,enrollment_event_id,result) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, scope.Tenant, scope.Partner, t.Actor, c.Partner, c.Admin, key, meaning, data, p.Event, enrollmentEvent, result); err != nil {
		var pe *pgconn.PgError
		if errors.As(err, &pe) && pe.Code == "23505" {
			return nil, ErrPartnerExists
		}
		if errors.As(err, &pe) && pe.Code == "42501" {
			return nil, ErrForbidden
		}
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return &PartnerResult{Partner: p}, tx.Commit(ctx)
}
