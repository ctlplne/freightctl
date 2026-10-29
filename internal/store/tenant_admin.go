package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/jackc/pgx/v5"
)

type TenantAdminCommand struct {
	Operation         string `json:"operation"`
	Actor             string `json:"actor_id"`
	ExpectedRevision  int64  `json:"expected_revision"`
	ExpectedAuthority int64  `json:"expected_authority_revision"`
}
type TenantAdministrator struct {
	Tenant    string `json:"tenant_id"`
	Partner   string `json:"partner_id"`
	Actor     string `json:"actor_id"`
	Authority int64  `json:"authority_revision"`
	Revision  int64  `json:"revision"`
	State     string `json:"state"`
	Event     string `json:"event_id"`
}
type TenantAdminResult struct {
	Membership TenantAdministrator `json:"membership"`
	Replayed   bool                `json:"replayed"`
}

func (t *Transaction) tenantAdministrator(ctx context.Context) (int64, error) {
	if t.Root != "/" || !t.Has("admin") || !t.Has("accounts_manage") {
		return 0, ErrForbidden
	}
	query := `SELECT revision FROM tenant_administrators WHERE actor_id=$1 AND state='active' AND authority_revision=$2`
	var revision int64
	if err := t.Tx.QueryRow(ctx, query, t.Actor, t.AuthorityRevision).Scan(&revision); errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrForbidden
	} else {
		return revision, err
	}
}

// Only explicit deployment maintenance or an opted-in first-run plan grants
// tenant directory authority. Ordinary account creation never copies it.
func changeTenantAdministrator(ctx context.Context, tx pgx.Tx, tenant, partner, key string, c TenantAdminCommand) (*TenantAdminResult, error) {
	if !ValidID(tenant) || !ValidID(partner) || !ValidID(c.Actor) || !ValidBrowserOperationKey(key) || c.ExpectedRevision < 0 || c.ExpectedAuthority < 1 || (c.Operation != "grant" && c.Operation != "revoke") || (c.Operation == "revoke" && c.ExpectedRevision < 1) {
		return nil, ErrPartnerInput
	}
	data, _ := json.Marshal(c)
	meaning := secure.Digest(data)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, tenant+":partner-directory"); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('freightctl.tenant_id',$1,true),set_config('freightctl.partner_id',$2,true),set_config('freightctl.actor_id',$3,true)`, tenant, partner, c.Actor); err != nil {
		return nil, err
	}
	var previous string
	var result []byte
	err := tx.QueryRow(ctx, `SELECT request_hash,result FROM tenant_admin_commands WHERE tenant_id=$1 AND partner_id=$2 AND request_key=$3`, tenant, partner, key).Scan(&previous, &result)
	if err == nil {
		if previous != meaning {
			return nil, ErrConflict
		}
		r := &TenantAdminResult{Replayed: true}
		if json.Unmarshal(result, &r.Membership) != nil {
			return nil, ErrIsolation
		}
		return r, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	var revision, authority int64
	err = tx.QueryRow(ctx, `SELECT revision,authority_revision FROM tenant_administrators WHERE tenant_id=$1 AND partner_id=$2 AND actor_id=$3 FOR UPDATE`, tenant, partner, c.Actor).Scan(&revision, &authority)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	if revision != c.ExpectedRevision || (c.Operation == "revoke" && authority != c.ExpectedAuthority) {
		return nil, ErrRevision
	}
	if c.Operation == "grant" {
		var current bool
		if err = tx.QueryRow(ctx, `SELECT namespace_root='/' AND permissions @> ARRAY['admin','accounts_manage']::text[] AND authority_revision=$4 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>clock_timestamp()) FROM credentials WHERE tenant_id=$1 AND partner_id=$2 AND actor_id=$3 FOR SHARE`, tenant, partner, c.Actor, c.ExpectedAuthority).Scan(&current); errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		} else if err != nil {
			return nil, err
		} else if !current {
			return nil, ErrRevision
		}
	}
	m := TenantAdministrator{Tenant: tenant, Partner: partner, Actor: c.Actor, Authority: c.ExpectedAuthority, Revision: revision + 1, State: "active", Event: secure.NewID()}
	if c.Operation == "revoke" {
		m.State = "revoked"
	}
	result, _ = json.Marshal(m)
	var maintenanceRole string
	if err = tx.QueryRow(ctx, `SELECT current_user`).Scan(&maintenanceRole); err != nil {
		return nil, err
	}
	payload, _ := json.Marshal(map[string]any{"request_key": key, "request_hash": meaning, "request": c, "membership": m, "maintenance_role": maintenanceRole})
	if _, err = tx.Exec(ctx, `INSERT INTO events(tenant_id,partner_id,event_id,actor_id,kind,resource_id,payload) VALUES($1,$2,$3,$4,'TenantAdministratorChanged',$4,$5)`, tenant, partner, m.Event, c.Actor, payload); err != nil {
		return nil, err
	}
	query := `INSERT INTO tenant_administrators(tenant_id,partner_id,actor_id,authority_revision,revision,state,event_id) VALUES($1,$2,$3,$4,$5,$6,$7)`
	if revision != 0 {
		query = `UPDATE tenant_administrators SET authority_revision=$4,revision=$5,state=$6,event_id=$7 WHERE tenant_id=$1 AND partner_id=$2 AND actor_id=$3`
	}
	if _, err = tx.Exec(ctx, query, tenant, partner, m.Actor, m.Authority, m.Revision, m.State, m.Event); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO tenant_admin_commands(tenant_id,partner_id,actor_id,request_key,request_hash,event_id,definition,result) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, tenant, partner, c.Actor, key, meaning, m.Event, data, result); err != nil {
		return nil, err
	}
	return &TenantAdminResult{Membership: m}, nil
}

func AdministerTenant(ctx context.Context, adminPath, tenant, partner, key string, c TenantAdminCommand) (*TenantAdminResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	p, err := connect(ctx, adminPath)
	if err != nil {
		return nil, err
	}
	defer p.Close()
	tx, err := p.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var allowed bool
	if err = tx.QueryRow(ctx, `SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname=current_user`).Scan(&allowed); err != nil || !allowed {
		return nil, ErrForbidden
	}
	// Serialize with schema maintenance before taking authority/credential locks.
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(721815033)`); err != nil {
		return nil, err
	}
	r, err := changeTenantAdministrator(ctx, tx, tenant, partner, key, c)
	if err != nil {
		return nil, err
	}
	return r, tx.Commit(ctx)
}

func TenantAdminStatus(ctx context.Context, adminPath, tenant, partner, actor string) (*TenantAdministrator, error) {
	if !ValidID(tenant) || !ValidID(partner) || !ValidID(actor) {
		return nil, ErrPartnerInput
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	p, err := connect(ctx, adminPath)
	if err != nil {
		return nil, err
	}
	defer p.Close()
	var allowed bool
	if err = p.QueryRow(ctx, `SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname=current_user`).Scan(&allowed); err != nil || !allowed {
		return nil, ErrForbidden
	}
	m := &TenantAdministrator{Tenant: tenant, Partner: partner, Actor: actor}
	err = p.QueryRow(ctx, `SELECT authority_revision,revision,state,event_id::text FROM tenant_administrators WHERE tenant_id=$1 AND partner_id=$2 AND actor_id=$3`, tenant, partner, actor).Scan(&m.Authority, &m.Revision, &m.State, &m.Event)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return m, err
}
