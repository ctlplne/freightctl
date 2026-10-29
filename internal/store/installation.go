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
	"golang.org/x/text/unicode/norm"
)

var ErrSetupInput = errors.New("invalid first-run plan")
var ErrInitialized = errors.New("installation already contains identities; use ordinary account management")

// SetupRequest is a frozen local administrator decision, not an HTTP command.
// The serving role cannot create tenants, partners or installation receipts.
type SetupRequest struct {
	SchemaVersion int      `json:"schema_version"`
	RequestKey    string   `json:"request_key"`
	Tenant        string   `json:"tenant_id"`
	Partner       string   `json:"partner_id"`
	Admin         string   `json:"admin_id"`
	TenantLabel   string   `json:"tenant_label"`
	PartnerLabel  string   `json:"partner_label"`
	AdminLabel    string   `json:"admin_label"`
	Credential    string   `json:"credential_sha256"`
	Storage       string   `json:"storage_id"`
	Permissions   []string `json:"permissions"`
}
type SetupResult struct {
	SchemaVersion int       `json:"schema_version"`
	Tenant        string    `json:"tenant_id"`
	Partner       string    `json:"partner_id"`
	Actor         string    `json:"actor_id"`
	TenantLabel   string    `json:"tenant_label"`
	PartnerLabel  string    `json:"partner_label"`
	AdminLabel    string    `json:"admin_label"`
	Storage       string    `json:"storage_id"`
	Event         string    `json:"event_id"`
	InitializedAt time.Time `json:"initialized_at"`
	Replayed      bool      `json:"replayed"`
}

func NormalizeSetup(c SetupRequest) (SetupRequest, error) {
	if c.SchemaVersion != 1 || !ValidID(c.RequestKey) || !ValidID(c.Tenant) || !ValidID(c.Partner) || !ValidID(c.Admin) || !ValidID(c.Storage) || !browserSecretHash.MatchString(c.Credential) {
		return c, ErrSetupInput
	}
	for _, label := range []string{c.TenantLabel, c.PartnerLabel, c.AdminLabel} {
		if label == "" || !utf8.ValidString(label) || len(label) > 128 || strings.TrimSpace(label) != label || !norm.NFC.IsNormalString(label) || strings.IndexFunc(label, unicode.IsControl) >= 0 {
			return c, ErrSetupInput
		}
	}
	c.Permissions = slices.Clone(c.Permissions)
	slices.Sort(c.Permissions)
	allowed := slices.Clone(DefaultPermissions)
	slices.Sort(allowed)
	if !slices.Equal(c.Permissions, allowed) {
		return c, ErrSetupInput
	}
	return c, nil
}

// InitializeInstallation uses the separately supplied deployment-admin reference.
// Table locks serialize it with legacy enrollment too; an advisory lock alone
// would not stop concurrent INSERTs from a different bootstrap command.
func InitializeInstallation(ctx context.Context, adminPath string, request SetupRequest) (*SetupResult, error) {
	c, err := NormalizeSetup(request)
	if err != nil {
		return nil, err
	}
	data, _ := json.Marshal(c)
	meaning := secure.Digest(data)
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
	var deploymentAdmin bool
	if err = tx.QueryRow(ctx, `SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname=current_user`).Scan(&deploymentAdmin); err != nil || !deploymentAdmin {
		return nil, ErrForbidden
	}
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(721815033)`); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, `LOCK TABLE tenants,partners,credentials,installation_enrollments IN EXCLUSIVE MODE`); err != nil {
		return nil, ErrForbidden
	}
	rows, err := tx.Query(ctx, `SELECT version,digest FROM freightctl_schema ORDER BY version`)
	if err != nil {
		return nil, ErrIsolation
	}
	matched := 0
	for rows.Next() {
		var version int
		var digest string
		if err = rows.Scan(&version, &digest); err != nil {
			break
		}
		if version != matched+1 || version > len(migrations) || digest != secure.Digest([]byte(migrations[version-1])) {
			err = ErrIsolation
			break
		}
		matched++
	}
	rows.Close()
	if err != nil || rows.Err() != nil || matched != len(migrations) {
		return nil, ErrIsolation
	}
	var protected int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM pg_class WHERE relnamespace='public'::regnamespace AND relname=ANY($1) AND relrowsecurity AND relforcerowsecurity`, domainTables).Scan(&protected); err != nil || protected != len(domainTables) {
		return nil, ErrIsolation
	}
	var prior string
	var result []byte
	err = tx.QueryRow(ctx, `SELECT request_hash,result FROM installation_enrollments WHERE singleton`).Scan(&prior, &result)
	if err == nil {
		if prior != meaning {
			return nil, ErrInitialized
		}
		r := &SetupResult{}
		if json.Unmarshal(result, r) != nil {
			return nil, ErrIsolation
		}
		r.Replayed = true
		return r, tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	var populated bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM tenants) OR EXISTS(SELECT 1 FROM partners) OR EXISTS(SELECT 1 FROM credentials)`).Scan(&populated); err != nil {
		return nil, err
	}
	if populated {
		return nil, ErrInitialized
	}
	if _, err = tx.Exec(ctx, `SELECT set_config('freightctl.tenant_id',$1,true),set_config('freightctl.partner_id',$2,true),set_config('freightctl.actor_id',$3,true)`, c.Tenant, c.Partner, c.Admin); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO tenants(tenant_id) VALUES($1)`, c.Tenant); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO partners(tenant_id,partner_id) VALUES($1,$2)`, c.Tenant, c.Partner); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO credentials(tenant_id,partner_id,actor_id,token_hash,permissions,namespace_root,account_label) VALUES($1,$2,$3,$4,$5,'/',$6)`, c.Tenant, c.Partner, c.Admin, c.Credential, c.Permissions, c.AdminLabel); err != nil {
		return nil, err
	}
	r := &SetupResult{SchemaVersion: 1, Tenant: c.Tenant, Partner: c.Partner, Actor: c.Admin, TenantLabel: c.TenantLabel, PartnerLabel: c.PartnerLabel, AdminLabel: c.AdminLabel, Storage: c.Storage, Event: secure.NewID()}
	if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&r.InitializedAt); err != nil {
		return nil, err
	}
	r.InitializedAt = r.InitializedAt.UTC()
	result, _ = json.Marshal(r)
	payload, _ := json.Marshal(map[string]any{"request": c, "request_hash": meaning, "result": r})
	if _, err = tx.Exec(ctx, `INSERT INTO events(tenant_id,partner_id,event_id,actor_id,kind,resource_id,payload) VALUES($1,$2,$3,$4,'InstallationInitialized',$5,$6)`, c.Tenant, c.Partner, r.Event, c.Admin, c.RequestKey, payload); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO installation_enrollments(tenant_id,partner_id,actor_id,request_key,request_hash,definition,result,event_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, c.Tenant, c.Partner, c.Admin, c.RequestKey, meaning, data, result, r.Event); err != nil {
		return nil, err
	}
	return r, tx.Commit(ctx)
}
