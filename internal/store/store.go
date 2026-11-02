package store

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/vpath"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed schema.sql
var schema string

//go:embed 002_event_binding.sql
var eventBinding string

//go:embed 003_event_bounds.sql
var eventBounds string

//go:embed 004_namespace.sql
var namespaceSchema string

//go:embed 005_uploads.sql
var uploadSchema string

//go:embed 006_upload_storage.sql
var uploadStorageSchema string

//go:embed 007_deliveries.sql
var deliverySchema string

//go:embed 008_workflows.sql
var workflowSchema string

//go:embed 009_assistance.sql
var assistanceSchema string

//go:embed 010_intake.sql
var intakeSchema string

//go:embed 011_pgp.sql
var pgpSchema string

//go:embed 012_encryption.sql
var encryptionSchema string

//go:embed 013_scanners.sql
var scannerSchema string

//go:embed 014_browser_sessions.sql
var browserSessionSchema string

//go:embed 015_browser_commands.sql
var browserCommandSchema string

//go:embed 016_accounts.sql
var accountSchema string

//go:embed 017_installation.sql
var installationSchema string

//go:embed 018_partners.sql
var partnerSchema string

//go:embed 019_onboarding.sql
var onboardingSchema string

//go:embed 020_onboarding_probes.sql
var onboardingProbesSchema string

//go:embed 021_file_rechecks.sql
var rechecksSchema string

//go:embed 022_onboarding_tests.sql
var onboardingTestsSchema string

//go:embed 023_onboarding_releases.sql
var onboardingReleasesSchema string

//go:embed 024_onboarding_handoffs.sql
var onboardingHandoffsSchema string

//go:embed 025_prepublication_handoffs.sql
var prepublicationHandoffsSchema string

//go:embed 026_onboarding_observations.sql
var onboardingObservationsSchema string

//go:embed 027_onboarding_approvals.sql
var onboardingApprovalsSchema string

//go:embed 028_outbound_dispatch_approvals.sql
var outboundDispatchApprovalsSchema string

//go:embed 029_workflow_schedules.sql
var workflowSchedulesSchema string

//go:embed 030_workflow_collections.sql
var workflowCollectionsSchema string

//go:embed 031_scheduled_collections.sql
var scheduledCollectionsSchema string

//go:embed 032_bounded_workflow_programs.sql
var boundedWorkflowProgramsSchema string

//go:embed 033_collection_routing.sql
var collectionRoutingSchema string

//go:embed 034_collection_handoffs.sql
var collectionHandoffsSchema string

//go:embed 035_collection_successors.sql
var collectionSuccessorsSchema string

var migrations = []string{schema, eventBinding, eventBounds, namespaceSchema, uploadSchema, uploadStorageSchema, deliverySchema, workflowSchema, assistanceSchema, intakeSchema, pgpSchema, encryptionSchema, scannerSchema, browserSessionSchema, browserCommandSchema, accountSchema, installationSchema, partnerSchema, onboardingSchema, onboardingProbesSchema, rechecksSchema, onboardingTestsSchema, onboardingReleasesSchema, onboardingHandoffsSchema, prepublicationHandoffsSchema, onboardingObservationsSchema, onboardingApprovalsSchema, outboundDispatchApprovalsSchema, workflowSchedulesSchema, workflowCollectionsSchema, scheduledCollectionsSchema, boundedWorkflowProgramsSchema, collectionRoutingSchema, collectionHandoffsSchema, collectionSuccessorsSchema}
var domainTables = []string{"tenants", "partners", "credentials", "events", "files", "idempotency", "namespace_entries", "namespace_revisions", "namespace_commands", "ssh_keys", "upload_sessions", "upload_chunks", "upload_receipts", "delivery_intents", "delivery_receipts", "connection_revisions", "workflow_revisions", "workflow_runs", "workflow_steps", "workflow_receipts", "ai_profiles", "ai_jobs", "ai_receipts", "intake_policies", "file_checks", "check_receipts", "file_releases", "pgp_keys", "file_signatures", "delivery_ciphertexts", "scanner_profiles", "browser_sessions", "browser_commands", "account_revisions", "account_commands", "installation_enrollments", "tenant_administrators", "tenant_admin_commands", "partner_registrations", "onboarding_plans", "onboarding_commands", "onboarding_probes", "file_rechecks", "file_recheck_slots", "onboarding_tests", "onboarding_releases", "onboarding_dispatches", "onboarding_handoffs", "onboarding_observations", "onboarding_approval_policies", "onboarding_approval_reviews", "outbound_dispatch_policies", "outbound_dispatch_reviews", "workflow_schedules", "workflow_schedule_occurrences", "workflow_schedule_inputs", "workflow_collection_jobs", "workflow_collection_batches", "workflow_collection_inputs", "workflow_collection_file_gates", "workflow_schedule_arrivals", "workflow_collection_routing", "workflow_collection_handoffs"}

// SchemaVersion lets maintenance compare a binary's target before connecting
// to the database; init applies every migration bundled with that binary.
func SchemaVersion() int { return len(migrations) }

var ErrUnauthorized = errors.New("unauthorized")
var ErrNotFound = errors.New("not found")
var ErrConflict = errors.New("idempotency key has different meaning")
var ErrLimit = errors.New("operation exceeds configured evidence bounds")
var ErrIsolation = errors.New("required database isolation is not active")
var ErrForbidden = errors.New("permission denied")
var ErrExists = errors.New("virtual path already exists")
var ErrState = errors.New("operation does not match the current resource state")
var ErrRevision = errors.New("resource revision changed")

var DefaultPermissions = []string{"read", "write", "list", "manage_paths", "inspect", "audit_read", "admin", "connections_manage", "deliver", "workflow_manage", "workflow_approve", "workflow_execute", "ai_manage", "ai_use", "ai_disclose", "intake_manage", "check_run", "check_release", "pgp_manage", "scanner_manage", "accounts_manage"}

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func ValidID(id string) bool { return uuidPattern.MatchString(id) }

// Scope carries selectors, not authority. Only trusted transport middleware may
// supply an SSH proof after the protocol library verifies its signature.
type Scope struct {
	Tenant, Partner, TokenHash           string
	Actor, SSHKeyFingerprint             string
	AuthorityRevision                    int64
	SessionID                            string
	BrowserSessionID, BrowserSessionHash string
}
type Store struct{ Pool *pgxpool.Pool }
type File struct {
	ID      string `json:"id"`
	Size    int64  `json:"size_bytes"`
	SHA256  string `json:"sha256"`
	Policy  string `json:"policy"`
	EventID string `json:"accepted_event_id"`
}
type Event struct {
	ID         string          `json:"id"`
	ActorID    string          `json:"actor_id"`
	Kind       string          `json:"kind"`
	ResourceID string          `json:"resource_id"`
	Payload    json.RawMessage `json:"payload"`
	At         time.Time       `json:"happened_at"`
}
type Transaction struct {
	Tx                pgx.Tx
	Scope             Scope
	Actor             string
	Permissions       []string
	Root              string
	AuthorityRevision int64
	ExpiresAt         *time.Time
	PendingFiles      map[string]bool
}

// Connection strings are read from bounded protected references. pgx requires a string copy.
func connect(ctx context.Context, path string) (*pgxpool.Pool, error) {
	secret, err := secure.ReadSecret(path, 4096)
	if err != nil {
		return nil, err
	}
	defer secret.Close()
	cfg, err := pgxpool.ParseConfig(string(secret.Bytes))
	if err != nil {
		return nil, errors.New("invalid database reference")
	}
	cfg.MaxConns = 8
	cfg.MinConns = 0
	cfg.ConnConfig.ConnectTimeout = 5 * time.Second
	cfg.ConnConfig.RuntimeParams["application_name"] = "freightctl"
	cfg.ConnConfig.RuntimeParams["row_security"] = "on"
	cfg.ConnConfig.RuntimeParams["search_path"] = "public"
	cfg.ConnConfig.RuntimeParams["statement_timeout"] = "10000"
	cfg.ConnConfig.RuntimeParams["idle_in_transaction_session_timeout"] = "120000"
	p, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, errors.New("database unavailable")
	}
	if err = p.Ping(ctx); err != nil {
		p.Close()
		return nil, errors.New("database unavailable")
	}
	return p, nil
}
func Open(ctx context.Context, path string) (*Store, error) {
	p, err := connect(ctx, path)
	if err != nil {
		return nil, err
	}
	var unsafe bool
	err = p.QueryRow(ctx, `SELECT r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR EXISTS (SELECT 1 FROM pg_auth_members WHERE member=r.oid) OR EXISTS (SELECT 1 FROM pg_class WHERE relnamespace='public'::regnamespace AND relowner=r.oid) FROM pg_roles r WHERE rolname=current_user`).Scan(&unsafe)
	if err != nil || unsafe {
		p.Close()
		return nil, errors.New("runtime database role must be non-owner without elevated privileges or memberships")
	}
	var protected int
	err = p.QueryRow(ctx, `SELECT count(*) FROM pg_class WHERE relnamespace='public'::regnamespace AND relname=ANY($1) AND relrowsecurity AND relforcerowsecurity`, domainTables).Scan(&protected)
	if err != nil || protected != len(domainTables) {
		p.Close()
		return nil, errors.New("runtime requires forced row security on every domain table")
	}
	rows, err := p.Query(ctx, `SELECT version,digest FROM freightctl_schema ORDER BY version`)
	if err != nil {
		p.Close()
		return nil, errors.New("database schema not initialized")
	}
	matched := 0
	for rows.Next() {
		var version int
		var digest string
		if err = rows.Scan(&version, &digest); err != nil {
			break
		}
		if version != matched+1 || version > len(migrations) || digest != secure.Digest([]byte(migrations[version-1])) {
			err = errors.New("database migration identity differs")
			break
		}
		matched++
	}
	rows.Close()
	if err != nil || rows.Err() != nil || matched != len(migrations) {
		p.Close()
		return nil, errors.New("database schema version or digest differs; run the matching administrative migrations")
	}
	var writerSafe bool
	if err = p.QueryRow(ctx, `SELECT freightctl_account_writer_safe() AND freightctl_partner_writer_safe()`).Scan(&writerSafe); err != nil || !writerSafe {
		p.Close()
		return nil, ErrIsolation
	}
	return &Store{Pool: p}, nil
}

// Migrate is an explicit administrative operation, never run with runtime credentials.
func Migrate(ctx context.Context, adminPath, passwordPath string) error {
	p, err := connect(ctx, adminPath)
	if err != nil {
		return err
	}
	defer p.Close()
	password, err := secure.ReadSecret(passwordPath, 256)
	if err != nil {
		return err
	}
	defer password.Close()
	if len(password.Bytes) < 32 {
		return errors.New("runtime password must contain at least 32 bytes")
	}
	tx, err := p.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(721815033)`); err != nil {
		return err
	}
	var exists bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='freightctl_runtime')`).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		// PostgreSQL utility statements cannot bind a password parameter; quote as SQL literal.
		_, err = tx.Exec(ctx, `CREATE ROLE freightctl_runtime LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '`+strings.ReplaceAll(string(password.Bytes), "'", "''")+`'`)
		if err != nil {
			return errors.New("cannot create runtime role")
		}
	}
	if _, err = tx.Exec(ctx, `REVOKE CREATE ON SCHEMA public FROM PUBLIC; CREATE TABLE IF NOT EXISTS freightctl_schema(version integer PRIMARY KEY, digest text NOT NULL); GRANT SELECT ON freightctl_schema TO freightctl_runtime`); err != nil {
		return err
	}
	var latest int
	if err = tx.QueryRow(ctx, `SELECT coalesce(max(version),0) FROM freightctl_schema`).Scan(&latest); err != nil {
		return err
	}
	if latest > len(migrations) {
		return errors.New("database uses a newer schema; use a matching binary")
	}
	for index, migration := range migrations {
		var digest string
		err = tx.QueryRow(ctx, `SELECT digest FROM freightctl_schema WHERE version=$1`, index+1).Scan(&digest)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			if _, err = tx.Exec(ctx, migration); err != nil {
				return err
			}
			if _, err = tx.Exec(ctx, `INSERT INTO freightctl_schema VALUES($1,$2)`, index+1, secure.Digest([]byte(migration))); err != nil {
				return err
			}
		case err != nil:
			return err
		case digest != secure.Digest([]byte(migration)):
			return errors.New("existing migration digest differs; do not rewrite applied migrations")
		}
	}
	return tx.Commit(ctx)
}

func Provision(ctx context.Context, adminPath, tenant, partner, tokenPath string) error {
	return ProvisionPolicy(ctx, adminPath, tenant, partner, tokenPath, DefaultPermissions, "/")
}

func ProvisionPolicy(ctx context.Context, adminPath, tenant, partner, tokenPath string, permissions []string, root string) error {
	if !ValidID(tenant) || !ValidID(partner) {
		return errors.New("invalid tenant or partner UUID")
	}
	canonical, err := vpath.Canonical(root)
	if err != nil || canonical != root || vpath.ControlPath(root) {
		return vpath.ErrPath
	}
	seen := make(map[string]bool)
	for _, permission := range permissions {
		valid := false
		for _, allowed := range DefaultPermissions {
			if permission == allowed {
				valid = true
			}
		}
		if !valid || seen[permission] {
			return ErrForbidden
		}
		seen[permission] = true
	}
	secret, err := secure.ReadSecret(tokenPath, 64)
	if err != nil {
		return err
	}
	defer secret.Close()
	if len(secret.Bytes) != 64 {
		return errors.New("token must be 64 bytes")
	}
	p, err := connect(ctx, adminPath)
	if err != nil {
		return err
	}
	defer p.Close()
	tx, err := p.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `SELECT set_config('freightctl.tenant_id',$1,true),set_config('freightctl.partner_id',$2,true)`, tenant, partner)
	if err != nil {
		return err
	}
	actor := secure.NewID()
	if _, err = tx.Exec(ctx, `INSERT INTO tenants VALUES($1) ON CONFLICT DO NOTHING`, tenant); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO partners VALUES($1,$2) ON CONFLICT DO NOTHING`, tenant, partner); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO credentials(tenant_id,partner_id,actor_id,token_hash,permissions,namespace_root) VALUES($1,$2,$3,$4,$5,$6)`, tenant, partner, actor, secure.Digest(secret.Bytes), permissions, root); err != nil {
		return errors.New("cannot enroll duplicate or invalid identity")
	}
	payload, err := json.Marshal(map[string]any{"permissions": permissions, "namespace_root": root, "authority_revision": 1})
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO events(tenant_id,partner_id,event_id,actor_id,kind,resource_id,payload) VALUES($1,$2,$3,$4,'ServiceIdentityEnrolled',$4,$5)`, tenant, partner, secure.NewID(), actor, payload); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) Begin(ctx context.Context, scope Scope) (*Transaction, error) {
	return s.begin(ctx, scope, pgx.TxOptions{})
}

func (s *Store) begin(ctx context.Context, scope Scope, options pgx.TxOptions) (*Transaction, error) {
	return s.beginAuthenticated(ctx, scope, options, false)
}

func (s *Store) beginAuthenticated(ctx context.Context, scope Scope, options pgx.TxOptions, accountLock bool) (*Transaction, error) {
	tx, err := s.scopedTransaction(ctx, scope, options)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = tx.Rollback(ctx)
		}
	}()
	// Management serialization must precede browser-session/credential locks.
	// Otherwise two managers can each hold a session needed by the other's
	// invalidation while waiting on the partner's account command lock.
	if accountLock {
		if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, scope.Tenant+":"+scope.Partner+":accounts"); err != nil {
			return nil, err
		}
	}
	t := &Transaction{Tx: tx, Scope: scope}
	if err = t.authenticate(ctx); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, `SELECT set_config('freightctl.actor_id',$1,true)`, t.Actor); err != nil {
		return nil, err
	}
	ok = true
	return t, nil
}

// scopedTransaction is shared by ordinary authentication and the opaque browser
// credential lookup. Every domain relation stays locked while its forced RLS
// policy is inspected; no lookup can silently use an owner or bypass role.
func (s *Store) scopedTransaction(ctx context.Context, scope Scope, options pgx.TxOptions) (pgx.Tx, error) {
	if !ValidID(scope.Tenant) || !ValidID(scope.Partner) {
		return nil, ErrUnauthorized
	}
	tx, err := s.Pool.BeginTx(ctx, options)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = tx.Rollback(ctx)
		}
	}()
	// Hold relation locks before inspecting policies. ALTER TABLE cannot disable a
	// checked policy between this check and the operation's reads or writes.
	names := make([]string, len(domainTables))
	for i, name := range domainTables {
		names[i] = pgx.Identifier{"public", name}.Sanitize()
	}
	_, err = tx.Exec(ctx, `LOCK TABLE `+strings.Join(names, ",")+` IN ACCESS SHARE MODE`)
	if err != nil {
		return nil, err
	}
	var protected int
	err = tx.QueryRow(ctx, `SELECT count(*) FROM pg_class WHERE relnamespace='public'::regnamespace AND relname=ANY($1) AND relrowsecurity AND relforcerowsecurity AND relowner<>(SELECT oid FROM pg_roles WHERE rolname=current_user)`, domainTables).Scan(&protected)
	if err != nil {
		return nil, err
	}
	var writerSafe bool
	if err = tx.QueryRow(ctx, `SELECT freightctl_account_writer_safe() AND freightctl_partner_writer_safe()`).Scan(&writerSafe); err != nil || !writerSafe {
		return nil, ErrIsolation
	}
	if protected != len(domainTables) {
		return nil, ErrIsolation
	}
	_, err = tx.Exec(ctx, `SELECT set_config('freightctl.tenant_id',$1,true),set_config('freightctl.partner_id',$2,true),set_config('freightctl.actor_id','',true),set_config('freightctl.browser_session_hash',$3,true)`, scope.Tenant, scope.Partner, scope.BrowserSessionHash)
	if err != nil {
		return nil, err
	}
	ok = true
	return tx, nil
}
func (t *Transaction) Replay(ctx context.Context, key, meaning string) (*File, error) {
	// Database ownership serializes concurrent uploads, including different service processes.
	if _, err := t.Tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, t.Scope.Tenant+":"+t.Scope.Partner+":"+key); err != nil {
		return nil, err
	}
	var prior, id string
	err := t.Tx.QueryRow(ctx, `SELECT request_hash,file_id::text FROM idempotency WHERE request_key=$1 AND actor_id=$2`, key, t.Actor).Scan(&prior, &id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if prior != meaning {
		return nil, ErrConflict
	}
	return t.File(ctx, id)
}
func (t *Transaction) File(ctx context.Context, id string) (*File, error) {
	f := &File{}
	err := t.Tx.QueryRow(ctx, `SELECT file_id::text,size_bytes,sha256,policy,accepted_event_id::text FROM files WHERE file_id=$1`, id).Scan(&f.ID, &f.Size, &f.SHA256, &f.Policy, &f.EventID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return f, err
}
func (t *Transaction) Append(ctx context.Context, kind, resource string, payload any) (string, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	if len(b) > 32<<10 || len(kind) < 1 || len(kind) > 128 {
		return "", ErrLimit
	}
	id := secure.NewID()
	_, err = t.Tx.Exec(ctx, `INSERT INTO events(tenant_id,partner_id,event_id,actor_id,kind,resource_id,payload) VALUES($1,$2,$3,$4,$5,$6,$7)`, t.Scope.Tenant, t.Scope.Partner, id, t.Actor, kind, resource, b)
	return id, err
}
func (t *Transaction) Accept(ctx context.Context, key, meaning string, f *File) error {
	return t.accept(ctx, key, meaning, f, "", "")
}
func (t *Transaction) AcceptUpload(ctx context.Context, key, meaning string, f *File, uploadID, storageID string) error {
	if !ValidID(uploadID) || !ValidID(storageID) {
		return ErrState
	}
	return t.accept(ctx, key, meaning, f, uploadID, storageID)
}
func (t *Transaction) accept(ctx context.Context, key, meaning string, f *File, uploadID, storageID string) error {
	if err := t.Reauthorize(ctx); err != nil {
		return err
	}
	if err := t.Require("write"); err != nil {
		return err
	}
	id, err := t.Append(ctx, "FileAccepted", f.ID, map[string]any{"schema_version": 2, "size_bytes": f.Size, "sha256": f.SHA256, "policy": f.Policy, "request_key": key, "request_hash": meaning, "protocol_session_id": t.Scope.SessionID, "upload_session_id": uploadID, "storage_id": storageID})
	if err != nil {
		return err
	}
	f.EventID = id
	_, err = t.Tx.Exec(ctx, `INSERT INTO files VALUES($1,$2,$3,$4,$5,$6,$7)`, t.Scope.Tenant, t.Scope.Partner, f.ID, f.Size, f.SHA256, f.Policy, f.EventID)
	if err != nil {
		return err
	}
	_, err = t.Tx.Exec(ctx, `INSERT INTO idempotency(tenant_id,partner_id,request_key,request_hash,file_id,actor_id) VALUES($1,$2,$3,$4,$5,$6)`, t.Scope.Tenant, t.Scope.Partner, key, meaning, f.ID, t.Actor)
	if err == nil {
		if t.PendingFiles == nil {
			t.PendingFiles = make(map[string]bool)
		}
		t.PendingFiles[f.ID] = true
	}
	return err
}
func (t *Transaction) Reauthorize(ctx context.Context) error {
	actor, revision := t.Actor, t.AuthorityRevision
	if err := t.authenticate(ctx); err != nil {
		return err
	}
	if actor != t.Actor || revision != t.AuthorityRevision {
		return ErrUnauthorized
	}
	return nil
}

func (t *Transaction) authenticate(ctx context.Context) error {
	var row pgx.Row
	if t.Scope.TokenHash != "" {
		if t.Scope.Actor != "" || t.Scope.SSHKeyFingerprint != "" {
			return ErrUnauthorized
		}
		row = t.Tx.QueryRow(ctx, `SELECT actor_id::text,permissions,namespace_root,authority_revision,expires_at FROM credentials WHERE token_hash=$1 AND tenant_id=$2 AND partner_id=$3 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>clock_timestamp())`, t.Scope.TokenHash, t.Scope.Tenant, t.Scope.Partner)
	} else {
		if !ValidID(t.Scope.Actor) || t.Scope.SSHKeyFingerprint == "" {
			return ErrUnauthorized
		}
		row = t.Tx.QueryRow(ctx, `SELECT c.actor_id::text,c.permissions,c.namespace_root,c.authority_revision,c.expires_at FROM credentials c JOIN ssh_keys k USING(tenant_id,partner_id,actor_id) WHERE c.actor_id=$1 AND k.fingerprint=$2 AND c.tenant_id=$3 AND c.partner_id=$4 AND c.revoked_at IS NULL AND (c.expires_at IS NULL OR c.expires_at>clock_timestamp()) AND k.revoked_at IS NULL`, t.Scope.Actor, t.Scope.SSHKeyFingerprint, t.Scope.Tenant, t.Scope.Partner)
	}
	err := row.Scan(&t.Actor, &t.Permissions, &t.Root, &t.AuthorityRevision, &t.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrUnauthorized
	}
	if err != nil {
		return err
	}
	root, err := vpath.Canonical(t.Root)
	if err != nil || root != t.Root || vpath.ControlPath(root) {
		return ErrIsolation
	}
	if t.Scope.AuthorityRevision > 0 && t.Scope.AuthorityRevision != t.AuthorityRevision {
		return ErrUnauthorized
	}
	if t.Scope.BrowserSessionID != "" || t.Scope.BrowserSessionHash != "" {
		// The parent credential was authenticated above. Row locking obeys
		// UPDATE policies too, so establish this verified actor before locking
		// its browser-session row; the opaque lookup itself remains read-only.
		if _, err := t.Tx.Exec(ctx, `SELECT set_config('freightctl.actor_id',$1,true)`, t.Actor); err != nil {
			return err
		}
		if err := t.currentBrowserSession(ctx); err != nil {
			return err
		}
	}
	return nil
}
func (t *Transaction) Has(permission string) bool {
	for _, p := range t.Permissions {
		if p == permission {
			return true
		}
	}
	return false
}
func (t *Transaction) Require(permission string) error {
	if !t.Has(permission) {
		return ErrForbidden
	}
	return nil
}
func (s *Store) Events(ctx context.Context, scope Scope) ([]Event, error) {
	t, err := s.Begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if err = t.Require("audit_read"); err != nil {
		return nil, err
	}
	if t.Root != "/" {
		return nil, ErrForbidden
	}
	rows, err := t.Tx.Query(ctx, `SELECT event_id::text,actor_id::text,kind,resource_id::text,payload,happened_at FROM events ORDER BY happened_at DESC,event_id DESC LIMIT 100`)
	if err != nil {
		return nil, err
	}
	result := make([]Event, 0)
	for rows.Next() {
		var e Event
		if err = rows.Scan(&e.ID, &e.ActorID, &e.Kind, &e.ResourceID, &e.Payload, &e.At); err != nil {
			rows.Close()
			return nil, err
		}
		result = append(result, redactOnboardingEvent(e))
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return result, t.Tx.Commit(ctx)
}
func Meaning(size int64, digest string) string {
	return secure.Digest([]byte(fmt.Sprintf("integrity-only-v1:%d:%s", size, digest)))
}
