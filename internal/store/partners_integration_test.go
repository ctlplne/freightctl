//go:build integration

package store

import (
	"errors"
	"path/filepath"
	"slices"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
)

func TestPartnerEnrollmentRequiresSeparateAuthorityAndPreservesScope(t *testing.T) {
	ctx, adminPath, runtimePath, password := migrationDatabase(t)
	if err := Migrate(ctx, adminPath, password); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "manager.token")
	if err := secure.WriteToken(file); err != nil {
		t.Fatal(err)
	}
	tenant, control := secure.NewID(), secure.NewID()
	if err := Provision(ctx, adminPath, tenant, control, file); err != nil {
		t.Fatal(err)
	}
	token, err := secure.ReadSecret(file, 64)
	if err != nil {
		t.Fatal(err)
	}
	scope := Scope{Tenant: tenant, Partner: control, TokenHash: secure.Digest(token.Bytes)}
	token.Close()
	db, err := Open(ctx, runtimePath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Pool.Close()
	identity, err := db.Identity(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	c := PartnerCommand{ExpectedAuthority: 1, ExpectedTenant: 1, Partner: secure.NewID(), Admin: secure.NewID(), Label: "New payroll partner", AdminLabel: "Partner administrator", Credential: secure.Digest([]byte("new synthetic partner token")), Permissions: slices.Clone(DefaultPermissions)}
	if _, err = db.RegisterPartner(ctx, scope, "enroll", c); !errors.Is(err, ErrForbidden) {
		t.Fatal("ordinary partner administrator gained tenant authority", err)
	}
	if _, err = db.Partners(ctx, scope, "", 50); !errors.Is(err, ErrForbidden) {
		t.Fatal("unauthorized tenant directory", err)
	}
	grant := TenantAdminCommand{Operation: "grant", Actor: identity.Actor, ExpectedAuthority: identity.AuthorityRevision}
	if _, err = AdministerTenant(ctx, runtimePath, tenant, control, "grant", grant); !errors.Is(err, ErrForbidden) {
		t.Fatal("runtime granted tenant authority", err)
	}
	authorized, err := AdministerTenant(ctx, adminPath, tenant, control, "grant", grant)
	if err != nil || authorized.Membership.Revision != 1 {
		t.Fatal("authorize", err)
	}
	r, err := db.RegisterPartner(ctx, scope, "enroll", c)
	if err != nil || r.Replayed || r.Partner.ID != c.Partner {
		t.Fatal("enroll partner", err)
	}
	replay, err := db.RegisterPartner(ctx, scope, "enroll", c)
	if err != nil || !replay.Replayed || replay.Partner.Event != r.Partner.Event {
		t.Fatal("exact enrollment replay", err)
	}
	changed := c
	changed.Label = "Changed decision"
	if _, err = db.RegisterPartner(ctx, scope, "enroll", changed); !errors.Is(err, ErrConflict) {
		t.Fatal("changed enrollment replayed", err)
	}
	page, err := db.Partners(ctx, scope, "", 1)
	if err != nil || len(page.Partners) != 1 || page.Next == "" {
		t.Fatal("directory pagination", err)
	}
	page2, err := db.Partners(ctx, scope, page.Next, 1)
	if err != nil || len(page2.Partners) != 1 || page2.Partners[0].ID == page.Partners[0].ID || page2.Next != "" {
		t.Fatal("directory next page", err)
	}
	partnerScope := Scope{Tenant: tenant, Partner: c.Partner, TokenHash: c.Credential}
	if i, e := db.Identity(ctx, partnerScope); e != nil || i.Actor != c.Admin {
		t.Fatal("initial partner administrator cannot authenticate", e)
	}
	if _, err = db.Partners(ctx, partnerScope, "", 50); !errors.Is(err, ErrForbidden) {
		t.Fatal("new partner inherited tenant directory authority", err)
	}
	wrong := scope
	wrong.Partner = c.Partner
	if _, err = db.Identity(ctx, wrong); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("tenant directory authority leaked partner credentials", err)
	}
	tx, err := db.Begin(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	var targetCredentials int
	err = tx.Tx.QueryRow(ctx, `SELECT count(*) FROM credentials WHERE partner_id=$1`, c.Partner).Scan(&targetCredentials)
	tx.Tx.Rollback(ctx)
	if err != nil || targetCredentials != 0 {
		t.Fatal("directory grant exposed target credential rows", err)
	}
	revoke := TenantAdminCommand{Operation: "revoke", Actor: identity.Actor, ExpectedRevision: 1, ExpectedAuthority: identity.AuthorityRevision}
	if _, err = AdministerTenant(ctx, adminPath, tenant, control, "revoke", revoke); err != nil {
		t.Fatal(err)
	}
	if _, err = db.RegisterPartner(ctx, scope, "enroll", c); !errors.Is(err, ErrForbidden) {
		t.Fatal("cached receipt bypassed current tenant authority", err)
	}
	old, err := AdministerTenant(ctx, adminPath, tenant, control, "grant", grant)
	if err != nil || !old.Replayed || old.Membership.State != "active" {
		t.Fatal("historical maintenance receipt", err)
	}
	if _, err = db.Partners(ctx, scope, "", 50); !errors.Is(err, ErrForbidden) {
		t.Fatal("old grant receipt resurrected tenant authority", err)
	}
}

func TestPartnerEnrollmentProjectionFailureRollsBackBothScopes(t *testing.T) {
	ctx, adminPath, runtimePath, password := migrationDatabase(t)
	if err := Migrate(ctx, adminPath, password); err != nil {
		t.Fatal(err)
	}
	request := setupRequest()
	if _, err := InitializeInstallation(ctx, adminPath, request); err != nil {
		t.Fatal(err)
	}
	if _, err := AdministerTenant(ctx, adminPath, request.Tenant, request.Partner, "grant", TenantAdminCommand{Operation: "grant", Actor: request.Admin, ExpectedAuthority: 1}); err != nil {
		t.Fatal(err)
	}
	admin, err := connect(ctx, adminPath)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if _, err = admin.Exec(ctx, `CREATE FUNCTION freightctl_test_partner_failure() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'injected post-projection failure';END$$;CREATE TRIGGER fail_partner AFTER INSERT ON partner_registrations FOR EACH ROW EXECUTE FUNCTION freightctl_test_partner_failure()`); err != nil {
		t.Fatal(err)
	}
	db, err := Open(ctx, runtimePath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Pool.Close()
	c := PartnerCommand{ExpectedAuthority: 1, ExpectedTenant: 1, Partner: secure.NewID(), Admin: secure.NewID(), Label: "Test partner", AdminLabel: "Administrator", Credential: secure.Digest([]byte("token")), Permissions: slices.Clone(DefaultPermissions)}
	scope := Scope{Tenant: request.Tenant, Partner: request.Partner, TokenHash: request.Credential}
	if _, err = db.RegisterPartner(ctx, scope, "enroll", c); err == nil {
		t.Fatal("post-projection failure acknowledged")
	}
	for _, table := range []string{"partners", "credentials", "events"} {
		var count int
		if err = admin.QueryRow(ctx, "SELECT count(*) FROM "+table+" WHERE tenant_id=$1 AND partner_id=$2", request.Tenant, c.Partner).Scan(&count); err != nil || count != 0 {
			t.Fatal("failed enrollment left target state", table, count, err)
		}
	}
	var count int
	if err = admin.QueryRow(ctx, `SELECT count(*) FROM events WHERE tenant_id=$1 AND kind='PartnerRegistered'`, request.Tenant).Scan(&count); err != nil || count != 0 {
		t.Fatal("failed enrollment left source event", err)
	}
	if _, err = admin.Exec(ctx, `DROP TRIGGER fail_partner ON partner_registrations`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.RegisterPartner(ctx, scope, "enroll", c); err != nil {
		t.Fatal("original enrollment cannot recover", err)
	}
}

func TestTenantAuthorityIsBoundToCredentialAndReviewedGrantRevisions(t *testing.T) {
	ctx, adminPath, runtimePath, password := migrationDatabase(t)
	if err := Migrate(ctx, adminPath, password); err != nil {
		t.Fatal(err)
	}
	c := setupRequest()
	c.TenantAdministration = true
	if _, err := InitializeInstallation(ctx, adminPath, c); err != nil {
		t.Fatal(err)
	}
	db, err := Open(ctx, runtimePath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Pool.Close()
	scope := Scope{Tenant: c.Tenant, Partner: c.Partner, TokenHash: c.Credential}
	if who, e := db.Identity(ctx, scope); e != nil || !who.TenantAdministration {
		t.Fatal("opted-in first-run authority missing", e)
	}
	reviewer, reviewerToken := secure.NewID(), secure.Digest([]byte("reviewer"))
	if _, err = db.ChangeAccount(ctx, scope, "reviewer", AccountCommand{Operation: "create", ID: reviewer, CredentialHash: reviewerToken, Policy: &AccountPolicy{Label: "Account manager", Root: "/", Permissions: slices.Clone(DefaultPermissions)}}); err != nil {
		t.Fatal(err)
	}
	reviewerScope := Scope{Tenant: c.Tenant, Partner: c.Partner, TokenHash: reviewerToken}
	newToken := secure.Digest([]byte("rotated manager"))
	if _, err = db.ChangeAccount(ctx, reviewerScope, "rotate", AccountCommand{Operation: "rotate", ID: c.Admin, ExpectedRevision: 1, CredentialHash: newToken}); err != nil {
		t.Fatal(err)
	}
	scope.TokenHash = newToken
	if who, e := db.Identity(ctx, scope); e != nil || who.TenantAdministration {
		t.Fatal("credential rotation inherited tenant authority", e)
	}
	if _, err = db.Partners(ctx, scope, "", 50); !errors.Is(err, ErrForbidden) {
		t.Fatal("rotated credential kept directory grant", err)
	}
	status, err := TenantAdminStatus(ctx, adminPath, c.Tenant, c.Partner, c.Admin)
	if err != nil || status.Authority != 1 || status.Revision != 1 {
		t.Fatal("maintenance status lost the grant's original binding", err)
	}
	if _, err = TenantAdminStatus(ctx, runtimePath, c.Tenant, c.Partner, c.Admin); !errors.Is(err, ErrForbidden) {
		t.Fatal("runtime used deployment status capability", err)
	}
	if _, err = AdministerTenant(ctx, adminPath, c.Tenant, c.Partner, "reauthorize", TenantAdminCommand{Operation: "grant", Actor: c.Admin, ExpectedRevision: 1, ExpectedAuthority: 2}); err != nil {
		t.Fatal(err)
	}
	command := PartnerCommand{ExpectedAuthority: 1, ExpectedTenant: 1, Partner: secure.NewID(), Admin: secure.NewID(), Label: "Reviewed partner", AdminLabel: "Administrator", Credential: secure.Digest([]byte("partner")), Permissions: slices.Clone(DefaultPermissions)}
	if _, err = db.RegisterPartner(ctx, scope, "old-review", command); !errors.Is(err, ErrRevision) {
		t.Fatal("old credential/grant review executed", err)
	}
	command.ExpectedAuthority, command.ExpectedTenant = 2, 2
	if _, err = db.RegisterPartner(ctx, scope, "current-review", command); err != nil {
		t.Fatal(err)
	}
	if _, err = AdministerTenant(ctx, adminPath, c.Tenant, c.Partner, "revoke", TenantAdminCommand{Operation: "revoke", Actor: c.Admin, ExpectedRevision: 2, ExpectedAuthority: 2}); err != nil {
		t.Fatal(err)
	}
	if _, err = AdministerTenant(ctx, adminPath, c.Tenant, c.Partner, "grant-again", TenantAdminCommand{Operation: "grant", Actor: c.Admin, ExpectedRevision: 3, ExpectedAuthority: 2}); err != nil {
		t.Fatal(err)
	}
	replay, err := db.RegisterPartner(ctx, scope, "current-review", command)
	if err != nil || !replay.Replayed {
		t.Fatal("historical exact receipt unavailable under renewed current authority", err)
	}
	command.Partner, command.Admin = secure.NewID(), secure.NewID()
	if _, err = db.RegisterPartner(ctx, scope, "stale-grant-review", command); !errors.Is(err, ErrRevision) {
		t.Fatal("stale tenant grant review executed a new enrollment", err)
	}
}

func TestPartnerDirectoryCannotCrossTenantAndRejectsUnsafeWriter(t *testing.T) {
	ctx, adminPath, runtimePath, password := migrationDatabase(t)
	if err := Migrate(ctx, adminPath, password); err != nil {
		t.Fatal(err)
	}
	c := setupRequest()
	c.TenantAdministration = true
	if _, err := InitializeInstallation(ctx, adminPath, c); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(t.TempDir(), "other.token")
	if err := secure.WriteToken(other); err != nil {
		t.Fatal(err)
	}
	if err := Provision(ctx, adminPath, secure.NewID(), secure.NewID(), other); err != nil {
		t.Fatal(err)
	}
	db, err := Open(ctx, runtimePath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Pool.Close()
	scope := Scope{Tenant: c.Tenant, Partner: c.Partner, TokenHash: c.Credential}
	page, err := db.Partners(ctx, scope, "", 100)
	if err != nil || len(page.Partners) != 1 || page.Partners[0].ID != c.Partner {
		t.Fatal("foreign tenant visible", err)
	}
	admin, err := connect(ctx, adminPath)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if _, err = admin.Exec(ctx, `ALTER FUNCTION freightctl_project_partner() OWNER TO CURRENT_USER`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Identity(ctx, scope); !errors.Is(err, ErrIsolation) {
		t.Fatal("unsafe projection writer accepted", err)
	}
}

func TestTenantDirectoryGrantCannotExpandInitialAdministratorPermissions(t *testing.T) {
	ctx, adminPath, runtimePath, password := migrationDatabase(t)
	if err := Migrate(ctx, adminPath, password); err != nil {
		t.Fatal(err)
	}
	c := setupRequest()
	c.TenantAdministration = true
	if _, err := InitializeInstallation(ctx, adminPath, c); err != nil {
		t.Fatal(err)
	}
	db, err := Open(ctx, runtimePath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Pool.Close()
	owner := Scope{Tenant: c.Tenant, Partner: c.Partner, TokenHash: c.Credential}
	actor, token := secure.NewID(), secure.Digest([]byte("limited directory manager"))
	grants := []string{"admin", "accounts_manage", "read", "list", "write"}
	if _, err = db.ChangeAccount(ctx, owner, "limited-manager", AccountCommand{Operation: "create", ID: actor, CredentialHash: token, Policy: &AccountPolicy{Label: "Limited directory manager", Root: "/", Permissions: grants}}); err != nil {
		t.Fatal(err)
	}
	if _, err = AdministerTenant(ctx, adminPath, c.Tenant, c.Partner, "limited-grant", TenantAdminCommand{Operation: "grant", Actor: actor, ExpectedAuthority: 1}); err != nil {
		t.Fatal(err)
	}
	scope := Scope{Tenant: c.Tenant, Partner: c.Partner, TokenHash: token}
	request := PartnerCommand{ExpectedAuthority: 1, ExpectedTenant: 1, Partner: secure.NewID(), Admin: secure.NewID(), Label: "Scoped partner", AdminLabel: "Scoped administrator", Credential: secure.Digest([]byte("partner credential")), Permissions: slices.Clone(DefaultPermissions)}
	if _, err = db.RegisterPartner(ctx, scope, "excess-grants", request); !errors.Is(err, ErrForbidden) {
		t.Fatal("tenant directory grant expanded account permissions", err)
	}
	request.Permissions = grants
	if _, err = db.RegisterPartner(ctx, scope, "reviewed-grants", request); err != nil {
		t.Fatal(err)
	}
	identity, err := db.Identity(ctx, Scope{Tenant: c.Tenant, Partner: request.Partner, TokenHash: request.Credential})
	if err != nil || identity.TenantAdministration || len(identity.Permissions) != len(grants) {
		t.Fatal("initial administrator authority changed", err)
	}
}
