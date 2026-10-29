//go:build integration

package store

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
)

func setupRequest() SetupRequest {
	return SetupRequest{SchemaVersion: 1, RequestKey: secure.NewID(), Tenant: secure.NewID(), Partner: secure.NewID(), Admin: secure.NewID(), Storage: secure.NewID(), TenantLabel: "Example tenant", PartnerLabel: "Payroll partner", AdminLabel: "First administrator", Credential: secure.Digest([]byte("synthetic credential")), Permissions: slices.Clone(DefaultPermissions)}
}
func TestFirstRunAtomicReplayIsolationAndRuntimeRefusal(t *testing.T) {
	ctx, adminPath, runtimePath, password := migrationDatabase(t)
	if err := Migrate(ctx, adminPath, password); err != nil {
		t.Fatal(err)
	}
	c := setupRequest()
	if _, err := InitializeInstallation(ctx, runtimePath, c); !errors.Is(err, ErrForbidden) {
		t.Fatal("runtime initialized deployment", err)
	}
	r, err := InitializeInstallation(ctx, adminPath, c)
	if err != nil || r.Replayed || r.Actor != c.Admin {
		t.Fatal("first enrollment", err)
	}
	replay, err := InitializeInstallation(ctx, adminPath, c)
	if err != nil || !replay.Replayed || replay.Event != r.Event || !replay.InitializedAt.Equal(r.InitializedAt) {
		t.Fatal("lost-response replay changed enrollment", err)
	}
	changed := c
	changed.PartnerLabel = "Changed after review"
	if _, err = InitializeInstallation(ctx, adminPath, changed); !errors.Is(err, ErrInitialized) {
		t.Fatal("changed plan replayed", err)
	}
	if _, err = InitializeInstallation(ctx, adminPath, setupRequest()); !errors.Is(err, ErrInitialized) {
		t.Fatal("second installation accepted", err)
	}
	db, err := Open(ctx, runtimePath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Pool.Close()
	scope := Scope{Tenant: c.Tenant, Partner: c.Partner, TokenHash: c.Credential}
	i, err := db.Identity(ctx, scope)
	if err != nil || i.Actor != c.Admin || !slices.Contains(i.Permissions, "accounts_manage") {
		t.Fatal("new administrator cannot authenticate", err)
	}
	other := secure.NewID()
	if _, err = db.ChangeAccount(ctx, scope, "ordinary-account", AccountCommand{Operation: "create", ID: other, CredentialHash: secure.Digest([]byte("partner account")), Policy: &AccountPolicy{Label: "Sender", Permissions: []string{"read", "list"}, Root: "/"}}); err != nil {
		t.Fatal("ordinary account enrollment after setup", err)
	}
	for _, token := range []string{c.Credential, secure.Digest([]byte("partner account"))} {
		tx, err := db.Begin(ctx, Scope{Tenant: c.Tenant, Partner: c.Partner, TokenHash: token})
		if err != nil {
			t.Fatal(err)
		}
		var count int
		err = tx.Tx.QueryRow(ctx, `SELECT count(*) FROM installation_enrollments`).Scan(&count)
		tx.Tx.Rollback(ctx)
		want := 0
		if token == c.Credential {
			want = 1
		}
		if err != nil || count != want {
			t.Fatal("installation receipt actor isolation", count, err)
		}
	}
	admin, err := connect(ctx, adminPath)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	for _, table := range []string{"tenants", "partners", "installation_enrollments"} {
		var count int
		if err = admin.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&count); err != nil || count != 1 {
			t.Fatal("enrollment duplicated", table, count, err)
		}
	}
	if _, err = admin.Exec(ctx, `UPDATE installation_enrollments SET request_hash=repeat('0',64)`); err == nil {
		t.Fatal("immutable installation receipt updated")
	}
}
func TestFirstRunReceiptFailureRollsBackEveryIdentity(t *testing.T) {
	ctx, adminPath, _, password := migrationDatabase(t)
	if err := Migrate(ctx, adminPath, password); err != nil {
		t.Fatal(err)
	}
	admin, err := connect(ctx, adminPath)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if _, err = admin.Exec(ctx, `CREATE FUNCTION freightctl_test_setup_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected receipt failure';END $$; CREATE TRIGGER fail_setup BEFORE INSERT ON installation_enrollments FOR EACH ROW EXECUTE FUNCTION freightctl_test_setup_failure()`); err != nil {
		t.Fatal(err)
	}
	c := setupRequest()
	if _, err = InitializeInstallation(ctx, adminPath, c); err == nil {
		t.Fatal("failed receipt acknowledged")
	}
	for _, table := range []string{"tenants", "partners", "credentials", "events", "installation_enrollments"} {
		var count int
		if err = admin.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&count); err != nil || count != 0 {
			t.Fatal("partial initialization survived rollback", table, count, err)
		}
	}
	if _, err = admin.Exec(ctx, `DROP TRIGGER fail_setup ON installation_enrollments`); err != nil {
		t.Fatal(err)
	}
	if _, err = InitializeInstallation(ctx, adminPath, c); err != nil {
		t.Fatal("original plan cannot recover", err)
	}
}
func TestFirstRunConcurrentPlansAndExistingInstallation(t *testing.T) {
	ctx, adminPath, _, password := migrationDatabase(t)
	if err := Migrate(ctx, adminPath, password); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errorsSeen := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func(c SetupRequest) {
			defer wg.Done()
			_, err := InitializeInstallation(ctx, adminPath, c)
			errorsSeen <- err
		}(setupRequest())
	}
	wg.Wait()
	close(errorsSeen)
	passed, refused := 0, 0
	for err := range errorsSeen {
		if err == nil {
			passed++
		} else if errors.Is(err, ErrInitialized) {
			refused++
		} else {
			t.Fatal(err)
		}
	}
	if passed != 1 || refused != 1 {
		t.Fatal("concurrent initialization was not exclusive", passed, refused)
	}
}

func TestFirstRunRefusesLegacyInstallationWithoutChangingIt(t *testing.T) {
	ctx, adminPath, runtimePath, password := migrationDatabase(t)
	if err := Migrate(ctx, adminPath, password); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(t.TempDir(), "legacy.token")
	if err := secure.WriteToken(tokenPath); err != nil {
		t.Fatal(err)
	}
	tenant, partner := secure.NewID(), secure.NewID()
	if err := Provision(ctx, adminPath, tenant, partner, tokenPath); err != nil {
		t.Fatal(err)
	}
	if _, err := InitializeInstallation(ctx, adminPath, setupRequest()); !errors.Is(err, ErrInitialized) {
		t.Fatal("legacy hierarchy replaced or adopted", err)
	}
	db, err := Open(ctx, runtimePath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Pool.Close()
	token, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	defer secure.Clear(token)
	if _, err = db.Identity(ctx, Scope{Tenant: tenant, Partner: partner, TokenHash: secure.Digest(token)}); err != nil {
		t.Fatal("legacy authority changed", err)
	}
}
