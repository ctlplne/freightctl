//go:build integration

package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
)

type browserFixture struct {
	ctx                  context.Context
	db                   *Store
	scope                Scope
	adminPath, tokenPath string
}

func newBrowserFixture(t *testing.T) *browserFixture {
	t.Helper()
	ctx, admin, runtime, password := migrationDatabase(t)
	if err := Migrate(ctx, admin, password); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "credential")
	if err := secure.WriteToken(path); err != nil {
		t.Fatal(err)
	}
	scope := Scope{Tenant: secure.NewID(), Partner: secure.NewID()}
	if err := Provision(ctx, admin, scope.Tenant, scope.Partner, path); err != nil {
		t.Fatal(err)
	}
	credential, err := secure.ReadSecret(path, 64)
	if err != nil {
		t.Fatal(err)
	}
	scope.TokenHash = secure.Digest(credential.Bytes)
	credential.Close()
	db, err := Open(ctx, runtime)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Pool.Close)
	return &browserFixture{ctx: ctx, db: db, scope: scope, adminPath: admin, tokenPath: path}
}

func (f *browserFixture) create(t *testing.T, key string, lifetime time.Duration) (*BrowserSession, Scope) {
	t.Helper()
	credential, err := secure.ReadSecret(f.tokenPath, 64)
	if err != nil {
		t.Fatal(err)
	}
	defer credential.Close()
	secret, err := secure.BrowserSessionToken(credential.Bytes, f.scope.Tenant, f.scope.Partner, key)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Close()
	hash := secure.Digest(secret.Bytes)
	session, identity, _, err := f.db.CreateBrowserSession(f.ctx, f.scope, key, hash, lifetime)
	if err != nil || identity == nil {
		t.Fatal("session creation", err)
	}
	scope, read, err := f.db.BrowserScope(f.ctx, f.scope.Tenant, f.scope.Partner, hash)
	if err != nil || read.ID != session.ID || scope.AuthorityRevision != identity.AuthorityRevision {
		t.Fatal("opaque lookup", err)
	}
	return session, scope
}

func TestBrowserSessionReplayIsolationAndLiveRevocation(t *testing.T) {
	f := newBrowserFixture(t)
	b, scope := f.create(t, "browser-session", 10*time.Minute)
	identity, err := f.db.Identity(f.ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	if identity.AuthorityRevision != b.Authority || scope.TokenHash != f.scope.TokenHash || scope.SessionID != b.ID {
		t.Fatal("session changed ordinary authority")
	}
	again, _, _, err := f.db.CreateBrowserSession(f.ctx, f.scope, b.RequestKey, b.SecretHash, 10*time.Minute)
	if err != nil || !again.Replayed || again.ID != b.ID || !again.ExpiresAt.Equal(b.ExpiresAt) {
		t.Fatal("replay renewed or changed session", err)
	}
	if _, _, _, err = f.db.CreateBrowserSession(f.ctx, f.scope, b.RequestKey, secure.Digest([]byte("changed-meaning")), 10*time.Minute); !errors.Is(err, ErrConflict) {
		t.Fatal("changed secret replay", err)
	}
	if _, _, _, err = f.db.CreateBrowserSession(f.ctx, f.scope, b.RequestKey, b.SecretHash, 5*time.Minute); !errors.Is(err, ErrConflict) {
		t.Fatal("changed lifetime replay", err)
	}
	if _, _, err = f.db.BrowserScope(f.ctx, secure.NewID(), f.scope.Partner, b.SecretHash); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("foreign tenant", err)
	}
	if _, _, err = f.db.BrowserScope(f.ctx, f.scope.Tenant, secure.NewID(), b.SecretHash); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("foreign partner", err)
	}
	forged := scope
	forged.BrowserSessionID = secure.NewID()
	if _, err = f.db.Identity(f.ctx, forged); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("forged session proof", err)
	}
	if err = f.db.RevokeBrowserSession(f.ctx, scope, "logout-session"); err != nil {
		t.Fatal(err)
	}
	if _, err = f.db.Identity(f.ctx, scope); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("captured scope survived logout", err)
	}
	if _, _, err = f.db.BrowserScope(f.ctx, f.scope.Tenant, f.scope.Partner, b.SecretHash); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("revoked cookie survived", err)
	}
	again, _, _, err = f.db.CreateBrowserSession(f.ctx, f.scope, b.RequestKey, b.SecretHash, 10*time.Minute)
	if err != nil || again.State != "revoked" || !again.ExpiresAt.Equal(b.ExpiresAt) {
		t.Fatal("login replay resurrected logout", err)
	}
}

func TestBrowserSessionDatabaseExpiryAndAdmissionStayBounded(t *testing.T) {
	f := newBrowserFixture(t)
	b, scope := f.create(t, "short-session", 2*time.Second)
	time.Sleep(2200 * time.Millisecond)
	if _, err := f.db.Identity(f.ctx, scope); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("captured expired scope accepted", err)
	}
	if _, _, err := f.db.BrowserScope(f.ctx, f.scope.Tenant, f.scope.Partner, b.SecretHash); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("expired lookup accepted", err)
	}
	if _, err := f.db.Identity(f.ctx, f.scope); err != nil {
		t.Fatal("expiry revoked parent credential", err)
	}
	var first Scope
	for i := 0; i < 8; i++ {
		_, s := f.create(t, secure.NewID(), 10*time.Minute)
		if i == 0 {
			first = s
		}
	}
	if _, _, _, err := f.db.CreateBrowserSession(f.ctx, f.scope, "over-capacity", secure.Digest([]byte("capacity-token")), 10*time.Minute); !errors.Is(err, ErrLimit) {
		t.Fatal("unbounded active sessions", err)
	}
	if err := f.db.RevokeBrowserSession(f.ctx, first, "logout-first"); err != nil {
		t.Fatal(err)
	}
	f.create(t, "after-revocation", 10*time.Minute)
}

func TestBrowserSessionCannotChangeAuthorityOrBypassItsEvent(t *testing.T) {
	f := newBrowserFixture(t)
	b, scope := f.create(t, "immutable-session", 10*time.Minute)
	tx, err := f.db.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Tx.Exec(f.ctx, `UPDATE browser_sessions SET expires_at=expires_at+interval '1 hour' WHERE session_id=$1`, b.ID); err == nil {
		t.Fatal("unjournaled expiry changed")
	}
	_ = tx.Tx.Rollback(f.ctx)
	tx, err = f.db.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	changed := *b
	changed.ExpiresAt = changed.ExpiresAt.Add(time.Hour)
	changed.Revision++
	event, err := tx.Append(f.ctx, "BrowserSessionChanged", changed.ID, &changed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Tx.Exec(f.ctx, `UPDATE browser_sessions SET expires_at=$1,revision=$2,changed_event_id=$3 WHERE session_id=$4`, changed.ExpiresAt, changed.Revision, event, b.ID); err == nil {
		t.Fatal("forged exact event changed immutable expiry")
	}
	_ = tx.Tx.Rollback(f.ctx)
	if _, err = f.db.Identity(f.ctx, scope); err != nil {
		t.Fatal("rejected mutation affected valid session", err)
	}
	admin, err := connect(f.ctx, f.adminPath)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if _, err = admin.Exec(f.ctx, `UPDATE credentials SET revoked_at=clock_timestamp() WHERE tenant_id=$1 AND partner_id=$2 AND token_hash=$3`, f.scope.Tenant, f.scope.Partner, f.scope.TokenHash); err != nil {
		t.Fatal(err)
	}
	if _, err = f.db.Identity(f.ctx, scope); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("parent credential revocation ignored", err)
	}
}

func TestBrowserSessionCreationRollsBackItsEventOnProjectionFailure(t *testing.T) {
	f := newBrowserFixture(t)
	admin, err := connect(f.ctx, f.adminPath)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if _, err = admin.Exec(f.ctx, `CREATE FUNCTION freightctl_browser_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic browser projection fault'; END $$; CREATE TRIGGER browser_fault BEFORE INSERT ON browser_sessions FOR EACH ROW EXECUTE FUNCTION freightctl_browser_fault()`); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = f.db.CreateBrowserSession(f.ctx, f.scope, "fault", secure.Digest([]byte("fault-token")), 10*time.Minute); err == nil {
		t.Fatal("projection fault ignored")
	}
	var count int
	if err = admin.QueryRow(f.ctx, `SELECT count(*) FROM events WHERE kind='BrowserSessionChanged'`).Scan(&count); err != nil || count != 0 {
		t.Fatal("orphan session event", count, err)
	}
}

func TestBrowserSessionRemainsBoundToOriginalCredentialAfterAdminRotation(t *testing.T) {
	f := newBrowserFixture(t)
	b, captured := f.create(t, "before-rotation", 10*time.Minute)
	path := filepath.Join(t.TempDir(), "replacement-credential")
	if err := secure.WriteToken(path); err != nil {
		t.Fatal(err)
	}
	replacement, err := secure.ReadSecret(path, 64)
	if err != nil {
		t.Fatal(err)
	}
	hash := secure.Digest(replacement.Bytes)
	replacement.Close()
	admin, err := connect(f.ctx, f.adminPath)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if _, err = admin.Exec(f.ctx, `UPDATE credentials SET token_hash=$1 WHERE tenant_id=$2 AND partner_id=$3 AND token_hash=$4`, hash, f.scope.Tenant, f.scope.Partner, f.scope.TokenHash); err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.db.BrowserScope(f.ctx, f.scope.Tenant, f.scope.Partner, b.SecretHash); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("old cookie inherited replacement credential", err)
	}
	if _, err = f.db.Identity(f.ctx, captured); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("captured session proof survived parent rotation", err)
	}
	f.scope.TokenHash = hash
	f.tokenPath = path
	f.create(t, "after-rotation", 10*time.Minute)
}

func TestBrowserLogoutReceiptFailureRollsBackRevocationAndEvents(t *testing.T) {
	f := newBrowserFixture(t)
	_, scope := f.create(t, "receipt-fault", 10*time.Minute)
	admin, err := connect(f.ctx, f.adminPath)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if _, err = admin.Exec(f.ctx, `CREATE FUNCTION freightctl_browser_command_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic logout receipt fault'; END $$; CREATE TRIGGER browser_command_fault BEFORE INSERT ON browser_commands FOR EACH ROW EXECUTE FUNCTION freightctl_browser_command_fault()`); err != nil {
		t.Fatal(err)
	}
	if err = f.db.RevokeBrowserSession(f.ctx, scope, "fault-logout"); err == nil {
		t.Fatal("receipt failure acknowledged logout")
	}
	if _, err = f.db.Identity(f.ctx, scope); err != nil {
		t.Fatal("failed receipt left revoked session", err)
	}
	var changed, commands int
	if err = admin.QueryRow(f.ctx, `SELECT count(*) FILTER(WHERE kind='BrowserSessionChanged'),count(*) FILTER(WHERE kind='BrowserLogoutRecorded') FROM events`).Scan(&changed, &commands); err != nil || changed != 1 || commands != 0 {
		t.Fatal("logout rollback lost atomicity", changed, commands, err)
	}
	if _, err = admin.Exec(f.ctx, `DROP TRIGGER browser_command_fault ON browser_commands`); err != nil {
		t.Fatal(err)
	}
	if err = f.db.RevokeBrowserSession(f.ctx, scope, "fault-logout"); err != nil {
		t.Fatal("original logout retry failed", err)
	}
	if err = f.db.RevokeBrowserSession(f.ctx, scope, "fault-logout"); err != nil {
		t.Fatal("original logout replay failed", err)
	}
}

func TestBrowserLogoutReceiptsHaveBoundedDistinctCommands(t *testing.T) {
	f := newBrowserFixture(t)
	_, scope := f.create(t, "bounded-logout", 10*time.Minute)
	for i := 0; i < 16; i++ {
		if err := f.db.RevokeBrowserSession(f.ctx, scope, secure.NewID()); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.db.RevokeBrowserSession(f.ctx, scope, "over-budget"); !errors.Is(err, ErrLimit) {
		t.Fatal("unbounded logout receipts", err)
	}
	if _, err := f.db.Identity(f.ctx, scope); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("close-only capability recovered file authority", err)
	}
}
