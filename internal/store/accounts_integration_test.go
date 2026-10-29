//go:build integration

package store

import (
	"encoding/json"
	"errors"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"testing"
	"time"
)

func TestAccountLifecycleReplaysAndInvalidatesSessions(t *testing.T) {
	f := newBrowserFixture(t)
	command := AccountCommand{Operation: "create", ID: secure.NewID(), CredentialHash: secure.Digest([]byte("synthetic-credential-proof-one")), Policy: &AccountPolicy{Label: "Partner account", Root: "/", Permissions: []string{"read", "list"}}}
	r, err := f.db.ChangeAccount(f.ctx, f.scope, "create-account", command)
	if err != nil {
		t.Fatal(err)
	}
	original := r.Account
	if r.Replayed || original.Revision != 1 || original.AuthorityRevision != 1 {
		t.Fatal("invalid initial revision", r)
	}
	replay, err := f.db.ChangeAccount(f.ctx, f.scope, "create-account", command)
	if err != nil || !replay.Replayed || *replay.Account.EventID != *original.EventID {
		t.Fatal("lost retry receipt", err)
	}
	changed := command
	changed.Policy = &AccountPolicy{Label: "different", Root: "/", Permissions: []string{"read"}}
	if _, err = f.db.ChangeAccount(f.ctx, f.scope, "create-account", changed); !errors.Is(err, ErrConflict) {
		t.Fatal("changed request replayed", err)
	}
	child := Scope{Tenant: f.scope.Tenant, Partner: f.scope.Partner, TokenHash: command.CredentialHash}
	hashes := []string{}
	for i := 0; i < 8; i++ {
		hash := secure.Digest([]byte(secure.NewID()))
		hashes = append(hashes, hash)
		if _, _, _, err = f.db.CreateBrowserSession(f.ctx, child, secure.NewID(), hash, time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, _, err = f.db.CreateBrowserSession(f.ctx, child, "ninth-session", secure.Digest([]byte(secure.NewID())), time.Minute); !errors.Is(err, ErrLimit) {
		t.Fatal("session admission exceeded", err)
	}
	rotate := AccountCommand{Operation: "rotate", ID: command.ID, ExpectedRevision: 1, CredentialHash: secure.Digest([]byte("synthetic-credential-proof-two"))}
	r, err = f.db.ChangeAccount(f.ctx, f.scope, "rotate-account", rotate)
	if err != nil {
		t.Fatal(err)
	}
	if r.Account.AuthorityRevision != 2 || r.Account.Revision != 2 {
		t.Fatal("rotation kept authority")
	}
	if _, err = f.db.Identity(f.ctx, child); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("old credential survived", err)
	}
	for _, hash := range hashes {
		if _, _, err = f.db.BrowserScope(f.ctx, child.Tenant, child.Partner, hash); !errors.Is(err, ErrUnauthorized) {
			t.Fatal("old browser survived", err)
		}
	}
	admin, err := connect(f.ctx, f.adminPath)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	var active, events int
	if err = admin.QueryRow(f.ctx, `SELECT count(*) FROM browser_sessions WHERE actor_id=$1 AND state='active'`, command.ID).Scan(&active); err != nil || active != 0 {
		t.Fatal("sessions were not atomically revoked", active, err)
	}
	if err = admin.QueryRow(f.ctx, `SELECT count(*) FROM events WHERE kind='BrowserSessionChanged' AND payload->>'account_change_event_id'=$1`, *r.Account.EventID).Scan(&events); err != nil || events != 8 {
		t.Fatal("missing manager audit", events, err)
	}
	child.TokenHash = rotate.CredentialHash
	if _, err = f.db.Identity(f.ctx, child); err != nil {
		t.Fatal(err)
	}
	if _, err = f.db.ChangeAccount(f.ctx, f.scope, "stale-rotate", rotate); !errors.Is(err, ErrRevision) {
		t.Fatal("stale revision changed account", err)
	}
	update := AccountCommand{Operation: "update", ID: command.ID, ExpectedRevision: 2, Policy: &AccountPolicy{Label: "New label", Root: "/", Permissions: []string{"list", "read"}}}
	r, err = f.db.ChangeAccount(f.ctx, f.scope, "label-account", update)
	if err != nil {
		t.Fatal(err)
	}
	if r.Account.AuthorityRevision != 2 || r.Account.Revision != 3 {
		t.Fatal("label invalidated file authority")
	}
	revoke := AccountCommand{Operation: "revoke", ID: command.ID, ExpectedRevision: 3}
	if _, err = f.db.ChangeAccount(f.ctx, f.scope, "revoke-account", revoke); err != nil {
		t.Fatal(err)
	}
	if _, err = f.db.Identity(f.ctx, child); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("revoked credential survived", err)
	}
	if _, err = f.db.ChangeAccount(f.ctx, child, "child-manage", command); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("revoked actor managed accounts", err)
	}
	if _, err = f.db.ChangeAccount(f.ctx, f.scope, "resurrect-account", AccountCommand{Operation: "rotate", ID: command.ID, ExpectedRevision: 4, CredentialHash: secure.Digest([]byte("third"))}); !errors.Is(err, ErrState) {
		t.Fatal("revocation resurrected", err)
	}
}

func TestAccountExpiryAndRuntimeBoundary(t *testing.T) {
	f := newBrowserFixture(t)
	expiry := time.Now().Add(3 * time.Second).UTC().Truncate(time.Microsecond)
	command := AccountCommand{Operation: "create", ID: secure.NewID(), CredentialHash: secure.Digest([]byte("expiry-proof")), Policy: &AccountPolicy{Label: "Expires", Root: "/", Permissions: []string{"read"}, ExpiresAt: &expiry}}
	if _, err := f.db.ChangeAccount(f.ctx, f.scope, "create-expiring", command); err != nil {
		t.Fatal(err)
	}
	child := Scope{Tenant: f.scope.Tenant, Partner: f.scope.Partner, TokenHash: command.CredentialHash}
	b, _, _, err := f.db.CreateBrowserSession(f.ctx, child, "expiry-browser", secure.Digest([]byte("expiry-browser-proof")), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !b.ExpiresAt.Equal(expiry) {
		t.Fatal("browser outlives account")
	}
	if _, err = f.db.Accounts(f.ctx, child, "", 10); !errors.Is(err, ErrForbidden) {
		t.Fatal("ordinary actor listed accounts", err)
	}
	tx, err := f.db.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Tx.Exec(f.ctx, `UPDATE credentials SET account_label='bypass' WHERE actor_id=$1`, command.ID); err == nil {
		t.Fatal("runtime has direct credential update")
	}
	tx.Tx.Rollback(f.ctx)
	time.Sleep(time.Until(expiry.Add(30 * time.Millisecond)))
	if _, err = f.db.Identity(f.ctx, child); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("expired credential authenticated", err)
	}
	current, err := f.db.Account(f.ctx, f.scope, command.ID)
	if err != nil || current.State != "expired" {
		t.Fatal("expiry state absent", err)
	}
	rotated, err := f.db.ChangeAccount(f.ctx, f.scope, "expired-rotate", AccountCommand{Operation: "rotate", ID: command.ID, ExpectedRevision: 1, CredentialHash: secure.Digest([]byte("expired-new-proof"))})
	if err != nil || rotated.Account.State != "expired" {
		t.Fatal("rotation revived expiry", err)
	}
}

func TestAccountCommandsRollbackReceiptsAndRejectForgery(t *testing.T) {
	f := newBrowserFixture(t)
	admin, err := connect(f.ctx, f.adminPath)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	command := AccountCommand{Operation: "create", ID: secure.NewID(), CredentialHash: secure.Digest([]byte("rollback-proof")), Policy: &AccountPolicy{Label: "Atomic", Root: "/", Permissions: []string{"read"}}}
	if _, err = admin.Exec(f.ctx, `CREATE FUNCTION freightctl_fail_account_receipt() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected account receipt failure';END $$;CREATE TRIGGER freightctl_fail_account_receipt BEFORE INSERT ON account_commands FOR EACH ROW EXECUTE FUNCTION freightctl_fail_account_receipt()`); err != nil {
		t.Fatal(err)
	}
	if _, err = f.db.ChangeAccount(f.ctx, f.scope, "receipt-failure", command); err == nil {
		t.Fatal("acknowledged failed receipt")
	}
	var credentials, events int
	if err = admin.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM credentials WHERE actor_id=$1),(SELECT count(*) FROM events WHERE resource_id=$1)`, command.ID).Scan(&credentials, &events); err != nil || credentials != 0 || events != 0 {
		t.Fatal("partial account escaped rollback", credentials, events, err)
	}
	if _, err = admin.Exec(f.ctx, `DROP TRIGGER freightctl_fail_account_receipt ON account_commands`); err != nil {
		t.Fatal(err)
	}
	if _, err = f.db.ChangeAccount(f.ctx, f.scope, "receipt-failure", command); err != nil {
		t.Fatal("original command did not recover", err)
	}
	tx, err := f.db.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Append(f.ctx, "AccountChanged", secure.NewID(), map[string]any{"request_key": "forged-alone"}); err != nil {
		t.Fatal(err)
	}
	if err = tx.Tx.Commit(f.ctx); err == nil {
		t.Fatal("orphan account journal event committed")
	}
	tx, err = f.db.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	now, err := tx.DatabaseTime(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	id := secure.NewID()
	eventID := secure.NewID()
	hash := secure.Digest([]byte("forged"))
	definition := accountDefinition{AccountPolicy: AccountPolicy{Label: "Exact", Root: "/", Permissions: []string{"read"}}, CredentialHash: hash}
	wrong := Account{ID: id, AccountPolicy: definition.AccountPolicy, Revision: 1, AuthorityRevision: 1, State: "active", EventID: &eventID, ObservedAt: now}
	wrong.Label = "False success"
	payload, _ := json.Marshal(map[string]any{"account_id": id, "revision": 1, "authority_revision": 1, "operation": "create", "request_key": "forged-result", "request_hash": hash, "definition": definition, "account": wrong})
	encoded, _ := json.Marshal(definition)
	if _, err = tx.Tx.Exec(f.ctx, `INSERT INTO events(tenant_id,partner_id,event_id,actor_id,kind,resource_id,payload,happened_at) VALUES($1,$2,$3,$4,'AccountChanged',$5,$6,$7)`, f.scope.Tenant, f.scope.Partner, eventID, tx.Actor, id, payload, now); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Tx.Exec(f.ctx, `INSERT INTO account_revisions(tenant_id,partner_id,manager_actor_id,account_id,revision,authority_revision,operation,request_key,request_hash,definition,event_id) VALUES($1,$2,$3,$4,1,1,'create','forged-result',$5,$6,$7)`, f.scope.Tenant, f.scope.Partner, tx.Actor, id, hash, encoded, eventID); err == nil {
		t.Fatal("forged account result projected")
	}
	tx.Tx.Rollback(f.ctx)
	if _, err = admin.Exec(f.ctx, `ALTER TABLE account_revisions NO FORCE ROW LEVEL SECURITY`); err != nil {
		t.Fatal(err)
	}
	if _, err = f.db.Account(f.ctx, f.scope, command.ID); !errors.Is(err, ErrIsolation) {
		t.Fatal("weakened account isolation accepted", err)
	}
}

func TestAccountManagerCannotEscalateOrCrossScope(t *testing.T) {
	f := newBrowserFixture(t)
	command := AccountCommand{Operation: "create", ID: secure.NewID(), CredentialHash: secure.Digest([]byte("manager-proof")), Policy: &AccountPolicy{Label: "Limited manager", Root: "/", Permissions: []string{"admin", "accounts_manage", "read"}}}
	if _, err := f.db.ChangeAccount(f.ctx, f.scope, "manager", command); err != nil {
		t.Fatal(err)
	}
	manager := Scope{Tenant: f.scope.Tenant, Partner: f.scope.Partner, TokenHash: command.CredentialHash}
	escalation := AccountCommand{Operation: "create", ID: secure.NewID(), CredentialHash: secure.Digest([]byte("escalation-proof")), Policy: &AccountPolicy{Label: "Escalated", Root: "/", Permissions: []string{"write"}}}
	if _, err := f.db.ChangeAccount(f.ctx, manager, "escalate", escalation); !errors.Is(err, ErrForbidden) {
		t.Fatal("manager granted authority it lacks", err)
	}
	identity, err := f.db.Identity(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.db.ChangeAccount(f.ctx, manager, "rotate-superior", AccountCommand{Operation: "rotate", ID: identity.Actor, ExpectedRevision: 1, CredentialHash: secure.Digest([]byte("takeover"))}); !errors.Is(err, ErrForbidden) {
		t.Fatal("manager took over superior account", err)
	}
	manager.Partner = secure.NewID()
	if _, err = f.db.Accounts(f.ctx, manager, "", 10); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("cross-partner account listing", err)
	}
	manager.Partner = f.scope.Partner
	manager.Tenant = secure.NewID()
	if _, err = f.db.Accounts(f.ctx, manager, "", 10); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("cross-tenant account listing", err)
	}
}

func TestAccountConcurrentManagersSerializeBeforeSessionLocks(t *testing.T) {
	f := newBrowserFixture(t)
	scopes := []Scope{}
	ids := []string{}
	for i := 0; i < 2; i++ {
		command := AccountCommand{Operation: "create", ID: secure.NewID(), CredentialHash: secure.Digest([]byte(secure.NewID())), Policy: &AccountPolicy{Label: "Concurrent manager", Root: "/", Permissions: append([]string{}, DefaultPermissions...)}}
		if _, err := f.db.ChangeAccount(f.ctx, f.scope, secure.NewID(), command); err != nil {
			t.Fatal(err)
		}
		child := Scope{Tenant: f.scope.Tenant, Partner: f.scope.Partner, TokenHash: command.CredentialHash}
		hash := secure.Digest([]byte(secure.NewID()))
		if _, _, _, err := f.db.CreateBrowserSession(f.ctx, child, secure.NewID(), hash, time.Minute); err != nil {
			t.Fatal(err)
		}
		browser, _, err := f.db.BrowserScope(f.ctx, child.Tenant, child.Partner, hash)
		if err != nil {
			t.Fatal(err)
		}
		scopes = append(scopes, browser)
		ids = append(ids, command.ID)
	}
	admin, err := connect(f.ctx, f.adminPath)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	gate, err := admin.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Rollback(f.ctx)
	if _, err = gate.Exec(f.ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, f.scope.Tenant+":"+f.scope.Partner+":accounts"); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func(i int) {
			_, e := f.db.ChangeAccount(f.ctx, scopes[i], secure.NewID(), AccountCommand{Operation: "rotate", ID: ids[1-i], ExpectedRevision: 1, CredentialHash: secure.Digest([]byte(secure.NewID()))})
			done <- e
		}(i)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		var waiting int
		if err = admin.QueryRow(f.ctx, `SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND NOT granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database())`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("both management commands did not reach serialization gate")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err = gate.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	successes, refusals := 0, 0
	for i := 0; i < 2; i++ {
		e := <-done
		if e == nil {
			successes++
		} else if errors.Is(e, ErrUnauthorized) {
			refusals++
		} else {
			t.Fatalf("concurrent managers produced a database failure instead of an authority decision: %v", e)
		}
	}
	if successes != 1 || refusals != 1 {
		t.Fatal("both concurrent authority changes escaped serial review", successes, refusals)
	}
}
