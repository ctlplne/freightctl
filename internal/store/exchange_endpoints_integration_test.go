//go:build integration

package store

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
)

func endpointParticipant(t *testing.T, f *browserFixture, permissions []string) (ExchangeParticipant, Scope) {
	t.Helper()
	id, proof := secure.NewID(), secure.Digest([]byte(secure.NewID()))
	_, err := f.db.ChangeAccount(f.ctx, f.scope, "create-"+id, AccountCommand{Operation: "create", ID: id, CredentialHash: proof, Policy: &AccountPolicy{Label: "Exchange participant", Permissions: permissions, Root: "/"}})
	if err != nil {
		t.Fatal(err)
	}
	scope := Scope{Tenant: f.scope.Tenant, Partner: f.scope.Partner, TokenHash: proof}
	identity, err := f.db.Identity(f.ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	return ExchangeParticipant{Tenant: scope.Tenant, Partner: scope.Partner, Actor: identity.Actor, AuthorityRevision: identity.AuthorityRevision, RootPolicyDigest: identity.RootPolicyDigest}, scope
}

func currentEndpoint(t *testing.T, f *browserFixture, scope Scope, id string) (*ExchangeEndpointVersion, error) {
	t.Helper()
	tx, err := f.db.Begin(f.ctx, scope)
	if err != nil {
		return nil, err
	}
	defer tx.Tx.Rollback(f.ctx)
	return tx.CurrentExchangeEndpoint(f.ctx, id)
}

func TestExchangeEndpointRegistrationCurrentHeadAndReceipts(t *testing.T) {
	f := newBrowserFixture(t)
	a, scopeA := endpointParticipant(t, f, []string{"read", "deliver"})
	b, scopeB := endpointParticipant(t, f, []string{"read", "list"})
	c, scopeC := endpointParticipant(t, f, []string{"read", "deliver"})
	limits := ExchangeLimits{MaxArtifactBytes: 1 << 20, MaxLifetime: time.Hour, MaxSenders: 16}
	definition := ExchangeEndpointDefinition{Schema: 1, Profile: "custody-https-poll-v1", Recipient: b, Senders: []ExchangeParticipant{a}}
	create := ExchangeEndpointCommand{Operation: "create", ID: secure.NewID(), Definition: &definition}
	first, err := f.db.RegisterExchangeEndpoint(f.ctx, f.scope, "endpoint-create", create, limits, 2)
	if err != nil || first.Replayed || first.Endpoint.Revision != 1 {
		t.Fatal("first registration", err)
	}
	if _, err = currentEndpoint(t, f, scopeA, create.ID); err != nil {
		t.Fatal("allowed sender cannot resolve current view", err)
	}
	if _, err = currentEndpoint(t, f, scopeB, create.ID); err != nil {
		t.Fatal("recipient cannot resolve current view", err)
	}
	if _, err = currentEndpoint(t, f, scopeC, create.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("unrelated participant learned endpoint", err)
	}
	if _, err = f.db.RegisterExchangeEndpoint(f.ctx, scopeA, "sender-register", create, limits, 2); !errors.Is(err, ErrForbidden) {
		t.Fatal("sender gained registration authority", err)
	}
	definition.Senders = []ExchangeParticipant{c}
	replace := ExchangeEndpointCommand{Operation: "replace", ID: create.ID, ExpectedRevision: 1, Definition: &definition}
	second, err := f.db.RegisterExchangeEndpoint(f.ctx, f.scope, "endpoint-replace", replace, limits, 2)
	if err != nil || second.Endpoint.Revision != 2 {
		t.Fatal("endpoint replacement", err)
	}
	// Historical visibility cannot be used as proof of current permission.
	old, err := f.db.Begin(f.ctx, scopeA)
	if err != nil {
		t.Fatal(err)
	}
	var historical int
	err = old.Tx.QueryRow(f.ctx, `SELECT count(*) FROM exchange_endpoint_versions WHERE endpoint_id=$1`, create.ID).Scan(&historical)
	if err != nil || historical != 1 {
		t.Fatal("historical fixture did not retain original version", err)
	}
	if _, err = old.CurrentExchangeEndpoint(f.ctx, create.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("removed sender's old visible version became the current endpoint", err)
	}
	old.Tx.Rollback(f.ctx)
	if current, err := currentEndpoint(t, f, scopeC, create.ID); err != nil || current.Revision != 2 {
		t.Fatal("new sender current binding", err)
	}
	revoke := ExchangeEndpointCommand{Operation: "revoke", ID: create.ID, ExpectedRevision: 2}
	third, err := f.db.RegisterExchangeEndpoint(f.ctx, f.scope, "endpoint-revoke", revoke, limits, 2)
	if err != nil || third.Endpoint.Revision != 3 || third.Endpoint.State != "revoked" {
		t.Fatal("endpoint revocation", err)
	}
	// Restore original command bytes; changing the local definition pointer is
	// not allowed to change the committed retry receipt.
	definition.Senders = []ExchangeParticipant{a}
	replay, err := f.db.RegisterExchangeEndpoint(f.ctx, f.scope, "endpoint-create", create, limits, 2)
	if err != nil || !replay.Replayed || replay.Endpoint.EventID != first.Endpoint.EventID {
		t.Fatal("original response-loss receipt lost", err)
	}
	if current, err := currentEndpoint(t, f, f.scope, create.ID); err != nil || current.Revision != 3 || current.State != "revoked" {
		t.Fatal("historical retry reactivated endpoint", err)
	}
	definition.Senders[0].AuthorityRevision++
	if _, err = f.db.RegisterExchangeEndpoint(f.ctx, f.scope, "endpoint-create", create, limits, 2); !errors.Is(err, ErrConflict) {
		t.Fatal("changed retry meaning accepted", err)
	}
	revoke.ExpectedRevision = 3
	if _, err = f.db.RegisterExchangeEndpoint(f.ctx, f.scope, "endpoint-resurrect", revoke, limits, 2); !errors.Is(err, ErrState) {
		t.Fatal("revoked endpoint changed", err)
	}
	admin, err := connect(f.ctx, f.adminPath)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	for table, want := range map[string]int{"exchange_endpoint_versions": 3, "exchange_endpoint_commands": 3, "exchange_endpoint_heads": 1} {
		var count int
		if err = admin.QueryRow(f.ctx, `SELECT count(*) FROM `+table+` WHERE tenant_id=$1 AND partner_id=$2 AND endpoint_id=$3`, f.scope.Tenant, f.scope.Partner, create.ID).Scan(&count); err != nil || count != want {
			t.Fatal("non-atomic retry/projection", table, count, err)
		}
	}
}

func TestExchangeEndpointRefusesStaleAndWrongScopeParticipants(t *testing.T) {
	f := newBrowserFixture(t)
	a, _ := endpointParticipant(t, f, []string{"read", "deliver"})
	b, scopeB := endpointParticipant(t, f, []string{"read", "list"})
	limits := ExchangeLimits{MaxArtifactBytes: 1 << 20, MaxLifetime: time.Hour, MaxSenders: 16}
	definition := ExchangeEndpointDefinition{Schema: 1, Profile: "custody-https-poll-v1", Recipient: b, Senders: []ExchangeParticipant{a}}
	command := ExchangeEndpointCommand{Operation: "create", ID: secure.NewID(), Definition: &definition}
	if _, err := f.db.RegisterExchangeEndpoint(f.ctx, f.scope, "endpoint-create", command, limits, 2); err != nil {
		t.Fatal(err)
	}
	proof := secure.Digest([]byte(secure.NewID()))
	if _, err := f.db.ChangeAccount(f.ctx, f.scope, "rotate-recipient", AccountCommand{Operation: "rotate", ID: b.Actor, ExpectedRevision: 1, CredentialHash: proof}); err != nil {
		t.Fatal(err)
	}
	scopeB.TokenHash = proof
	if _, err := currentEndpoint(t, f, scopeB, command.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("rotated recipient kept stale receive binding", err)
	}
	command.ID = secure.NewID()
	if _, err := f.db.RegisterExchangeEndpoint(f.ctx, f.scope, "stale-recipient", command, limits, 2); !errors.Is(err, ErrNotFound) {
		t.Fatal("stale binding registered", err)
	}
	for _, wrong := range []string{"tenant", "partner"} {
		definition.Recipient = b
		definition.Senders = []ExchangeParticipant{a}
		if wrong == "tenant" {
			definition.Recipient.Tenant = secure.NewID()
			definition.Senders[0].Tenant = definition.Recipient.Tenant
		} else {
			definition.Recipient.Partner = secure.NewID()
			definition.Senders[0].Partner = definition.Recipient.Partner
		}
		if _, err := f.db.RegisterExchangeEndpoint(f.ctx, f.scope, "wrong-"+wrong, command, limits, 2); !errors.Is(err, ErrNotFound) {
			t.Fatal("wrong-scope identities registered", err)
		}
	}
}

func TestExchangeEndpointSQLRequiresCompleteJournalReceiptAndCurrentHead(t *testing.T) {
	f := newBrowserFixture(t)
	a, _ := endpointParticipant(t, f, []string{"read", "deliver"})
	b, _ := endpointParticipant(t, f, []string{"read", "list"})
	limits := ExchangeLimits{MaxArtifactBytes: 1 << 20, MaxLifetime: time.Hour, MaxSenders: 16}
	definition, hash, err := CanonicalExchangeEndpoint(ExchangeEndpointDefinition{Schema: 1, Profile: "custody-https-poll-v1", Recipient: b, Senders: []ExchangeParticipant{a}}, limits)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.db.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Tx.Rollback(f.ctx)
	e := ExchangeEndpointVersion{ID: secure.NewID(), Revision: 1, Definition: definition, Hash: hash, State: "active", RecordedBy: tx.Actor}
	e.EventID, err = tx.Append(f.ctx, "ExchangeEndpointRecorded", e.ID, e)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Tx.Exec(f.ctx, `INSERT INTO exchange_endpoint_versions(tenant_id,partner_id,endpoint_id,revision,definition,definition_wire,definition_hash,state,recorded_by,event_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, f.scope.Tenant, f.scope.Partner, e.ID, e.Revision, e.Definition, string(e.Definition), e.Hash, e.State, e.RecordedBy, e.EventID)
	if err != nil {
		t.Fatal("first exact version/projection fixture failed before missing-receipt boundary", err)
	}
	if err = tx.Tx.Commit(f.ctx); err == nil {
		t.Fatal("orphan endpoint projection committed without receipt")
	}
	check, err := f.db.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	defer check.Tx.Rollback(f.ctx)
	var count int
	if err = check.Tx.QueryRow(f.ctx, `SELECT count(*) FROM exchange_endpoint_versions WHERE endpoint_id=$1`, e.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("failed transaction left a version", count, err)
	}
	if err = check.Tx.QueryRow(f.ctx, `SELECT count(*) FROM exchange_endpoint_heads WHERE endpoint_id=$1`, e.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("failed transaction left a current head", count, err)
	}
	if err = check.Tx.QueryRow(f.ctx, `SELECT count(*) FROM events WHERE event_id=$1`, e.EventID).Scan(&count); err != nil || count != 0 {
		t.Fatal("failed transaction left journal acceptance", count, err)
	}
	// Even a syntactically valid event cannot claim a missing domain mutation.
	if _, err = check.Append(f.ctx, "ExchangeEndpointCommandCompleted", secure.NewID(), json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err = check.Tx.Commit(f.ctx); err == nil {
		t.Fatal("orphan typed receipt event committed")
	}
}

func TestExchangeEndpointRLSAndForgedHeadRefuseRuntimeWriter(t *testing.T) {
	f := newBrowserFixture(t)
	a, scopeA := endpointParticipant(t, f, []string{"read", "deliver"})
	b, _ := endpointParticipant(t, f, []string{"read", "list"})
	limits := ExchangeLimits{MaxArtifactBytes: 1 << 20, MaxLifetime: time.Hour, MaxSenders: 16}
	d := ExchangeEndpointDefinition{Schema: 1, Profile: "custody-https-poll-v1", Recipient: b, Senders: []ExchangeParticipant{a}}
	c := ExchangeEndpointCommand{Operation: "create", ID: secure.NewID(), Definition: &d}
	created, err := f.db.RegisterExchangeEndpoint(f.ctx, f.scope, "registered", c, limits, 2)
	if err != nil {
		t.Fatal(err)
	}
	for _, attack := range []string{
		`UPDATE exchange_endpoint_heads SET revision=revision+1 WHERE endpoint_id=$1`,
		`UPDATE exchange_endpoint_heads SET state='revoked' WHERE endpoint_id=$1`,
		`DELETE FROM exchange_endpoint_heads WHERE endpoint_id=$1`,
		`UPDATE exchange_endpoint_versions SET state='revoked' WHERE endpoint_id=$1`,
	} {
		tx, err := f.db.Begin(f.ctx, f.scope)
		if err != nil {
			t.Fatal(err)
		}
		_, err = tx.Tx.Exec(f.ctx, attack, c.ID)
		tx.Tx.Rollback(f.ctx)
		if err == nil {
			t.Fatal("runtime writer forged or removed journal projection")
		}
	}
	tx, err := f.db.Begin(f.ctx, scopeA)
	if err != nil {
		t.Fatal(err)
	}
	e := created.Endpoint
	e.ID, e.RecordedBy, e.EventID = secure.NewID(), a.Actor, ""
	e.EventID, err = tx.Append(f.ctx, "ExchangeEndpointRecorded", e.ID, e)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Tx.Exec(f.ctx, `INSERT INTO exchange_endpoint_versions(tenant_id,partner_id,endpoint_id,revision,definition,definition_wire,definition_hash,state,recorded_by,event_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, f.scope.Tenant, f.scope.Partner, e.ID, e.Revision, e.Definition, string(e.Definition), e.Hash, e.State, e.RecordedBy, e.EventID)
	tx.Tx.Rollback(f.ctx)
	if err == nil {
		t.Fatal("sender forged administrator registration with matching event")
	}
	for _, setting := range []string{"freightctl.tenant_id", "freightctl.partner_id"} {
		tx, err := f.db.Begin(f.ctx, f.scope)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Tx.Exec(f.ctx, `SELECT set_config($1,$2,true)`, setting, secure.NewID()); err != nil {
			t.Fatal(err)
		}
		for _, table := range []string{"exchange_endpoint_versions", "exchange_endpoint_commands", "exchange_endpoint_heads"} {
			var count int
			if err = tx.Tx.QueryRow(f.ctx, `SELECT count(*) FROM `+table).Scan(&count); err != nil || count != 0 {
				t.Fatal("runtime role disclosed wrong-scope endpoint records", table, count, err)
			}
		}
		tx.Tx.Rollback(f.ctx)
	}
	current, err := currentEndpoint(t, f, f.scope, c.ID)
	if err != nil || current.Revision != 1 || current.State != "active" {
		t.Fatal("rejected SQL attack changed current endpoint", err)
	}
}
