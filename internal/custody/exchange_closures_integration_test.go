//go:build integration

package custody_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/ctlplne/freightctl/internal/store"
)

func TestExchangeClosureStopsOpenReadersPreservesOtherViewsAndExactReceipts(t *testing.T) {
	for _, operation := range []string{"cancel", "decline"} {
		t.Run(operation, func(t *testing.T) {
			f := newExchangeFixture(t)
			file := actorFile(t, f, f.a, "closure-source", bytes.Repeat([]byte("inert-bytes\n"), 4096))
			r := exchangeRequest(file, f.endpoint)
			offer, err := f.service.OfferExchange(f.ctx, f.a, "first-view", r)
			if err != nil {
				t.Fatal(err)
			}
			other, err := f.service.OfferExchange(f.ctx, f.a, "second-view", r)
			if err != nil {
				t.Fatal(err)
			}
			_, reader, err := f.service.OpenExchangeReader(f.ctx, f.b, offer.Exchange.ID)
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			if n, err := reader.ReadAt(make([]byte, 1024), 0); err != nil || n != 1024 {
				t.Fatal("positive chunk", n, err)
			}
			actor, wrong := f.a, f.b
			if operation == "decline" {
				actor, wrong = f.b, f.a
			}
			command := store.ExchangeClosureCommand{Schema: 1, ID: offer.Exchange.ID, RequestHash: offer.Exchange.RequestHash, Operation: operation}
			for _, scope := range []store.Scope{wrong, f.other, f.fixture.b, f.fixture.c} {
				if _, err = f.db.CloseExchange(f.ctx, scope, "forbidden", command); err == nil {
					t.Fatal("wrong role/scope closed another view")
				}
			}
			changed := command
			changed.RequestHash = other.Exchange.RequestHash[:63] + "0"
			if changed.RequestHash == command.RequestHash {
				changed.RequestHash = other.Exchange.RequestHash[:63] + "1"
			}
			if _, err = f.db.CloseExchange(f.ctx, actor, "wrong-hash", changed); !errors.Is(err, store.ErrRevision) {
				t.Fatal("changed offer binding", err)
			}
			// A byte authorization in progress holds the shared view lock. A
			// cancellation cannot commit past it, then permits no later chunk.
			reading, err := f.db.Begin(f.ctx, f.b)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err = reading.AuthorizeIncomingExchange(f.ctx, offer.Exchange.ID, f.limits); err != nil {
				reading.Tx.Rollback(f.ctx)
				t.Fatal(err)
			}
			blocked, cancel := context.WithTimeout(f.ctx, 100*time.Millisecond)
			_, err = f.db.CloseExchange(blocked, actor, "close", command)
			cancel()
			reading.Tx.Rollback(f.ctx)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("cancellation did not wait at an active read grant until its deadline", err)
			}
			closed, err := f.db.CloseExchange(f.ctx, actor, "close", command)
			if err != nil || closed.Replayed || closed.ID != offer.Exchange.ID || closed.EventID == "" {
				t.Fatal("first terminal decision", err)
			}
			state := "canceled"
			if operation == "decline" {
				state = "declined"
			}
			if closed.State != state {
				t.Fatal("dishonest terminal state")
			}
			if n, err := reader.ReadAt(make([]byte, 1024), 1024); n != 0 || !errors.Is(err, store.ErrNotFound) {
				t.Fatal("closed open reader emitted bytes", n, err)
			}
			if _, err = f.service.InspectExchange(f.ctx, f.b, offer.Exchange.ID); !errors.Is(err, store.ErrNotFound) {
				t.Fatal("closed view disclosed live metadata", err)
			}
			page, err := f.db.IncomingExchanges(f.ctx, f.b, f.endpoint.ID, "", 20, f.limits)
			if err != nil || len(page.Exchanges) != 1 || page.Exchanges[0].ID != other.Exchange.ID {
				t.Fatal("closure affected a different offer", err)
			}
			replayed, err := f.db.CloseExchange(f.ctx, actor, "close", command)
			if err != nil || !replayed.Replayed || replayed.EventID != closed.EventID || replayed.CommandHash != closed.CommandHash {
				t.Fatal("response-loss replay changed decision", err)
			}
			changed = command
			changed.ID = other.Exchange.ID
			if _, err = f.db.CloseExchange(f.ctx, actor, "close", changed); !errors.Is(err, store.ErrConflict) {
				t.Fatal("key reused for another view", err)
			}
			if _, err = f.db.CloseExchange(f.ctx, actor, "new-key", command); !errors.Is(err, store.ErrState) {
				t.Fatal("second terminal decision accepted", err)
			}
			receipt, err := f.service.OfferExchange(f.ctx, f.a, "first-view", r)
			if err != nil || !receipt.Replayed || receipt.Exchange.ID != offer.Exchange.ID {
				t.Fatal("closure destroyed original publication receipt", err)
			}
			if _, reopened, err := f.service.OpenExchangeReader(f.ctx, f.b, receipt.Exchange.ID); err == nil {
				reopened.Close()
				t.Fatal("publication replay reopened closed view")
			}
			var decisions, events int
			if err = f.admin.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM artifact_exchange_closures WHERE tenant_id=$1 AND partner_id=$2),(SELECT count(*) FROM events WHERE tenant_id=$1 AND partner_id=$2 AND kind='ArtifactExchangeClosed')`, f.a.Tenant, f.a.Partner).Scan(&decisions, &events); err != nil || decisions != 1 || events != 1 {
				t.Fatal("closure/event/receipt not atomic", decisions, events, err)
			}
		})
	}
}

func TestExchangeClosureCanWithdrawAfterEndpointRevocationButNotActorRebinding(t *testing.T) {
	f := newExchangeFixture(t)
	file := actorFile(t, f, f.a, "withdraw-source", []byte("source"))
	offer, err := f.service.OfferExchange(f.ctx, f.a, "offer", exchangeRequest(file, f.endpoint))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.db.RegisterExchangeEndpoint(f.ctx, f.fixture.a, "revoke-endpoint", store.ExchangeEndpointCommand{Operation: "revoke", ID: f.endpoint.ID, ExpectedRevision: 1}, f.limits, 16); err != nil {
		t.Fatal(err)
	}
	command := store.ExchangeClosureCommand{Schema: 1, ID: offer.Exchange.ID, RequestHash: offer.Exchange.RequestHash, Operation: "cancel"}
	closed, err := f.db.CloseExchange(f.ctx, f.a, "withdraw", command)
	if err != nil || closed.State != "canceled" {
		t.Fatal("revoked destination prevented withdrawal", err)
	}
	if _, err = f.db.ChangeAccount(f.ctx, f.fixture.a, "rename-sender-label", store.AccountCommand{Operation: "update", ID: f.actorA.Actor, ExpectedRevision: 1, Policy: &store.AccountPolicy{Label: "Renamed sender", Root: "/", Permissions: []string{"read", "write", "list", "deliver"}}}); err != nil {
		t.Fatal(err)
	}
	current, err := f.db.Identity(f.ctx, f.a)
	if err != nil || current.AuthorityRevision != f.actorA.AuthorityRevision {
		t.Fatal("label-only update changed authority", err)
	}
	labelReplay, err := f.db.CloseExchange(f.ctx, f.a, "withdraw", command)
	if err != nil || !labelReplay.Replayed || labelReplay.ID != closed.ID || labelReplay.State != closed.State || labelReplay.CommandHash != closed.CommandHash || labelReplay.EventID != closed.EventID {
		t.Fatal("label-only update erased exact closure receipt", err)
	}
	// Remove an unrelated write grant while preserving read/deliver,so the
	// original refusal exercises authority rebinding rather than a missing role.
	if _, err = f.db.ChangeAccount(f.ctx, f.fixture.a, "rebind-sender", store.AccountCommand{Operation: "update", ID: f.actorA.Actor, ExpectedRevision: 2, Policy: &store.AccountPolicy{Label: "Changed authority", Root: "/", Permissions: []string{"read", "list", "deliver"}}}); err != nil {
		t.Fatal(err)
	}
	current, err = f.db.Identity(f.ctx, f.a)
	if err != nil || current.AuthorityRevision != f.actorA.AuthorityRevision+1 {
		t.Fatal("fixture did not change actual sender authority", err)
	}
	if _, err = f.db.CloseExchange(f.ctx, f.a, "withdraw", command); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("new actor authority reused an old closure receipt", err)
	}
	tx, err := f.db.Begin(f.ctx, f.a)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Tx.Rollback(f.ctx)
	for _, table := range []string{"artifact_exchange_closures", "artifact_exchange_closure_commands"} {
		var count int
		if err = tx.Tx.QueryRow(f.ctx, `SELECT count(*) FROM `+table+` WHERE exchange_id=$1`, command.ID).Scan(&count); err != nil || count != 0 {
			t.Fatal("rebound actor read historical closure metadata/key through RLS", table, count, err)
		}
	}
}

func TestExchangeClosureSQLRefusesForgedRoleOrOrphanEventAndKeepsDecisionImmutable(t *testing.T) {
	f := newExchangeFixture(t)
	file := actorFile(t, f, f.a, "sql-source", []byte("private"))
	offer, err := f.service.OfferExchange(f.ctx, f.a, "sql-offer", exchangeRequest(file, f.endpoint))
	if err != nil {
		t.Fatal(err)
	}
	command := store.ExchangeClosureCommand{Schema: 1, ID: offer.Exchange.ID, RequestHash: offer.Exchange.RequestHash, Operation: "cancel"}
	_, hash, err := store.CanonicalExchangeClosure(command)
	if err != nil {
		t.Fatal(err)
	}
	// The recipient can see the offer and write an event, but cannot forge a
	// sender's cancel operation by constructing a perfectly matching payload.
	tx, err := f.db.Begin(f.ctx, f.b)
	if err != nil {
		t.Fatal(err)
	}
	event, err := tx.Append(f.ctx, "ArtifactExchangeClosed", command.ID, map[string]any{"command": command, "command_hash": hash, "request_key": "forged-role", "participant": f.actorB})
	if err != nil {
		tx.Tx.Rollback(f.ctx)
		t.Fatal("forgery did not reach intended SQL boundary", err)
	}
	binding, err := json.Marshal(f.actorB)
	if err != nil {
		tx.Tx.Rollback(f.ctx)
		t.Fatal(err)
	}
	_, err = tx.Tx.Exec(f.ctx, `INSERT INTO artifact_exchange_closures(tenant_id,partner_id,exchange_id,actor_id,request_hash,operation,command_hash,participant,event_id) VALUES($1,$2,$3,$4,$5,'cancel',$6,$7,$8)`, f.b.Tenant, f.b.Partner, command.ID, f.actorB.Actor, command.RequestHash, hash, binding, event)
	tx.Tx.Rollback(f.ctx)
	if err == nil {
		t.Fatal("matching journal payload bypassed independent SQL role check")
	}
	tx, err = f.db.Begin(f.ctx, f.a)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Append(f.ctx, "ArtifactExchangeClosed", command.ID, map[string]any{"command": command, "command_hash": hash, "request_key": "orphan", "participant": f.actorA}); err != nil {
		tx.Tx.Rollback(f.ctx)
		t.Fatal(err)
	}
	if err = tx.Tx.Commit(f.ctx); err == nil {
		t.Fatal("orphan closure event committed without decision/receipt")
	}
	// A valid decision row and exact event still need the actor-key receipt.
	tx, err = f.db.Begin(f.ctx, f.a)
	if err != nil {
		t.Fatal(err)
	}
	event, err = tx.Append(f.ctx, "ArtifactExchangeClosed", command.ID, map[string]any{"command": command, "command_hash": hash, "request_key": "missing-receipt", "participant": f.actorA})
	if err != nil {
		tx.Tx.Rollback(f.ctx)
		t.Fatal(err)
	}
	binding, err = json.Marshal(f.actorA)
	if err != nil {
		tx.Tx.Rollback(f.ctx)
		t.Fatal(err)
	}
	_, err = tx.Tx.Exec(f.ctx, `INSERT INTO artifact_exchange_closures(tenant_id,partner_id,exchange_id,actor_id,request_hash,operation,command_hash,participant,event_id) VALUES($1,$2,$3,$4,$5,'cancel',$6,$7,$8)`, f.a.Tenant, f.a.Partner, command.ID, f.actorA.Actor, command.RequestHash, hash, binding, event)
	if err != nil {
		tx.Tx.Rollback(f.ctx)
		t.Fatal("valid decision fixture failed before the missing-receipt boundary", err)
	}
	if err = tx.Tx.Commit(f.ctx); err == nil {
		t.Fatal("decision committed without its actor-private receipt")
	}
	if _, err = f.db.CloseExchange(f.ctx, f.a, "real-decision", command); err != nil {
		t.Fatal(err)
	}
	tx, err = f.db.Begin(f.ctx, f.b)
	if err != nil {
		t.Fatal(err)
	}
	var publicDecision, privateCommand int
	err = tx.Tx.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM artifact_exchange_closures WHERE exchange_id=$1),(SELECT count(*) FROM artifact_exchange_closure_commands WHERE exchange_id=$1)`, command.ID).Scan(&publicDecision, &privateCommand)
	tx.Tx.Rollback(f.ctx)
	if err != nil || publicDecision != 1 || privateCommand != 0 {
		t.Fatal("counterpart could read sender's original operation key or lost closure visibility", publicDecision, privateCommand, err)
	}
	for _, attack := range []string{`UPDATE artifact_exchange_closures SET operation='decline' WHERE exchange_id=$1`, `DELETE FROM artifact_exchange_closures WHERE exchange_id=$1`} {
		tx, err = f.db.Begin(f.ctx, f.a)
		if err != nil {
			t.Fatal(err)
		}
		_, err = tx.Tx.Exec(f.ctx, attack, command.ID)
		tx.Tx.Rollback(f.ctx)
		if err == nil {
			t.Fatal("runtime writer changed immutable terminal decision")
		}
	}
	for _, scope := range []store.Scope{f.other, f.fixture.b, f.fixture.c} {
		tx, err = f.db.Begin(f.ctx, scope)
		if err != nil {
			t.Fatal(err)
		}
		var count int
		err = tx.Tx.QueryRow(f.ctx, `SELECT count(*) FROM artifact_exchange_closures WHERE exchange_id=$1`, command.ID).Scan(&count)
		tx.Tx.Rollback(f.ctx)
		if err != nil || count != 0 {
			t.Fatal("closure RLS exposed another participant/scope", count, err)
		}
	}
	var decisions, events int
	if err = f.admin.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM artifact_exchange_closures WHERE tenant_id=$1 AND partner_id=$2),(SELECT count(*) FROM events WHERE tenant_id=$1 AND partner_id=$2 AND kind='ArtifactExchangeClosed')`, f.a.Tenant, f.a.Partner).Scan(&decisions, &events); err != nil || decisions != 1 || events != 1 {
		t.Fatal("forgery/orphan left domain effects", decisions, events, err)
	}
}
