//go:build integration

package custody_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/ctlplne/freightctl/internal/checks"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestExchangeEvidenceUsesOriginalAuthorityAndCreatesNoDomainEffects(t *testing.T) {
	f := newExchangeFixture(t)
	file := actorFile(t, f, f.a, "trace-source", []byte("inert trace source\n"))
	request := exchangeRequest(file, f.endpoint)
	offer, err := f.service.OfferExchange(f.ctx, f.a, "trace-offer", request)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := func() [4]int {
		t.Helper()
		tx, err := f.db.Begin(f.ctx, f.a)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Tx.Rollback(f.ctx)
		var counts [4]int
		if err = tx.Tx.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM events),(SELECT count(*) FROM artifact_exchanges),(SELECT count(*) FROM artifact_exchange_commands),(SELECT count(*) FROM delivery_intents)`).Scan(&counts[0], &counts[1], &counts[2], &counts[3]); err != nil {
			t.Fatal(err)
		}
		return counts
	}
	read := func(scope store.Scope, direction string) *store.ExchangeTrace {
		t.Helper()
		v, err := f.service.TraceExchange(f.ctx, scope, store.ExchangeTraceRequest{ID: offer.Exchange.ID, Direction: direction})
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	before := snapshot()
	if before[1] != 1 || before[2] != 1 {
		t.Fatal("snapshot did not observe the original sender's own view/receipt")
	}
	for _, v := range []*store.ExchangeTrace{read(f.a, "outgoing"), read(f.b, "incoming"), read(f.b, "incoming")} {
		if v.Profile != "authorized-exchange-evidence-v1" || v.State != "offered" || v.Details != "authorized-records" || v.Artifact == nil || *v.Artifact != request.Artifact || v.RequestHash != offer.Exchange.RequestHash || len(v.Events) != 2 || v.Events[0].ID != file.EventID || v.Events[0].Resource != file.ID || v.Events[1].ID != offer.Exchange.EventID || v.Events[1].Resource != offer.Exchange.ID || v.CheckedAt.IsZero() || v.StorageVerification != "not-checked" || v.Retrieval != "unknown" || v.ReceiverPersistence != "unknown" || v.BusinessProcessing != "unknown" {
			t.Fatal("evidence changed bindings or claimed stronger outcomes")
		}
		tx, err := f.db.Begin(f.ctx, f.fixture.a)
		if err != nil {
			t.Fatal(err)
		}
		var accepted, offered time.Time
		err = tx.Tx.QueryRow(f.ctx, `SELECT (SELECT happened_at FROM events WHERE event_id=$1),(SELECT happened_at FROM events WHERE event_id=$2)`, file.EventID, offer.Exchange.EventID).Scan(&accepted, &offered)
		tx.Tx.Rollback(f.ctx)
		if err != nil || !accepted.Equal(v.Events[0].At) || !offered.Equal(v.Events[1].At) {
			t.Fatal("projected event time differs from immutable source", err)
		}
		wire, _ := json.Marshal(v)
		if bytes.Contains(wire, []byte(f.service.Disk.Identity())) || bytes.Contains(wire, []byte("inert trace source")) || bytes.Contains(wire, []byte("payload")) {
			t.Fatal("evidence exposed private bytes/storage/event data")
		}
	}
	for _, pair := range []struct {
		scope     store.Scope
		direction string
	}{{f.other, "incoming"}, {f.other, "outgoing"}, {f.b, "outgoing"}, {f.a, "incoming"}, {f.fixture.b, "incoming"}, {f.fixture.c, "incoming"}} {
		if _, err = f.service.TraceExchange(f.ctx, pair.scope, store.ExchangeTraceRequest{ID: offer.Exchange.ID, Direction: pair.direction}); err == nil {
			t.Fatal("evidence bypassed original actor or scope")
		}
	}
	if snapshot() != before {
		t.Fatal("evidence read wrote events,views,receipts or intents")
	}
	closed, err := f.db.CloseExchange(f.ctx, f.a, "trace-close", store.ExchangeClosureCommand{Schema: 1, ID: offer.Exchange.ID, RequestHash: offer.Exchange.RequestHash, Operation: "cancel"})
	if err != nil {
		t.Fatal(err)
	}
	before = snapshot()
	v := read(f.a, "outgoing")
	if v.State != "canceled" || len(v.Events) != 3 || v.Events[2].Kind != "view-canceled" || v.Events[2].ID != closed.EventID {
		t.Fatal("original closure evidence lost")
	}
	if _, err = f.service.TraceExchange(f.ctx, f.b, store.ExchangeTraceRequest{ID: offer.Exchange.ID, Direction: "incoming"}); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("closed incoming evidence bypassed ordinary view refusal", err)
	}
	if snapshot() != before {
		t.Fatal("historical evidence minted another receipt")
	}
}

func TestExchangeEvidenceKeepsPolicyHeldViewsOpaqueAndRechecksRevocation(t *testing.T) {
	f := newExchangeFixture(t)
	file := actorFile(t, f, f.a, "trace-held-source", []byte("record\nvalue\n"))
	offer, err := f.service.OfferExchange(f.ctx, f.a, "trace-held-offer", exchangeRequest(file, f.endpoint))
	if err != nil {
		t.Fatal(err)
	}
	checking := &checks.Service{Custody: f.service}
	if _, err = checking.Register(f.ctx, f.fixture.a, "trace-policy", checks.PolicyRequest{Definition: checks.Policy{Schema: 1, Kind: "csv", Columns: []checks.Column{{Name: "record", Type: "text", Required: true}}}}); err != nil {
		t.Fatal(err)
	}
	v, err := f.service.TraceExchange(f.ctx, f.b, store.ExchangeTraceRequest{ID: offer.Exchange.ID, Direction: "incoming"})
	if err != nil || v.State != "held" || v.Details != "opaque" || v.Artifact != nil || v.RequestHash != "" || v.ReplyTo != "" || len(v.Events) != 0 {
		t.Fatal("held evidence disclosed immutable details", err)
	}
	wire, _ := json.Marshal(v)
	if bytes.Contains(wire, []byte(file.ID)) || bytes.Contains(wire, []byte(file.SHA256)) || bytes.Contains(wire, []byte(file.EventID)) {
		t.Fatal("opaque trace exposed source identity/event")
	}
	out, err := f.service.TraceExchange(f.ctx, f.a, store.ExchangeTraceRequest{ID: offer.Exchange.ID, Direction: "outgoing"})
	if err != nil || out.State != "held" || out.Artifact == nil || len(out.Events) != 2 {
		t.Fatal("sender original history was erased by a hold", err)
	}
	account, err := f.db.Account(f.ctx, f.fixture.a, f.actorB.Actor)
	if err != nil {
		t.Fatal(err)
	}
	policy := account.AccountPolicy
	policy.Permissions = []string{"list"}
	if _, err = f.db.ChangeAccount(f.ctx, f.fixture.a, "trace-revoke-read", store.AccountCommand{Operation: "update", ID: f.actorB.Actor, ExpectedRevision: account.Revision, Policy: &policy}); err != nil {
		t.Fatal(err)
	}
	if _, err = f.service.TraceExchange(f.ctx, f.b, store.ExchangeTraceRequest{ID: offer.Exchange.ID, Direction: "incoming"}); err == nil {
		t.Fatal("revoked identity read old evidence")
	}
	out, err = f.service.TraceExchange(f.ctx, f.a, store.ExchangeTraceRequest{ID: offer.Exchange.ID, Direction: "outgoing"})
	if err != nil || out.State != "unavailable" || out.RequestHash != offer.Exchange.RequestHash {
		t.Fatal("recipient revocation changed original sender receipt", err)
	}
}
