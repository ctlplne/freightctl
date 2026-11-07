//go:build integration

package custody_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/freightctl/internal/checks"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestOutgoingExchangeHistoryKeepsReceiptAndStateSeparateWithoutReceiverClaims(t *testing.T) {
	f := newExchangeFixture(t)
	// Three independent histories exercise open/canceled/declined states. This
	// fixture setting does not change the standard two-slot admission tests.
	f.service.Exchanges.MaxOpenViews = 4
	file := actorFile(t, f, f.a, "history-source", []byte("row\nvalue\n"))
	r := exchangeRequest(file, f.endpoint)
	r.ExpiresAt = time.Now().UTC().Add(30 * time.Minute).Truncate(time.Microsecond)
	wanted := map[string]string{}
	var open *store.ArtifactExchangeResult
	for _, key := range []string{"open", "cancel", "decline"} {
		offer, err := f.service.OfferExchange(f.ctx, f.a, key, r)
		if err != nil {
			t.Fatal(err)
		}
		wanted[offer.Exchange.ID] = "offered"
		if key == "open" {
			open = offer
			continue
		}
		actor := f.a
		state := "canceled"
		if key == "decline" {
			actor = f.b
			state = "declined"
		}
		if _, err = f.db.CloseExchange(f.ctx, actor, "close-"+key, store.ExchangeClosureCommand{Schema: 1, ID: offer.Exchange.ID, RequestHash: offer.Exchange.RequestHash, Operation: key}); err != nil {
			t.Fatal(err)
		}
		wanted[offer.Exchange.ID] = state
	}
	seen := map[string]bool{}
	after := ""
	for {
		page, err := f.db.OutgoingExchanges(f.ctx, f.a, after, 1)
		if err != nil || len(page.Exchanges) != 1 {
			t.Fatal("history page", err)
		}
		row := page.Exchanges[0]
		id := row.Exchange.ID
		if seen[id] || row.State != wanted[id] || row.Exchange.RequestHash != open.Exchange.RequestHash || row.Retrieval != "unknown" || row.ReceiverPersistence != "unknown" || row.BusinessProcessing != "unknown" || row.CheckedAt.IsZero() || row.Tenant != f.a.Tenant || row.Partner != f.a.Partner {
			t.Fatal("history changed receipt meaning or inferred a receiver outcome")
		}
		if (row.State == "canceled" || row.State == "declined") != (row.ClosureEvent != "") {
			t.Fatal("terminal state lost exact event binding")
		}
		wire, err := json.Marshal(row)
		if err != nil || strings.Contains(string(wire), f.service.Disk.Identity()) || strings.Contains(string(wire), "request_key") {
			t.Fatal("history disclosed custody or private operation key", err)
		}
		seen[id] = true
		if page.Next == "" {
			break
		}
		if page.Next != id || page.Next <= after {
			t.Fatal("unauthorized or reordered cursor")
		}
		after = page.Next
	}
	if len(seen) != 3 {
		t.Fatal("history lost original records")
	}
	for _, scope := range []store.Scope{f.other, f.fixture.b, f.fixture.c} {
		page, err := f.db.OutgoingExchanges(f.ctx, scope, "", 20)
		if err != nil || len(page.Exchanges) != 0 || page.Next != "" {
			t.Fatal("wrong actor/scope history disclosure", err)
		}
		if _, err = f.db.OutgoingExchange(f.ctx, scope, open.Exchange.ID); !errors.Is(err, store.ErrNotFound) {
			t.Fatal("wrong actor/scope inspected history", err)
		}
	}
	if _, err := f.db.OutgoingExchanges(f.ctx, f.b, "", 20); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("receive-only role gained sending history", err)
	}
	// New definition quotas cannot hide or revoke already admitted exact grants.
	f.service.Exchanges.MaxSenders = 1
	if _, err := f.db.OutgoingExchange(f.ctx, f.a, open.Exchange.ID); err != nil {
		t.Fatal("admission change hid existing receipt", err)
	}
	_, reader, err := f.service.OpenExchangeReader(f.ctx, f.b, open.Exchange.ID)
	if err != nil {
		t.Fatal("admission change revoked unchanged view", err)
	}
	if n, err := reader.ReadAt(make([]byte, 4), 0); err != nil || n != 4 {
		reader.Close()
		t.Fatal("old view bounded read", n, err)
	}
	reader.Close()
	replayed, err := f.service.OfferExchange(f.ctx, f.a, "open", r)
	if err != nil || !replayed.Replayed || replayed.Exchange.ID != open.Exchange.ID {
		t.Fatal("new-definition cap broke exact receipt replay", err)
	}
	lower := f.limits
	lower.MaxSenders = 1
	definition := store.ExchangeEndpointDefinition{Schema: 1, Profile: "custody-https-poll-v1", Recipient: f.actorB, Senders: []store.ExchangeParticipant{f.actorA, f.actorOther}}
	if _, err = f.db.RegisterExchangeEndpoint(f.ctx, f.fixture.a, "too-many-new", store.ExchangeEndpointCommand{Operation: "create", ID: secure.NewID(), Definition: &definition}, lower, 16); !errors.Is(err, store.ErrExchangeInput) {
		t.Fatal("new definition admission was weakened", err)
	}
	checking := &checks.Service{Custody: f.service}
	if _, err = checking.Register(f.ctx, f.fixture.a, "history-policy", checks.PolicyRequest{Definition: checks.Policy{Schema: 1, Kind: "csv", Columns: []checks.Column{{Name: "row", Type: "text", Required: true}}}}); err != nil {
		t.Fatal(err)
	}
	held, err := f.db.OutgoingExchange(f.ctx, f.a, open.Exchange.ID)
	if err != nil || held.State != "held" {
		t.Fatal("history ignored current intake hold", err)
	}
	if _, err = f.db.RegisterExchangeEndpoint(f.ctx, f.fixture.a, "revoke-history-endpoint", store.ExchangeEndpointCommand{Operation: "revoke", ID: f.endpoint.ID, ExpectedRevision: 1}, lower, 16); err != nil {
		t.Fatal(err)
	}
	unavailable, err := f.db.OutgoingExchange(f.ctx, f.a, open.Exchange.ID)
	if err != nil || unavailable.State != "unavailable" {
		t.Fatal("historical receipt became a live endpoint grant", err)
	}
	if _, err = f.db.ChangeAccount(f.ctx, f.fixture.a, "history-label-change", store.AccountCommand{Operation: "update", ID: f.actorA.Actor, ExpectedRevision: 1, Policy: &store.AccountPolicy{Label: "Renamed history sender", Root: "/", Permissions: []string{"read", "write", "list", "deliver"}}}); err != nil {
		t.Fatal(err)
	}
	current, err := f.db.Identity(f.ctx, f.a)
	if err != nil || current.AuthorityRevision != f.actorA.AuthorityRevision {
		t.Fatal("label-only history update changed authority", err)
	}
	labelView, err := f.db.OutgoingExchange(f.ctx, f.a, open.Exchange.ID)
	if err != nil || labelView.State != unavailable.State || labelView.Exchange.ID != unavailable.Exchange.ID || labelView.Exchange.RequestHash != unavailable.Exchange.RequestHash || labelView.Exchange.EventID != unavailable.Exchange.EventID {
		t.Fatal("label-only update erased original receipt metadata", err)
	}
	if _, err = f.db.ChangeAccount(f.ctx, f.fixture.a, "history-authority-change", store.AccountCommand{Operation: "update", ID: f.actorA.Actor, ExpectedRevision: 2, Policy: &store.AccountPolicy{Label: "Changed history authority", Root: "/", Permissions: []string{"read", "list", "deliver"}}}); err != nil {
		t.Fatal(err)
	}
	current, err = f.db.Identity(f.ctx, f.a)
	if err != nil || current.AuthorityRevision != f.actorA.AuthorityRevision+1 {
		t.Fatal("fixture did not change actual history authority", err)
	}
	page, err := f.db.OutgoingExchanges(f.ctx, f.a, "", 20)
	if err != nil || len(page.Exchanges) != 0 || page.Next != "" {
		t.Fatal("new authority adopted old receipt metadata", err)
	}
	if _, err = f.db.OutgoingExchange(f.ctx, f.a, open.Exchange.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("old stamp metadata survived authority change", err)
	}
}

func TestOutgoingExchangeHistoryRechecksNamespacePermissionWithoutFabricatingReads(t *testing.T) {
	f := newExchangeFixture(t)
	f.service.NamespaceMaxEntries = 100
	mode := uint32(0640)
	data := []byte("source-path-authorized history")
	file, _, err := f.service.AcceptAt(f.ctx, f.fixture.a, "history-shared-file", int64(len(data)), secure.Digest(data), bytes.NewReader(data), custody.UploadTarget{Path: "/history.txt", Mode: &mode})
	if err != nil {
		t.Fatal(err)
	}
	offer, err := f.service.OfferExchange(f.ctx, f.other, "history-offer", exchangeRequest(file, f.endpoint))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.db.OutgoingExchange(f.ctx, f.other, offer.Exchange.ID); err != nil {
		t.Fatal("positive source permission", err)
	}
	entry, err := f.service.StatPath(f.ctx, f.fixture.a, "/history.txt")
	if err != nil {
		t.Fatal(err)
	}
	mode = 0600
	if _, err = f.service.PathCommand(f.ctx, f.fixture.a, "hide-history-source", store.PathCommand{Operation: "setstat", Path: "/history.txt", ExpectedRevision: &entry.Revision, Mode: &mode}); err != nil {
		t.Fatal(err)
	}
	page, err := f.db.OutgoingExchanges(f.ctx, f.other, "", 1)
	if err != nil || len(page.Exchanges) != 0 || page.Next != "" {
		t.Fatal("source permission loss leaked a record or cursor", err)
	}
	if _, err = f.db.OutgoingExchange(f.ctx, f.other, offer.Exchange.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("source-mode loss retained historical metadata", err)
	}
	var retrievals int
	if err = f.admin.QueryRow(f.ctx, `SELECT count(*) FROM events WHERE tenant_id=$1 AND partner_id=$2 AND kind='ArtifactExchangeRetrievalAuthorized'`, f.a.Tenant, f.a.Partner).Scan(&retrievals); err != nil || retrievals != 0 {
		t.Fatal("history fabricated byte read authorization", retrievals, err)
	}
}

func TestOutgoingHistoryEnumerationNeedsListButKnownOwnReceiptDoesNot(t *testing.T) {
	f := newExchangeFixture(t)
	scope, actor := exchangeActor(t, f.fixture, []string{"read", "write", "deliver"})
	endpoint, err := f.db.RegisterExchangeEndpoint(f.ctx, f.fixture.a, "no-list-endpoint", store.ExchangeEndpointCommand{Operation: "create", ID: secure.NewID(), Definition: &store.ExchangeEndpointDefinition{Schema: 1, Profile: "custody-https-poll-v1", Recipient: f.actorB, Senders: []store.ExchangeParticipant{actor}}}, f.limits, 16)
	if err != nil {
		t.Fatal(err)
	}
	file := actorFile(t, f, scope, "no-list-source", []byte("known own source"))
	offer, err := f.service.OfferExchange(f.ctx, scope, "no-list-offer", exchangeRequest(file, endpoint.Endpoint))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.db.OutgoingExchanges(f.ctx, scope, "", 20); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("read/deliver enumerated receipts without list", err)
	}
	row, err := f.db.OutgoingExchange(f.ctx, scope, offer.Exchange.ID)
	if err != nil || row.State != "offered" || row.Exchange.ID != offer.Exchange.ID {
		t.Fatal("list denial blocked known exact receipt recovery", err)
	}
}
