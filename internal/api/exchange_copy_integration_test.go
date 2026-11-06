//go:build integration

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"strconv"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestReceivedCopyHTTPSUsesOrdinaryCookieBearerAndIndependentWriteAuthority(t *testing.T) {
	service, scope, admin, server := browserAPI(t, time.Minute, custody.ExchangeSettings{MaxLifetime: time.Hour, MaxSenders: 16, MaxOpenViews: 128, MaxEndpoints: 16})
	service.NamespaceMaxEntries = 100
	cookie, csrf := loginBrowser(t, server, scope, admin)
	prefix := "/v1/tenants/" + scope.Tenant + "/partners/" + scope.Partner
	a, actorA := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "write", "list", "deliver"})
	b, actorB := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "write", "list"})
	readOnly, readActor := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "list"})
	data := bytes.Repeat([]byte("received data is not an execution instruction\n"), 2048)
	_, raw := exchangeAPIRequest(t, server, "POST", prefix+"/files", nil, map[string]string{"Authorization": "Bearer " + string(a.Bytes), "Idempotency-Key": "copy-api-source", "X-File-Size": strconv.Itoa(len(data)), "X-Content-SHA256": secure.Digest(data)}, data, 201)
	var accepted struct {
		File store.File `json:"file"`
	}
	if json.Unmarshal(raw, &accepted) != nil {
		t.Fatal("source response")
	}
	makeOffer := func(actor store.ExchangeParticipant, key string) store.ArtifactExchange {
		t.Helper()
		command := store.ExchangeEndpointCommand{Operation: "create", ID: secure.NewID(), Definition: &store.ExchangeEndpointDefinition{Schema: 1, Profile: "custody-https-poll-v1", Recipient: actor, Senders: []store.ExchangeParticipant{actorA}}}
		_, raw := exchangeAPIRequest(t, server, "POST", prefix+"/exchange-endpoints/commands", cookie, map[string]string{"Origin": server.URL, "X-CSRF-Token": csrf, "Idempotency-Key": key + "-endpoint"}, exchangeAPIJSON(t, command), 200)
		var endpoint store.ExchangeEndpointResult
		if json.Unmarshal(raw, &endpoint) != nil {
			t.Fatal("endpoint response")
		}
		r := store.ExchangeRequest{Schema: 1, Artifact: store.ExchangeArtifact{ID: accepted.File.ID, Size: accepted.File.Size, SHA256: accepted.File.SHA256, Policy: accepted.File.Policy}, Endpoint: store.ExchangeEndpointReference{ID: endpoint.Endpoint.ID, Revision: endpoint.Endpoint.Revision, Hash: endpoint.Endpoint.Hash}, ExpiresAt: time.Now().UTC().Add(time.Minute).Truncate(time.Microsecond), Receipt: "availability-only-v1"}
		_, raw = exchangeAPIRequest(t, server, "POST", prefix+"/exchanges", nil, map[string]string{"Authorization": "Bearer " + string(a.Bytes), "Idempotency-Key": key + "-offer"}, exchangeAPIJSON(t, r), 201)
		var offer store.ArtifactExchangeResult
		if json.Unmarshal(raw, &offer) != nil {
			t.Fatal("offer response")
		}
		return offer.Exchange
	}
	offer := makeOffer(actorB, "copy-api")
	r := store.ExchangeCopyRequest{ExchangeCopyOrigin: store.ExchangeCopyOrigin{ExchangeID: offer.ID, RequestHash: offer.RequestHash, Artifact: offer.Request.Artifact}, Path: "/received-api.dat"}
	recipientCookie, recipientCSRF := loginBrowser(t, server, scope, b)
	counts := func() (int, int, int) {
		t.Helper()
		tx, err := service.DB.Begin(context.Background(), scope)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Tx.Rollback(context.Background())
		var e, f, i int
		if err = tx.Tx.QueryRow(context.Background(), `SELECT (SELECT count(*) FROM events),(SELECT count(*) FROM files),(SELECT count(*) FROM delivery_intents)`).Scan(&e, &f, &i); err != nil {
			t.Fatal(err)
		}
		return e, f, i
	}
	e0, f0, i0 := counts()
	exchangeAPIRequest(t, server, "POST", prefix+"/exchange-copies", recipientCookie, map[string]string{"Origin": server.URL, "Idempotency-Key": "copy-api-original"}, exchangeAPIJSON(t, r), 403)
	e1, f1, i1 := counts()
	if e0 != e1 || f0 != f1 || i0 != i1 {
		t.Fatal("missing CSRF mutated custody")
	}
	_, raw = exchangeAPIRequest(t, server, "POST", prefix+"/exchange-copies", nil, map[string]string{"Authorization": "Bearer " + string(b.Bytes), "Idempotency-Key": "copy-api-original"}, exchangeAPIJSON(t, r), 201)
	var first custody.ExchangeCopyResult
	if json.Unmarshal(raw, &first) != nil || first.Replayed || first.Artifact.ID == accepted.File.ID || first.Source != r.ExchangeCopyOrigin || first.ReceiverPersistence != "unknown" {
		t.Fatal("copy response changed authority/evidence")
	}
	_, raw = exchangeAPIRequest(t, server, "POST", prefix+"/exchange-copies", recipientCookie, map[string]string{"Origin": server.URL, "X-CSRF-Token": recipientCSRF, "Idempotency-Key": "copy-api-original"}, exchangeAPIJSON(t, r), 200)
	var replay custody.ExchangeCopyResult
	if json.Unmarshal(raw, &replay) != nil || !replay.Replayed || replay.EventID != first.EventID || replay.Artifact != first.Artifact {
		t.Fatal("cookie and bearer produced different original receipt")
	}
	_, got := exchangeAPIRequest(t, server, "GET", prefix+"/files/"+first.Artifact.ID, nil, map[string]string{"Authorization": "Bearer " + string(b.Bytes)}, nil, 200)
	if !bytes.Equal(got, data) {
		t.Fatal("ordinary HTTPS receiver observed different copy bytes")
	}
	exchangeAPIRequest(t, server, "POST", prefix+"/exchange-copies", nil, map[string]string{"Authorization": "Bearer " + string(b.Bytes), "Idempotency-Key": "copy-api-overwrite"}, exchangeAPIJSON(t, r), 409)
	noWrite := makeOffer(readActor, "read-only-copy")
	r.ExchangeCopyOrigin = store.ExchangeCopyOrigin{ExchangeID: noWrite.ID, RequestHash: noWrite.RequestHash, Artifact: noWrite.Request.Artifact}
	r.Path = "/must-not-create.dat"
	e0, f0, i0 = counts()
	exchangeAPIRequest(t, server, "POST", prefix+"/exchange-copies", nil, map[string]string{"Authorization": "Bearer " + string(readOnly.Bytes), "Idempotency-Key": "no-write-copy"}, exchangeAPIJSON(t, r), 403)
	e1, f1, i1 = counts()
	if e0 != e1 || f0 != f1 || i0 != i1 {
		t.Fatal("receiving without write authority mutated custody")
	}
}
