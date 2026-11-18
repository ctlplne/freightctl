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
	"github.com/modelcontextprotocol/go-sdk/mcp"
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

func TestExchangeEvidenceIncludesOwnedCopyOnlyWhileSourceViewIsReadable(t *testing.T) {
	service, scope, admin, server := browserAPI(t, time.Minute, custody.ExchangeSettings{
		MaxLifetime: time.Hour, MaxSenders: 8, MaxOpenViews: 16, MaxEndpoints: 8,
	})
	cookie, csrf := loginBrowser(t, server, scope, admin)
	prefix := "/v1/tenants/" + scope.Tenant + "/partners/" + scope.Partner
	sender, a := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "write", "list", "deliver"})
	copyAuthor, b := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "write", "list", "deliver"})
	consumer, c := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "list"})
	scoped := func(token *secure.Secret) store.Scope {
		return store.Scope{Tenant: scope.Tenant, Partner: scope.Partner, TokenHash: secure.Digest(token.Bytes)}
	}
	bearer := func(token *secure.Secret) map[string]string {
		return map[string]string{"Authorization": "Bearer " + string(token.Bytes), "Content-Type": "application/json"}
	}
	limits, _, err := service.ExchangeLimits()
	if err != nil {
		t.Fatal(err)
	}
	offer := func(token *secure.Secret, from, to store.ExchangeParticipant, artifact store.ExchangeArtifact, key string) store.ArtifactExchange {
		t.Helper()
		endpoint, err := service.DB.RegisterExchangeEndpoint(t.Context(), scope, key+"-endpoint", store.ExchangeEndpointCommand{
			Operation: "create", ID: secure.NewID(), Definition: &store.ExchangeEndpointDefinition{
				Schema: 1, Profile: "custody-https-poll-v1", Recipient: to, Senders: []store.ExchangeParticipant{from},
			},
		}, limits, 8)
		if err != nil {
			t.Fatal(err)
		}
		got, err := service.OfferExchange(t.Context(), scoped(token), key, store.ExchangeRequest{
			Schema: 1, Artifact: artifact, Endpoint: store.ExchangeEndpointReference{
				ID: endpoint.Endpoint.ID, Revision: endpoint.Endpoint.Revision, Hash: endpoint.Endpoint.Hash,
			}, ExpiresAt: time.Now().UTC().Add(5 * time.Minute).Truncate(time.Microsecond), Receipt: "availability-only-v1",
		})
		if err != nil {
			t.Fatal(err)
		}
		return got.Exchange
	}
	payload := []byte("exact bytes from which the independently authorized onward file was copied")
	source, _, err := service.Accept(t.Context(), scoped(sender), "evidence-source", int64(len(payload)), secure.Digest(payload), bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	original := offer(sender, a, b, store.ExchangeArtifact{ID: source.ID, Size: source.Size, SHA256: source.SHA256, Policy: source.Policy}, "evidence-original")
	origin := store.ExchangeCopyOrigin{ExchangeID: original.ID, RequestHash: original.RequestHash, Artifact: original.Request.Artifact}
	result, err := service.CopyReceivedExchange(t.Context(), scoped(copyAuthor), "evidence-copy", store.ExchangeCopyRequest{
		ExchangeCopyOrigin: origin, Path: "/evidence-owned.dat",
	})
	if err != nil {
		t.Fatal(err)
	}
	onward := offer(copyAuthor, b, c, result.Artifact, "evidence-onward")
	const v4 = "authorized-exchange-evidence-v4"
	trace := func(token *secure.Secret, profile, direction string, status int) []byte {
		t.Helper()
		_, raw := exchangeAPIRequest(t, server, "POST", prefix+"/exchange-traces/previews", nil, bearer(token), exchangeAPIJSON(t,
			store.ExchangeTraceRequest{ID: onward.ID, Direction: direction, Profile: profile}), status)
		return raw
	}
	wire := trace(copyAuthor, v4, "outgoing", 200)
	var exposed map[string]json.RawMessage
	var copyEdge map[string]json.RawMessage
	var exactOrigin store.ExchangeCopyOrigin
	if json.Unmarshal(wire, &exposed) != nil || json.Unmarshal(exposed["received_copy"], &copyEdge) != nil ||
		json.Unmarshal(copyEdge["source"], &exactOrigin) != nil || exactOrigin != origin ||
		string(copyEdge["source_accepted_event_id"]) != strconv.Quote(source.EventID) ||
		string(copyEdge["source_offer_event_id"]) != strconv.Quote(original.EventID) {
		t.Fatal("owned-copy lineage does not match the exact committed revisions and journal")
	}
	if bytes.Contains(wire, []byte("/evidence-owned.dat")) || bytes.Contains(wire, []byte("evidence-copy")) {
		t.Fatal("lineage leaked private receipt or target metadata")
	}
	for _, redacted := range [][]byte{trace(consumer, v4, "incoming", 200), trace(copyAuthor, store.ExchangeEvidenceV3, "outgoing", 200)} {
		if bytes.Contains(redacted, []byte("received_copy")) || bytes.Contains(redacted, []byte(original.ID)) ||
			bytes.Contains(redacted, []byte(source.ID)) || bytes.Contains(redacted, []byte(source.EventID)) {
			t.Fatal("downstream recipient or older evidence profile learned the parent")
		}
	}
	trace(sender, v4, "outgoing", 404)
	client := *server.Client()
	client.Transport = mcpCredentialTransport{next: client.Transport, token: copyAuthor, origin: server.URL}
	sdk := mcp.NewClient(&mcp.Implementation{Name: "copy-lineage-verifier", Version: "1"}, &mcp.ClientOptions{Capabilities: &mcp.ClientCapabilities{}})
	session, err := sdk.Connect(t.Context(), &mcp.StreamableClientTransport{Endpoint: server.URL + prefix + "/mcp", HTTPClient: &client, MaxRetries: -1},
		&mcp.ClientSessionOptions{ProtocolVersion: mcpProtocolVersion})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	response, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "freightctl.exchange_trace", Arguments: store.ExchangeTraceRequest{
		ID: onward.ID, Direction: "outgoing", Profile: v4,
	}})
	if err != nil {
		t.Fatal(err)
	}
	var sdkTrace store.ExchangeTrace
	mcpDecodeResult(t, response, &sdkTrace)
	if sdkTrace.ReceivedCopy == nil || sdkTrace.ReceivedCopy.Source != origin {
		t.Fatal("stock MCP saw different copy evidence")
	}
	func() {
		t.Helper()
		parentChange, err := service.DB.Begin(t.Context(), scoped(sender))
		if err != nil {
			t.Fatal(err)
		}
		defer parentChange.Tx.Rollback(t.Context())
		if _, err = parentChange.Tx.Exec(t.Context(), `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`,
			scope.Tenant+":"+scope.Partner+":artifact-exchange:"+original.ID); err != nil {
			t.Fatal(err)
		}
		if busy := trace(copyAuthor, v4, "outgoing", 200); bytes.Contains(busy, []byte("received_copy")) ||
			!bytes.Contains(busy, []byte(result.Artifact.ID)) {
			t.Fatal("busy parent exposed the edge or prevented reading the authorized child offer")
		}
	}()
	exchangeAPIRequest(t, server, "GET", prefix+"/files/"+source.ID, nil, bearer(copyAuthor), nil, 404)
	if _, err = service.DB.CloseExchange(t.Context(), scoped(sender), "evidence-close-parent", store.ExchangeClosureCommand{
		Schema: 1, ID: original.ID, RequestHash: original.RequestHash, Operation: "cancel",
	}); err != nil {
		t.Fatal(err)
	}
	if closed := trace(copyAuthor, v4, "outgoing", 200); bytes.Contains(closed, []byte("received_copy")) ||
		!bytes.Contains(closed, []byte(result.Artifact.ID)) || !bytes.Contains(closed, []byte(result.EventID)) {
		t.Fatal("closing the parent disclosed its lineage or removed the separately owned evidence")
	}
	_, downloaded := exchangeAPIRequest(t, server, "GET", prefix+"/exchanges/"+onward.ID+"/file", nil, bearer(consumer), nil, 200)
	if !bytes.Equal(downloaded, payload) {
		t.Fatal("closing the source changed the descendant's independently authorized bytes")
	}
}
