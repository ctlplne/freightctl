//go:build integration

package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
)

func exchangeAPIRequest(t *testing.T, server *httptest.Server, method, path string, cookie *http.Cookie, headers map[string]string, body []byte, expected int) (*http.Response, []byte) {
	t.Helper()
	r, err := http.NewRequest(method, server.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal("request construction failed")
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	for name, value := range headers {
		r.Header.Set(name, value)
	}
	response, err := server.Client().Do(r)
	if err != nil {
		t.Fatal("bounded HTTPS request failed")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, (2<<20)+1))
	if err != nil || len(data) > 2<<20 || response.StatusCode != expected {
		t.Fatalf("%s expected status %d, got %d; bounded body read succeeded: %t", method, expected, response.StatusCode, err == nil)
	}
	return response, data
}

func exchangeAPIJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal("JSON fixture failed")
	}
	return data
}

func exchangeAPIParticipant(t *testing.T, server *httptest.Server, prefix string, cookie *http.Cookie, csrf string, permissions []string) (*secure.Secret, store.ExchangeParticipant) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "credential")
	if err := secure.WriteToken(path); err != nil {
		t.Fatal(err)
	}
	token, err := secure.ReadSecret(path, 64)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(token.Close)
	id := secure.NewID()
	command := store.AccountCommand{Operation: "create", ID: id, CredentialHash: secure.Digest(token.Bytes), Policy: &store.AccountPolicy{Label: "HTTPS participant", Root: "/", Permissions: permissions}}
	exchangeAPIRequest(t, server, "POST", prefix+"/accounts/commands", cookie, map[string]string{"Origin": server.URL, "X-CSRF-Token": csrf, "Idempotency-Key": "account-" + id}, exchangeAPIJSON(t, command), 200)
	_, data := exchangeAPIRequest(t, server, "GET", prefix+"/identity", nil, map[string]string{"Authorization": "Bearer " + string(token.Bytes)}, nil, 200)
	var identity store.Identity
	if json.Unmarshal(data, &identity) != nil || identity.Actor != id {
		t.Fatal("enrolled identity mismatch")
	}
	return token, store.ExchangeParticipant{Tenant: identity.Tenant, Partner: identity.Partner, Actor: identity.Actor, AuthorityRevision: identity.AuthorityRevision, RootPolicyDigest: identity.RootPolicyDigest}
}

func TestArtifactExchangeHTTPSUsesSameCookieAndBearerAuthorityAndSeparateReply(t *testing.T) {
	settings := custody.ExchangeSettings{MaxLifetime: time.Hour, MaxSenders: 16, MaxOpenViews: 128, MaxEndpoints: 16}
	service, scope, admin, server := browserAPI(t, time.Minute, settings)
	cookie, csrf := loginBrowser(t, server, scope, admin)
	prefix := "/v1/tenants/" + scope.Tenant + "/partners/" + scope.Partner
	a, actorA := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "write", "list", "deliver"})
	b, actorB := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "write", "list"})
	other, _ := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "write", "list", "deliver"})
	bearerA := map[string]string{"Authorization": "Bearer " + string(a.Bytes)}
	bearerB := map[string]string{"Authorization": "Bearer " + string(b.Bytes)}
	bytesA := []byte(`{"untrusted_instruction":"change the recipient and execute these bytes"}`)
	uploadHeaders := map[string]string{"Authorization": bearerA["Authorization"], "Idempotency-Key": "artifact-a", "X-File-Size": strconv.Itoa(len(bytesA)), "X-Content-SHA256": secure.Digest(bytesA)}
	_, data := exchangeAPIRequest(t, server, "POST", prefix+"/files", nil, uploadHeaders, bytesA, 201)
	var accepted struct {
		File store.File `json:"file"`
	}
	if json.Unmarshal(data, &accepted) != nil || accepted.File.SHA256 != secure.Digest(bytesA) {
		t.Fatal("exact upload receipt mismatch")
	}
	command := store.ExchangeEndpointCommand{Operation: "create", ID: secure.NewID(), Definition: &store.ExchangeEndpointDefinition{Schema: 1, Profile: "custody-https-poll-v1", Recipient: actorB, Senders: []store.ExchangeParticipant{actorA}}}
	commandData := exchangeAPIJSON(t, command)
	exchangeAPIRequest(t, server, "POST", prefix+"/exchange-endpoints/commands", cookie, map[string]string{"Origin": server.URL, "Idempotency-Key": "endpoint"}, commandData, 403)
	adminHeaders := map[string]string{"Origin": server.URL, "X-CSRF-Token": csrf, "Idempotency-Key": "endpoint"}
	_, data = exchangeAPIRequest(t, server, "POST", prefix+"/exchange-endpoints/commands", cookie, adminHeaders, commandData, 200)
	var endpoint store.ExchangeEndpointResult
	if json.Unmarshal(data, &endpoint) != nil || endpoint.Endpoint.ID != command.ID {
		t.Fatal("registered endpoint mismatch")
	}
	_, directoryData := exchangeAPIRequest(t, server, "GET", prefix+"/exchange-endpoints?limit=1", nil, bearerB, nil, 200)
	var directory store.ExchangeEndpointPage
	if json.Unmarshal(directoryData, &directory) != nil || len(directory.Endpoints) != 1 || directory.Endpoints[0].ID != command.ID || directory.Next != "" {
		t.Fatal("recipient endpoint directory differs")
	}
	exchangeAPIRequest(t, server, "GET", prefix+"/exchange-endpoints/"+command.ID, nil, bearerA, nil, 200)
	_, directoryData = exchangeAPIRequest(t, server, "GET", prefix+"/exchange-endpoints", nil, map[string]string{"Authorization": "Bearer " + string(other.Bytes)}, nil, 200)
	if json.Unmarshal(directoryData, &directory) != nil || len(directory.Endpoints) != 0 || directory.Next != "" {
		t.Fatal("unrelated actor learned endpoint directory metadata")
	}
	exchangeAPIRequest(t, server, "GET", prefix+"/exchange-endpoints/"+command.ID, nil, map[string]string{"Authorization": "Bearer " + string(other.Bytes)}, nil, 404)
	exchangeAPIRequest(t, server, "POST", prefix+"/exchange-endpoints/commands", nil, map[string]string{"Authorization": bearerA["Authorization"], "Idempotency-Key": "sender-cannot-admin"}, commandData, 403)
	r := store.ExchangeRequest{Schema: 1, Artifact: store.ExchangeArtifact{ID: accepted.File.ID, Size: accepted.File.Size, SHA256: accepted.File.SHA256, Policy: accepted.File.Policy}, Endpoint: store.ExchangeEndpointReference{ID: endpoint.Endpoint.ID, Revision: endpoint.Endpoint.Revision, Hash: endpoint.Endpoint.Hash}, ExpiresAt: time.Now().UTC().Add(2 * time.Minute).Truncate(time.Microsecond), Receipt: "availability-only-v1"}
	_, data = exchangeAPIRequest(t, server, "GET", prefix+"/exchange-sources/"+accepted.File.ID, nil, bearerA, nil, 200)
	var reviewedSource store.ExchangeArtifact
	if json.Unmarshal(data, &reviewedSource) != nil || reviewedSource != r.Artifact {
		t.Fatal("source review did not bind actual authorized revision")
	}
	exchangeAPIRequest(t, server, "GET", prefix+"/exchange-sources/"+accepted.File.ID, nil, bearerB, nil, 403)
	adminHeaders["Idempotency-Key"] = "admin-cannot-impersonate-sender"
	exchangeAPIRequest(t, server, "POST", prefix+"/exchanges", cookie, adminHeaders, exchangeAPIJSON(t, r), 404)
	offerHeaders := map[string]string{"Authorization": bearerA["Authorization"], "Idempotency-Key": "original-offer"}
	_, data = exchangeAPIRequest(t, server, "POST", prefix+"/exchanges", nil, offerHeaders, exchangeAPIJSON(t, r), 201)
	var offer store.ArtifactExchangeResult
	if json.Unmarshal(data, &offer) != nil || offer.Replayed || bytes.Contains(data, []byte(service.Disk.Identity())) {
		t.Fatal("invalid or overdisclosing offer receipt")
	}
	_, data = exchangeAPIRequest(t, server, "GET", prefix+"/outgoing-exchanges?limit=1", nil, bearerA, nil, 200)
	var sentPage store.OutgoingExchangePage
	if json.Unmarshal(data, &sentPage) != nil || len(sentPage.Exchanges) != 1 || sentPage.Exchanges[0].Exchange.ID != offer.Exchange.ID || sentPage.Exchanges[0].State != "offered" || sentPage.Exchanges[0].Retrieval != "unknown" {
		t.Fatal("served sender history changed original receipt or receiver evidence")
	}
	exchangeAPIRequest(t, server, "GET", prefix+"/outgoing-exchanges", nil, bearerB, nil, 403)
	exchangeAPIRequest(t, server, "GET", prefix+"/outgoing-exchanges/"+offer.Exchange.ID, nil, bearerB, nil, 404)
	_, data = exchangeAPIRequest(t, server, "POST", prefix+"/exchanges", nil, offerHeaders, exchangeAPIJSON(t, r), 200)
	var replay store.ArtifactExchangeResult
	if json.Unmarshal(data, &replay) != nil || !replay.Replayed || replay.Exchange.ID != offer.Exchange.ID {
		t.Fatal("original key response-loss recovery changed effect")
	}
	changed := r
	changed.Artifact.Size++
	exchangeAPIRequest(t, server, "POST", prefix+"/exchanges", nil, offerHeaders, exchangeAPIJSON(t, changed), 409)
	_, data = exchangeAPIRequest(t, server, "GET", prefix+"/exchange-endpoints/"+command.ID+"/incoming", nil, bearerB, nil, 200)
	var page store.ArtifactExchangePage
	if json.Unmarshal(data, &page) != nil || len(page.Exchanges) != 1 || page.Exchanges[0].ID != offer.Exchange.ID {
		t.Fatal("authorized incoming discovery mismatch")
	}
	exchangeAPIRequest(t, server, "GET", prefix+"/exchange-endpoints/"+command.ID+"/incoming", nil, bearerA, nil, 404)
	exchangeAPIRequest(t, server, "GET", prefix+"/exchange-endpoints/"+command.ID+"/incoming", nil, map[string]string{"Authorization": "Bearer " + string(other.Bytes)}, nil, 404)
	exchangeAPIRequest(t, server, "GET", prefix+"/files/"+accepted.File.ID, nil, bearerB, nil, 404)
	exchangeAPIRequest(t, server, "POST", prefix+"/exchanges", nil, map[string]string{"Authorization": bearerB["Authorization"], "Idempotency-Key": "no-forwarding"}, exchangeAPIJSON(t, r), 403)
	filePath := prefix + "/exchanges/" + offer.Exchange.ID + "/file"
	for _, wrong := range []string{"/v1/tenants/" + secure.NewID() + "/partners/" + scope.Partner, "/v1/tenants/" + scope.Tenant + "/partners/" + secure.NewID()} {
		exchangeAPIRequest(t, server, "GET", wrong+"/exchanges/"+offer.Exchange.ID+"/file", nil, bearerB, nil, 401)
	}
	response, data := exchangeAPIRequest(t, server, "GET", filePath, nil, bearerB, nil, 200)
	if !bytes.Equal(data, bytesA) || response.Header.Get("X-File-Revision-ID") != accepted.File.ID || response.Header.Get("X-Content-SHA256") != secure.Digest(data) {
		t.Fatal("HTTPS exact byte receipt mismatch")
	}
	_, partial := exchangeAPIRequest(t, server, "GET", filePath, nil, map[string]string{"Authorization": bearerB["Authorization"], "Range": "bytes=1-3"}, nil, 206)
	if !bytes.Equal(partial, bytesA[1:4]) {
		t.Fatal("range returned different bytes")
	}
	etag := response.Header.Get("ETag")
	if etag == "" || etag[0] != '"' {
		t.Fatal("authorized exchange has no strong immutable validator")
	}
	for _, method := range []string{"GET", "HEAD"} {
		response, conditional := exchangeAPIRequest(t, server, method, filePath, nil, map[string]string{"Authorization": bearerB["Authorization"], "If-None-Match": etag}, nil, 304)
		if len(conditional) != 0 || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("ETag") != etag {
			t.Fatal("conditional exchange changed privacy or validator")
		}
	}
	_, resumed := exchangeAPIRequest(t, server, "GET", filePath, nil, map[string]string{"Authorization": bearerB["Authorization"], "Range": "bytes=1-3", "If-Range": etag}, nil, 206)
	if !bytes.Equal(resumed, bytesA[1:4]) {
		t.Fatal("exact exchange validator resumed different bytes")
	}
	_, stale := exchangeAPIRequest(t, server, "GET", filePath, nil, map[string]string{"Authorization": bearerB["Authorization"], "Range": "bytes=1-3", "If-Range": "W/" + etag}, nil, 200)
	if !bytes.Equal(stale, bytesA) {
		t.Fatal("weak exchange validator permitted unchecked partial bytes")
	}
	bScope := store.Scope{Tenant: scope.Tenant, Partner: scope.Partner}
	bCookie, _ := loginBrowser(t, server, bScope, b)
	exchangeAPIRequest(t, server, "GET", filePath, bCookie, map[string]string{"Authorization": "Bearer " + string(other.Bytes)}, nil, 404)
	exchangeAPIRequest(t, server, "GET", filePath, bCookie, nil, nil, 200)
	update := store.AccountCommand{Operation: "update", ID: actorB.Actor, ExpectedRevision: 1, Policy: &store.AccountPolicy{Label: "HTTPS participant", Root: "/", Permissions: []string{"read", "write", "list", "deliver"}}}
	adminHeaders["Idempotency-Key"] = "allow-new-reply"
	exchangeAPIRequest(t, server, "POST", prefix+"/accounts/commands", cookie, adminHeaders, exchangeAPIJSON(t, update), 200)
	exchangeAPIRequest(t, server, "GET", filePath, bCookie, nil, nil, 401)
	exchangeAPIRequest(t, server, "GET", filePath, nil, bearerB, nil, 404)
	for _, method := range []string{"GET", "HEAD"} {
		response, _ := exchangeAPIRequest(t, server, method, filePath, nil, map[string]string{"Authorization": bearerB["Authorization"], "If-None-Match": etag, "If-Range": etag, "Range": "bytes=1-3"}, nil, 404)
		if response.Header.Get("ETag") != "" || response.Header.Get("Content-Range") != "" {
			t.Fatal("old validator bypassed current exchange authority")
		}
	}
	_, data = exchangeAPIRequest(t, server, "GET", prefix+"/identity", nil, bearerB, nil, 200)
	var newIdentity store.Identity
	if json.Unmarshal(data, &newIdentity) != nil || newIdentity.AuthorityRevision <= actorB.AuthorityRevision {
		t.Fatal("reply authority did not advance")
	}
	actorB.AuthorityRevision, actorB.RootPolicyDigest = newIdentity.AuthorityRevision, newIdentity.RootPolicyDigest
	exchangeAPIRequest(t, server, "GET", prefix+"/exchange-sources/"+accepted.File.ID, nil, bearerB, nil, 404)
	command.ID = secure.NewID()
	command.Definition = &store.ExchangeEndpointDefinition{Schema: 1, Profile: "custody-https-poll-v1", Recipient: actorA, Senders: []store.ExchangeParticipant{actorB}}
	adminHeaders["Idempotency-Key"] = "reply-endpoint"
	_, data = exchangeAPIRequest(t, server, "POST", prefix+"/exchange-endpoints/commands", cookie, adminHeaders, exchangeAPIJSON(t, command), 200)
	if json.Unmarshal(data, &endpoint) != nil {
		t.Fatal("reply endpoint response invalid")
	}
	forbidden := r
	forbidden.Endpoint = store.ExchangeEndpointReference{ID: endpoint.Endpoint.ID, Revision: endpoint.Endpoint.Revision, Hash: endpoint.Endpoint.Hash}
	forbidden.ReplyTo = offer.Exchange.ID
	exchangeAPIRequest(t, server, "POST", prefix+"/exchanges", nil, map[string]string{"Authorization": bearerB["Authorization"], "Idempotency-Key": "receive-is-not-onward-source"}, exchangeAPIJSON(t, forbidden), 404)
	replyBytes := []byte("separately authorized reply\n")
	uploadHeaders = map[string]string{"Authorization": bearerB["Authorization"], "Idempotency-Key": "artifact-b", "X-File-Size": strconv.Itoa(len(replyBytes)), "X-Content-SHA256": secure.Digest(replyBytes)}
	_, data = exchangeAPIRequest(t, server, "POST", prefix+"/files", nil, uploadHeaders, replyBytes, 201)
	var replyFile struct {
		File store.File `json:"file"`
	}
	if json.Unmarshal(data, &replyFile) != nil || replyFile.File.ID == accepted.File.ID {
		t.Fatal("reply artifact was not independently accepted")
	}
	r.Artifact = store.ExchangeArtifact{ID: replyFile.File.ID, Size: replyFile.File.Size, SHA256: replyFile.File.SHA256, Policy: replyFile.File.Policy}
	r.Endpoint = store.ExchangeEndpointReference{ID: endpoint.Endpoint.ID, Revision: endpoint.Endpoint.Revision, Hash: endpoint.Endpoint.Hash}
	r.ReplyTo = offer.Exchange.ID
	_, data = exchangeAPIRequest(t, server, "POST", prefix+"/exchanges", nil, map[string]string{"Authorization": bearerB["Authorization"], "Idempotency-Key": "new-reply-operation"}, exchangeAPIJSON(t, r), 201)
	var reply store.ArtifactExchangeResult
	if json.Unmarshal(data, &reply) != nil {
		t.Fatal("reply receipt invalid")
	}
	_, data = exchangeAPIRequest(t, server, "GET", prefix+"/exchanges/"+reply.Exchange.ID+"/file", nil, bearerA, nil, 200)
	if !bytes.Equal(data, replyBytes) {
		t.Fatal("separately authorized HTTPS reply bytes mismatch")
	}
	// Exercise recipient decline through the same cookie/Origin/CSRF guard as
	// every other browser command, then separately exercise sender cancellation.
	aCookie, aCSRF := loginBrowser(t, server, bScope, a)
	closure := store.ExchangeClosureCommand{Schema: 1, ID: reply.Exchange.ID, RequestHash: reply.Exchange.RequestHash, Operation: "decline"}
	closeHeaders := map[string]string{"Origin": server.URL, "Idempotency-Key": "decline-reply"}
	exchangeAPIRequest(t, server, "POST", prefix+"/exchange-closures", aCookie, closeHeaders, exchangeAPIJSON(t, closure), 403)
	closeHeaders["X-CSRF-Token"] = aCSRF
	_, data = exchangeAPIRequest(t, server, "POST", prefix+"/exchange-closures", aCookie, closeHeaders, exchangeAPIJSON(t, closure), 200)
	var terminal store.ExchangeClosureResult
	if json.Unmarshal(data, &terminal) != nil || terminal.State != "declined" || terminal.Replayed {
		t.Fatal("recipient terminal receipt invalid")
	}
	_, data = exchangeAPIRequest(t, server, "POST", prefix+"/exchange-closures", aCookie, closeHeaders, exchangeAPIJSON(t, closure), 200)
	var terminalReplay store.ExchangeClosureResult
	if json.Unmarshal(data, &terminalReplay) != nil || !terminalReplay.Replayed || terminalReplay.EventID != terminal.EventID {
		t.Fatal("terminal response-loss receipt changed")
	}
	exchangeAPIRequest(t, server, "GET", prefix+"/exchanges/"+reply.Exchange.ID+"/file", nil, bearerA, nil, 404)
	_, data = exchangeAPIRequest(t, server, "POST", prefix+"/exchanges", nil, map[string]string{"Authorization": bearerB["Authorization"], "Idempotency-Key": "second-reply-view"}, exchangeAPIJSON(t, r), 201)
	var cancelOffer store.ArtifactExchangeResult
	if json.Unmarshal(data, &cancelOffer) != nil {
		t.Fatal("cancellation offer invalid")
	}
	closure.ID, closure.RequestHash, closure.Operation = cancelOffer.Exchange.ID, cancelOffer.Exchange.RequestHash, "cancel"
	exchangeAPIRequest(t, server, "POST", prefix+"/exchange-closures", nil, map[string]string{"Authorization": bearerA["Authorization"], "Idempotency-Key": "wrong-cancel-role"}, exchangeAPIJSON(t, closure), 404)
	exchangeAPIRequest(t, server, "POST", prefix+"/exchange-closures", nil, map[string]string{"Authorization": bearerB["Authorization"], "Idempotency-Key": "sender-cancel"}, exchangeAPIJSON(t, closure), 200)
	exchangeAPIRequest(t, server, "GET", prefix+"/exchanges/"+cancelOffer.Exchange.ID+"/file", nil, bearerA, nil, 404)
	_, data = exchangeAPIRequest(t, server, "GET", prefix+"/outgoing-exchanges/"+cancelOffer.Exchange.ID, nil, bearerB, nil, 200)
	var canceledHistory store.OutgoingExchange
	if json.Unmarshal(data, &canceledHistory) != nil || canceledHistory.State != "canceled" || canceledHistory.ClosureEvent == "" || canceledHistory.Retrieval != "unknown" || canceledHistory.ReceiverPersistence != "unknown" || canceledHistory.BusinessProcessing != "unknown" {
		t.Fatal("served closed history fabricated receiver outcome or lost decision")
	}
	_, data = exchangeAPIRequest(t, server, "GET", prefix+"/files/"+replyFile.File.ID, nil, bearerB, nil, 200)
	if !bytes.Equal(data, replyBytes) {
		t.Fatal("closing a view removed its source bytes")
	}
	adminHeaders["Idempotency-Key"] = "revoke-original-endpoint"
	revoke := store.ExchangeEndpointCommand{Operation: "revoke", ID: offer.Exchange.Request.Endpoint.ID, ExpectedRevision: 1}
	_, data = exchangeAPIRequest(t, server, "POST", prefix+"/exchange-endpoints/commands", cookie, adminHeaders, exchangeAPIJSON(t, revoke), 200)
	var revoked store.ExchangeEndpointResult
	if json.Unmarshal(data, &revoked) != nil || revoked.Endpoint.State != "revoked" || revoked.Endpoint.Revision != 2 {
		t.Fatal("served endpoint revocation did not bind original revision")
	}
}
