//go:build integration

package api

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/jackc/pgx/v5/pgconn"
)

type integrityFixture struct {
	service                  *custody.Service
	scope                    store.Scope
	server                   *httptest.Server
	sender, recipient, other *secure.Secret
	recipientActor           store.ExchangeParticipant
	file                     *store.File
	offer                    *store.ArtifactExchange
	prefix                   string
}

func (f integrityFixture) acting(token *secure.Secret) store.Scope {
	return store.Scope{Tenant: f.scope.Tenant, Partner: f.scope.Partner, TokenHash: secure.Digest(token.Bytes)}
}

func prepareIntegrityExchange(t *testing.T, payload []byte) integrityFixture {
	t.Helper()
	settings := custody.ExchangeSettings{MaxLifetime: time.Hour, MaxSenders: 4, MaxOpenViews: 8, MaxEndpoints: 4}
	service, scope, admin, server := browserAPI(t, time.Minute, settings)
	cookie, csrf := loginBrowser(t, server, scope, admin)
	prefix := "/v1/tenants/" + scope.Tenant + "/partners/" + scope.Partner
	sender, actorA := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "write", "list", "deliver"})
	recipient, actorB := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "list"})
	other, _ := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "list"})
	f := integrityFixture{service: service, scope: scope, server: server, sender: sender, recipient: recipient, other: other, recipientActor: actorB, prefix: prefix}
	file, _, err := service.Accept(t.Context(), f.acting(sender), "integrity-source", int64(len(payload)), secure.Digest(payload), bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	limits, _, err := service.ExchangeLimits()
	if err != nil {
		t.Fatal(err)
	}
	registered, err := service.DB.RegisterExchangeEndpoint(t.Context(), scope, "integrity-endpoint", store.ExchangeEndpointCommand{
		Operation: "create", ID: secure.NewID(), Definition: &store.ExchangeEndpointDefinition{
			Schema: 1, Profile: "custody-https-poll-v1", Recipient: actorB, Senders: []store.ExchangeParticipant{actorA},
		},
	}, limits, 4)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := registered.Endpoint
	request := store.ExchangeRequest{
		Schema: 1, Artifact: store.ExchangeArtifact{ID: file.ID, Size: file.Size, SHA256: file.SHA256, Policy: file.Policy},
		Endpoint:  store.ExchangeEndpointReference{ID: endpoint.ID, Revision: endpoint.Revision, Hash: endpoint.Hash},
		ExpiresAt: time.Now().Add(10 * time.Minute).UTC().Truncate(time.Microsecond), Receipt: "availability-only-v1",
	}
	offer, err := service.OfferExchange(t.Context(), f.acting(sender), "integrity-offer", request)
	if err != nil {
		t.Fatal(err)
	}
	f.file, f.offer = file, &offer.Exchange
	return f
}

func TestExchangeRecipientIntegrityReportBindsStockHTTPSDownload(t *testing.T) {
	payload := []byte("annotated custody bytes\n")
	f := prepareIntegrityExchange(t, payload)
	service, server, file, offer := f.service, f.server, f.file, f.offer
	sender, recipient, other, acting := f.sender, f.recipient, f.other, f.acting
	credentials := func(token *secure.Secret, key string) map[string]string {
		return map[string]string{"Authorization": "Bearer " + string(token.Bytes), "Idempotency-Key": key, "Content-Type": "application/json"}
	}
	exchange := f.prefix + "/exchanges/" + offer.ID
	path := exchange + "/integrity-report"
	dir := t.TempDir()
	cert, err := secure.NativeProofCertificatePEM(server.Certificate().Raw)
	if err != nil {
		t.Fatal(err)
	}
	certPath, headerPath := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "authorization.headers")
	if err = os.WriteFile(certPath, cert, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(headerPath, []byte("Authorization: Bearer "+string(recipient.Bytes)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	output, responseHeaders := filepath.Join(dir, "bytes"), filepath.Join(dir, "response.headers")
	child := exec.CommandContext(t.Context(), "curl", "--disable", "--silent", "--show-error", "--fail", "--noproxy", "*", "--proto", "=https", "--max-time", "10", "--cacert", certPath, "--header", "@"+headerPath, "--dump-header", responseHeaders, "--output", output, server.URL+exchange+"/file")
	if err = child.Run(); err != nil {
		t.Fatal("stock curl byte retrieval failed", err)
	}
	actual, err := os.ReadFile(output)
	if err != nil || !bytes.Equal(actual, payload) {
		t.Fatal("independent client did not retrieve exact bytes", err)
	}
	rawHeaders, err := os.ReadFile(responseHeaders)
	if err != nil {
		t.Fatal(err)
	}
	head := textproto.NewReader(bufio.NewReader(bytes.NewReader(rawHeaders)))
	status, err := head.ReadLine()
	if err != nil || !strings.Contains(status+" ", " 200 ") {
		t.Fatal("expected the complete HTTPS response")
	}
	h, err := head.ReadMIMEHeader()
	authorization := h.Get("X-Exchange-Read-Authorization-ID")
	if err != nil || !store.ValidID(authorization) {
		t.Fatal("complete recipient response did not identify its recorded read authorization")
	}
	bearer := credentials(recipient, "")["Authorization"]
	partial, _ := exchangeAPIRequest(t, server, "GET", exchange+"/file", nil, map[string]string{"Authorization": bearer, "Range": "bytes=0-2"}, nil, 206)
	if partial.Header.Get("X-Exchange-Read-Authorization-ID") != "" {
		t.Fatal("partial response exposed a full-read authorization selector")
	}
	metadata, _ := exchangeAPIRequest(t, server, "HEAD", exchange+"/file", nil, map[string]string{"Authorization": bearer}, nil, 200)
	unchanged, _ := exchangeAPIRequest(t, server, "GET", exchange+"/file", nil, map[string]string{"Authorization": bearer, "If-None-Match": metadata.Header.Get("ETag")}, nil, 304)
	if metadata.Header.Get("X-Exchange-Read-Authorization-ID") != "" || unchanged.Header.Get("X-Exchange-Read-Authorization-ID") != "" {
		t.Fatal("HEAD or a conditional response offered an integrity report selector")
	}
	newReport := func(readID, digest string) []byte {
		return exchangeAPIJSON(t, map[string]any{
			"schema_version": 1, "exchange_id": offer.ID, "request_hash": offer.RequestHash,
			"read_authorization_event_id": readID, "file_revision_id": file.ID, "size_bytes": len(actual), "sha256": digest,
		})
	}
	body := newReport(authorization, secure.Digest(actual))
	post := func(token *secure.Secret, key string, body []byte, want int) []byte {
		t.Helper()
		_, data := exchangeAPIRequest(t, server, "POST", path, nil, credentials(token, key), body, want)
		return data
	}
	read := func(token *secure.Secret, direction string, want int) []byte {
		t.Helper()
		_, data := exchangeAPIRequest(t, server, "GET", path+"?direction="+direction, nil, credentials(token, ""), nil, want)
		return data
	}
	read(sender, "outgoing", 404)
	post(sender, "report-as-sender", body, 404)
	post(other, "report-as-other", body, 404)
	post(recipient, "invented-read", newReport(secure.NewID(), secure.Digest(actual)), 404)
	tx, err := service.DB.Begin(t.Context(), acting(recipient))
	if err != nil {
		t.Fatal(err)
	}
	var partialReadID string
	err = tx.Tx.QueryRow(t.Context(), `SELECT event_id::text FROM events WHERE actor_id=$1 AND resource_id=$2 AND kind='ArtifactExchangeRetrievalAuthorized' AND NOT(payload ? 'report_profile') LIMIT 1`, f.recipientActor.Actor, offer.ID).Scan(&partialReadID)
	tx.Tx.Rollback(t.Context())
	if err != nil {
		t.Fatal("non-full admissions did not retain their ordinary journal evidence", err)
	}
	post(recipient, "non-full-read", newReport(partialReadID, secure.Digest(actual)), 404)
	post(recipient, "incorrect-digest", newReport(authorization, secure.Digest([]byte("different"))), 409)
	post(recipient, "invented-durability", append(bytes.TrimSuffix(body, []byte("}")), []byte(`,"receiver_persistence":"durable"}`)...), 400)
	// Even a runtime transaction under the real recipient cannot commit a
	// stand-alone claim in the journal without its exact guarded receipt.
	tx, err = service.DB.Begin(t.Context(), acting(recipient))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Append(t.Context(), "ArtifactExchangeIntegrityReported", offer.ID, map[string]string{"unbound": "fixture"}); err != nil {
		tx.Tx.Rollback(t.Context())
		t.Fatal(err)
	}
	var pg *pgconn.PgError
	if err = tx.Tx.Commit(t.Context()); !errors.As(err, &pg) || pg.Code != "23514" {
		t.Fatal("database committed a report event without its transactional receipt", err)
	}
	first := post(recipient, "original-report", body, 201)
	if !bytes.Equal(first, read(sender, "outgoing", 200)) || !bytes.Equal(first, read(recipient, "incoming", 200)) {
		t.Fatal("directional receipt reads changed the original committed result")
	}
	replay := post(recipient, "original-report", body, 200)
	if !bytes.Equal(first, replay) {
		t.Fatal("same key did not recover the exact receipt bytes")
	}
	post(recipient, "original-report", newReport(authorization, secure.Digest([]byte("different"))), 409)
	post(recipient, "second-report", body, 409)
	receiverCookie, receiverCSRF := loginBrowser(t, server, acting(recipient), recipient)
	browserRead := exchange + "/integrity-read/" + secure.NewID()
	selection := browserRead + "/selection"
	exchangeAPIRequest(t, server, "GET", selection, receiverCookie, nil, nil, 404)
	exchangeAPIRequest(t, server, "GET", browserRead+"/file", nil, map[string]string{"Authorization": bearer}, nil, 401)
	for _, admission := range []struct {
		method  string
		headers map[string]string
		status  int
	}{
		{"HEAD", nil, 200},
		{"GET", map[string]string{"Range": "bytes=0-2"}, 206},
		{"GET", map[string]string{"If-None-Match": metadata.Header.Get("ETag")}, 304},
	} {
		response, _ := exchangeAPIRequest(t, server, admission.method, browserRead+"/file", receiverCookie, admission.headers, nil, admission.status)
		if len(response.Cookies()) != 0 || response.Header.Get("X-Exchange-Read-Authorization-ID") != "" {
			t.Fatal("non-full browser admission offered a report selector")
		}
	}
	full, saved := exchangeAPIRequest(t, server, "GET", browserRead+"/file", receiverCookie, nil, nil, 200)
	readID := full.Header.Get("X-Exchange-Read-Authorization-ID")
	cookies := full.Cookies()
	if !bytes.Equal(saved, payload) || !store.ValidID(readID) || len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly ||
		cookies[0].SameSite != http.SameSiteStrictMode || cookies[0].Path != selection || cookies[0].Domain != "" {
		t.Fatal("browser read and strictly scoped selection did not identify the same authorized bytes")
	}
	marker := cookies[0].Name + "=" + cookies[0].Value
	selectedHeader := func(session *http.Cookie, value string) map[string]string {
		return map[string]string{"Cookie": session.Name + "=" + session.Value + "; " + value}
	}
	_, selectedCommand := exchangeAPIRequest(t, server, "GET", selection, nil, selectedHeader(receiverCookie, marker), nil, 200)
	command, err := store.DecodeExchangeIntegrityCommand(selectedCommand)
	if err != nil || command.ReadAuthorization != readID || command.ExchangeID != offer.ID || command.RequestHash != offer.RequestHash ||
		command.FileID != file.ID || command.Size != int64(len(saved)) || command.SHA256 != secure.Digest(saved) {
		t.Fatal("selection returned a different command than the browser's exact full read", err)
	}
	again, _ := browserRequest(t, server, "POST", f.prefix+"/browser-session", nil,
		map[string]string{"Authorization": bearer, "Origin": server.URL, "Idempotency-Key": "separate-browser-login"}, "", 200)
	if len(again.Cookies()) != 1 || again.Cookies()[0].Value == receiverCookie.Value {
		t.Fatal("fixture did not create a different browser session")
	}
	secondSession := again.Cookies()[0]
	exchangeAPIRequest(t, server, "GET", selection, nil, selectedHeader(secondSession, marker), nil, 404)
	senderSession, _ := loginBrowser(t, server, acting(sender), sender)
	exchangeAPIRequest(t, server, "GET", selection, nil, selectedHeader(senderSession, marker), nil, 404)
	exchangeAPIRequest(t, server, "GET", exchange+"/integrity-read/"+secure.NewID()+"/selection", nil, selectedHeader(receiverCookie, marker), nil, 404)
	exchangeAPIRequest(t, server, "GET", selection, nil, selectedHeader(receiverCookie, marker+"; "+marker), nil, 404)
	foreign := strings.Replace(cookies[0].Value, readID, secure.NewID(), 1)
	exchangeAPIRequest(t, server, "GET", selection, nil, selectedHeader(receiverCookie, cookies[0].Name+"="+foreign), nil, 404)
	exchangeAPIRequest(t, server, "POST", path, receiverCookie, map[string]string{"Origin": server.URL, "Idempotency-Key": "original-report"}, body, 403)
	_, cookieReplay := exchangeAPIRequest(t, server, "POST", path, receiverCookie, map[string]string{"Origin": server.URL, "X-CSRF-Token": receiverCSRF, "Idempotency-Key": "original-report", "Content-Type": "application/json"}, body, 200)
	if !bytes.Equal(first, cookieReplay) {
		t.Fatal("browser replay differed from bearer receipt")
	}
	read(other, "incoming", 404)
	read(recipient, "outgoing", 404)
	var report store.ExchangeIntegrityReport
	if json.Unmarshal(first, &report) != nil || report.Profile != store.ExchangeIntegrityReportProfile || report.ReadAuthorization != authorization ||
		report.Artifact != offer.Request.Artifact || report.RequestHash != offer.RequestHash || report.ExchangeID != offer.ID ||
		!store.ValidID(report.EventID) || report.RecordedAt.IsZero() || report.ReceiverPersistence != "unknown" ||
		report.BusinessProcessing != "unknown" || report.Observation != "recipient-reported-sha256-and-length-match" {
		t.Fatal("report changed the recipient's integrity statement or claimed stronger outcomes")
	}
	tx, err = service.DB.Begin(t.Context(), acting(recipient))
	if err != nil {
		t.Fatal(err)
	}
	var reports, events, effects int
	err = tx.Tx.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM artifact_exchange_integrity_reports), (SELECT count(*) FROM events WHERE kind='ArtifactExchangeIntegrityReported'), (SELECT count(*) FROM delivery_intents)`).Scan(&reports, &events, &effects)
	tx.Tx.Rollback(t.Context())
	if err != nil || reports != 1 || events != 1 || effects != 0 {
		t.Fatal("refusals or replays changed the original report cardinality or caused a delivery", err)
	}
	_, err = service.DB.CloseExchange(t.Context(), acting(sender), "cancel-integrity-view", store.ExchangeClosureCommand{Schema: 1, ID: offer.ID, RequestHash: offer.RequestHash, Operation: "cancel"})
	if err != nil {
		t.Fatal(err)
	}
	read(recipient, "incoming", 404)
	exchangeAPIRequest(t, server, "GET", selection, nil, selectedHeader(receiverCookie, marker), nil, 404)
	post(recipient, "original-report", body, 404)
	if !bytes.Equal(first, read(sender, "outgoing", 200)) {
		t.Fatal("closure changed the original authorized sender report")
	}
}
