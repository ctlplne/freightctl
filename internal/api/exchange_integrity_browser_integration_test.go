//go:build integration && exchangebrowser && (linux || darwin)

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestExchangeIntegrityNativeBrowserVerifiesSavedBytesAndRecoversReport(t *testing.T) {
	payload := bytes.Repeat([]byte("custody artifact integrity fixture\n"), 40_000)
	f := prepareIntegrityExchange(t, payload)
	childOffer, copyLineage := prepareBrowserReceivedCopy(t, f)
	ctx, cancel := context.WithTimeout(t.Context(), 55*time.Second)
	defer cancel()
	private, err := os.MkdirTemp("../../.private", "freightctl-browser-integrity-")
	if err != nil {
		t.Fatal(err)
	}
	private, err = filepath.Abs(private)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if !t.Failed() {
			if err := os.RemoveAll(private); err != nil {
				t.Error(err)
			}
		}
	})
	certFile, keyFile := filepath.Join(private, "tls.crt"), filepath.Join(private, "tls.key")
	if err = secure.DevCertificate(certFile, keyFile); err != nil {
		t.Fatal(err)
	}
	_, tlsConfig, err := secure.NativeProofTLS(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	exchange := f.prefix + "/exchanges/" + f.offer.ID
	reportPath := exchange + "/integrity-report"
	app := New(f.service, nil)
	var attempts atomic.Int32
	first := make(chan *httptest.ResponseRecorder, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != reportPath || attempts.Add(1) != 1 {
			app.ServeHTTP(w, r)
			return
		}
		// Let production commit and send the response headers, then cut the
		// stream before the receipt body. Chromium can retry automatically
		// when the connection drops before any HTTP response arrives.
		original := httptest.NewRecorder()
		app.ServeHTTP(original, r)
		first <- original
		if original.Code != http.StatusCreated {
			w.WriteHeader(original.Code)
			_, _ = w.Write(original.Body.Bytes())
			return
		}
		w.Header().Set("Content-Type", original.Header().Get("Content-Type"))
		w.Header().Set("Content-Length", strconv.Itoa(original.Body.Len()))
		w.WriteHeader(original.Code)
		wire := http.NewResponseController(w)
		if err := wire.Flush(); err != nil {
			t.Error("could not flush the original report response headers")
			return
		}
		connection, _, err := wire.Hijack()
		if err != nil {
			t.Error("could not close the original committed report response")
			return
		}
		_ = connection.Close()
	}))
	server.TLS = tlsConfig
	server.Config.ReadHeaderTimeout = 5 * time.Second
	server.Config.ReadTimeout = 10 * time.Second
	server.Config.WriteTimeout = 10 * time.Second
	server.StartTLS()
	defer server.Close()

	sender, recipient := filepath.Join(private, "sender.credential"), filepath.Join(private, "recipient.credential")
	if err = os.WriteFile(sender, f.sender.Bytes, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(recipient, f.recipient.Bytes, 0600); err != nil {
		t.Fatal(err)
	}
	config, result := filepath.Join(private, "config.json"), filepath.Join(private, "result.json")
	wire := exchangeAPIJSON(t, map[string]any{
		"origin": server.URL, "certificate_der": server.Certificate().Raw,
		"tenant": f.scope.Tenant, "partner": f.scope.Partner, "sender": sender, "recipient": recipient,
		"exchange": f.offer.ID, "endpoint": f.offer.Request.Endpoint.ID, "artifact": f.offer.Request.Artifact,
		"copied_exchange": childOffer, "copy_lineage": copyLineage, "result": result,
	})
	if err = os.WriteFile(config, wire, 0600); err != nil {
		t.Fatal(err)
	}
	log, err := os.OpenFile(filepath.Join(private, "browser.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	child := exec.CommandContext(ctx, "node", "../../scripts/exchange-integrity-browser.mjs", config)
	child.Cancel = func() error { return child.Process.Signal(os.Interrupt) }
	child.WaitDelay = 5 * time.Second
	child.Stdout, child.Stderr = log, log
	if err = child.Run(); err != nil {
		select {
		case original := <-first:
			t.Logf("original report HTTP status %d, received POST attempts %d", original.Code, attempts.Load())
		default:
			t.Logf("received POST attempts %d without an original report response", attempts.Load())
		}
		t.Fatalf("native integrity browser proof failed, protected proof %s", filepath.Base(private))
	}
	var observed struct {
		Phase         string `json:"phase"`
		Browser       string `json:"browser"`
		Node          string `json:"node"`
		Writes        int    `json:"writes"`
		Runtimes      int    `json:"runtime_errors"`
		Blocked       int    `json:"blocked"`
		Accessibility int    `json:"accessibility"`
		LineageChecks int    `json:"copy_lineage_checks"`
		Event         string `json:"event"`
	}
	raw, err := os.ReadFile(result)
	if err != nil || len(raw) > 4096 || json.Unmarshal(raw, &observed) != nil || observed.Phase != "complete" ||
		observed.Browser == "" || observed.Node != "v26.13.0" || observed.Writes != 2 || observed.Runtimes != 0 ||
		observed.Blocked != 0 || observed.Accessibility != 3 || observed.LineageChecks != 2 || !store.ValidID(observed.Event) || attempts.Load() != 2 {
		t.Fatal("browser did not complete the exact recovery and inspection profile")
	}
	var committed store.ExchangeIntegrityReport
	select {
	case original := <-first:
		if original.Code != http.StatusCreated || json.Unmarshal(original.Body.Bytes(), &committed) != nil || committed.EventID != observed.Event {
			t.Fatal("recovered browser report differed from the original committed receipt")
		}
	default:
		t.Fatal("the original report request never reached the server")
	}
	tx, err := f.service.DB.Begin(ctx, f.acting(f.recipient))
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Tx.Rollback(ctx)
	var reports, events, reads, effects int
	err = tx.Tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM artifact_exchange_integrity_reports),
 (SELECT count(*) FROM events WHERE kind='ArtifactExchangeIntegrityReported'),
 (SELECT count(*) FROM events WHERE kind='ArtifactExchangeRetrievalAuthorized' AND payload ? 'report_profile'),
 (SELECT count(*) FROM delivery_intents)`).Scan(&reports, &events, &reads, &effects)
	if err != nil || reports != 1 || events != 1 || reads != 1 || effects != 0 {
		t.Fatal("browser recovery changed report, read or external-effect cardinality", err)
	}
	t.Logf("sandboxed Chromium %s, Node %s, one full native read, original receipt recovered, both copy-lineage views checked, three axe checks", observed.Browser, observed.Node)
}

func prepareBrowserReceivedCopy(t *testing.T, f integrityFixture) (string, store.ExchangeCopyLineage) {
	t.Helper()
	ctx := t.Context()
	asParticipant := func(scope store.Scope) store.ExchangeParticipant {
		t.Helper()
		id, err := f.service.DB.Identity(ctx, scope)
		if err != nil {
			t.Fatal(err)
		}
		return store.ExchangeParticipant{Tenant: id.Tenant, Partner: id.Partner, Actor: id.Actor, AuthorityRevision: id.AuthorityRevision, RootPolicyDigest: id.RootPolicyDigest}
	}
	copyAuthor := f.acting(f.sender)
	limits, _, err := f.service.ExchangeLimits()
	if err != nil {
		t.Fatal(err)
	}
	route, err := f.service.DB.RegisterExchangeEndpoint(ctx, f.scope, "browser-copy-source-route", store.ExchangeEndpointCommand{
		Operation: "create", ID: secure.NewID(), Definition: &store.ExchangeEndpointDefinition{
			Schema: 1, Profile: "custody-https-poll-v1", Recipient: asParticipant(copyAuthor), Senders: []store.ExchangeParticipant{asParticipant(f.scope)},
		},
	}, limits, 4)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("browser evidence for a separately owned copy\n")
	file, _, err := f.service.Accept(ctx, f.scope, "browser-copy-source", int64(len(body)), secure.Digest(body), bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request := f.offer.Request
	request.Endpoint = store.ExchangeEndpointReference{ID: route.Endpoint.ID, Revision: route.Endpoint.Revision, Hash: route.Endpoint.Hash}
	request.Artifact = store.ExchangeArtifact{ID: file.ID, Size: file.Size, SHA256: file.SHA256, Policy: file.Policy}
	parent, err := f.service.OfferExchange(ctx, f.scope, "browser-copy-parent", request)
	if err != nil {
		t.Fatal(err)
	}
	origin := store.ExchangeCopyOrigin{ExchangeID: parent.Exchange.ID, RequestHash: parent.Exchange.RequestHash, Artifact: request.Artifact}
	copy, err := f.service.CopyReceivedExchange(ctx, copyAuthor, "browser-copy-created", store.ExchangeCopyRequest{
		ExchangeCopyOrigin: origin, Path: "/browser-evidence-copy.dat",
	})
	if err != nil {
		t.Fatal(err)
	}
	request.Endpoint = f.offer.Request.Endpoint
	request.Artifact = copy.Artifact
	child, err := f.service.OfferExchange(ctx, copyAuthor, "browser-copy-child", request)
	if err != nil {
		t.Fatal(err)
	}
	return child.Exchange.ID, store.ExchangeCopyLineage{Source: origin, SourceAccepted: file.EventID, SourceOffer: parent.Exchange.EventID}
}
