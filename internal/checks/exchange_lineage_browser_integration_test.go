//go:build integration && exchangebrowser && (linux || darwin)

package checks_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/ctlplne/freightctl/internal/api"
	"github.com/ctlplne/freightctl/internal/checks"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

type observedTrace struct {
	http.ResponseWriter
	status   int
	body     bytes.Buffer
	overflow bool
}

func (w *observedTrace) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *observedTrace) Write(data []byte) (int, error) {
	n, err := w.ResponseWriter.Write(data)
	if !w.overflow && w.body.Len()+n <= 32<<10 {
		_, _ = w.body.Write(data[:n])
	} else {
		w.overflow = true
	}
	return n, err
}

func TestProjectionLineageNativeBrowserRespectsTheReleasedSourceBoundary(t *testing.T) {
	f := checks.PrepareProjectionExchange(t)
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	private, err := os.MkdirTemp("../../.private", "freightctl-browser-projection-lineage-")
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
	app := api.New(f.Custody, nil)
	tracePath := "/v1/tenants/" + f.Sender.Tenant + "/partners/" + f.Sender.Partner + "/exchange-traces/previews"
	traces := make(chan *observedTrace, 5)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != tracePath {
			app.ServeHTTP(w, r)
			return
		}
		observed := &observedTrace{ResponseWriter: w, status: http.StatusOK}
		app.ServeHTTP(observed, r)
		select {
		case traces <- observed:
		default:
			t.Error("unexpected extra trace request")
		}
	}))
	server.TLS = tlsConfig
	server.Config.ReadHeaderTimeout = 5 * time.Second
	server.Config.ReadTimeout = 10 * time.Second
	server.Config.WriteTimeout = 10 * time.Second
	server.StartTLS()
	defer server.Close()

	snapshot := func() [6]int {
		t.Helper()
		tx, err := f.Custody.DB.Begin(ctx, f.Sender)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Tx.Rollback(ctx)
		var count [6]int
		err = tx.Tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM files),(SELECT count(*) FROM record_projections),
 (SELECT count(*) FROM workflow_runs),(SELECT count(*) FROM artifact_exchanges),
 (SELECT count(*) FROM artifact_exchange_commands),(SELECT count(*) FROM delivery_intents)`).
			Scan(&count[0], &count[1], &count[2], &count[3], &count[4], &count[5])
		if err != nil {
			t.Fatal(err)
		}
		return count
	}
	before := snapshot()
	if before[1] != 1 || before[2] != 1 || before[3] != 1 || before[4] != 1 || before[5] != 0 {
		t.Fatal("fixture did not create one generated output and one authorized offer")
	}
	config, result := filepath.Join(private, "config.json"), filepath.Join(private, "result.json")
	fixture, err := json.Marshal(map[string]any{
		"origin": server.URL, "certificate_der": server.Certificate().Raw, "result": result,
		"tenant": f.Sender.Tenant, "partner": f.Sender.Partner, "sender": f.SenderToken, "recipient": f.RecipientToken,
		"exchange": f.Offer.ID, "endpoint": f.Offer.Request.Endpoint.ID,
		"output": f.Offer.Request.Artifact, "expected_lineage": f.Lineage,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(config, fixture, 0600); err != nil {
		t.Fatal(err)
	}
	log, err := os.OpenFile(filepath.Join(private, "browser.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	child := exec.CommandContext(ctx, "node", "../../scripts/projection-lineage-browser.mjs", config)
	child.Cancel = func() error { return child.Process.Signal(os.Interrupt) }
	child.WaitDelay = 5 * time.Second
	child.Stderr = log
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		if !waited {
			cancel()
			_ = child.Wait()
		}
	}()
	checkpoint := bufio.NewScanner(stdout)
	checkpoint.Buffer(make([]byte, 128), 128)
	if !checkpoint.Scan() || checkpoint.Text() != "source-held-confirmed" {
		t.Fatalf("browser did not verify the held source boundary, protected proof %s", filepath.Base(private))
	}
	// Approval is performed using the normal intake service. The browser stays
	// in its original authenticated sender session across this boundary.
	f.ReleaseSource(t)
	if _, err = io.WriteString(stdin, "source-released\n"); err != nil {
		t.Fatal(err)
	}
	if err = stdin.Close(); err != nil {
		t.Fatal(err)
	}
	extra := checkpoint.Scan()
	readErr := checkpoint.Err()
	waitErr := child.Wait()
	waited = true
	var observed struct {
		Phase         string `json:"phase"`
		Browser       string `json:"browser"`
		Node          string `json:"node"`
		Sandbox       bool   `json:"sandbox"`
		Logins        int    `json:"logins"`
		Traces        int    `json:"traces"`
		Accessibility int    `json:"accessibility"`
		Egress        int    `json:"egress"`
		Effects       int    `json:"effect_requests"`
		RuntimeErrors int    `json:"runtime_errors"`
	}
	wire, err := os.ReadFile(result)
	if err != nil || len(wire) > 4096 || json.Unmarshal(wire, &observed) != nil || extra || readErr != nil || waitErr != nil ||
		observed.Phase != "complete" || observed.Browser == "" || !observed.Sandbox || observed.Logins != 2 || observed.Traces != 5 ||
		observed.Accessibility != 2 || observed.Egress != 0 || observed.Effects != 0 || observed.RuntimeErrors != 0 {
		t.Fatalf("browser lineage check failed at phase %q, protected proof %s", observed.Phase, filepath.Base(private))
	}
	if snapshot() != before {
		t.Fatal("browser lineage reads changed custody, processing or exchange state")
	}
	if len(traces) != 5 {
		t.Fatal("missing original HTTPS trace responses")
	}
	for _, expected := range []struct {
		profile, direction string
		lineage            bool
	}{
		{store.ExchangeEvidenceV2, "outgoing", false},
		{store.ExchangeEvidenceV2, "outgoing", true},
		{store.ExchangeEvidenceV1, "incoming", false},
		{store.ExchangeEvidenceV2, "incoming", false},
	} {
		response := <-traces
		wire := response.body.Bytes()
		var trace store.ExchangeTrace
		decoder := json.NewDecoder(bytes.NewReader(wire))
		decoder.DisallowUnknownFields()
		if response.overflow || response.status != http.StatusOK || decoder.Decode(&trace) != nil ||
			trace.Profile != expected.profile || trace.Direction != expected.direction || trace.Tenant != f.Sender.Tenant || trace.Partner != f.Sender.Partner ||
			trace.ID != f.Offer.ID || trace.RequestHash != f.Offer.RequestHash || trace.Artifact == nil || *trace.Artifact != f.Offer.Request.Artifact ||
			trace.State != "offered" || trace.Details != "authorized-records" || trace.CheckedAt.IsZero() {
			t.Fatal("original HTTPS trace changed profile, direction or offer identity")
		}
		if len(trace.Events) != 2 || trace.Events[0].Kind != "custody-acceptance" || trace.Events[0].ID != f.Output.EventID || trace.Events[0].Resource != f.Output.ID ||
			trace.Events[1].Kind != "availability-offer" || trace.Events[1].ID != f.Offer.EventID || trace.Events[1].Resource != f.Offer.ID ||
			trace.StorageVerification != "not-checked" || trace.Retrieval != "unknown" || trace.ReceiverPersistence != "unknown" || trace.BusinessProcessing != "unknown" {
			t.Fatal("original HTTPS trace changed recorded outcomes")
		}
		if expected.lineage {
			if trace.Projection == nil || *trace.Projection != f.Lineage {
				t.Fatal("original HTTPS trace changed the exact generated lineage")
			}
		} else {
			for _, value := range []string{`"record_projection"`, f.Lineage.Source.ID, f.Lineage.Source.SHA256, f.Lineage.CompletedEvent} {
				if bytes.Contains(wire, []byte(value)) {
					t.Fatal("original HTTPS trace disclosed withheld lineage")
				}
			}
		}
		for _, value := range []string{f.Custody.Disk.Identity(), "checked.csv", `"report"`, `"payload"`} {
			if bytes.Contains(wire, []byte(value)) {
				t.Fatal("original HTTPS trace disclosed private internals")
			}
		}
	}
	if response := <-traces; response.status != http.StatusNotFound || response.overflow || bytes.Contains(response.body.Bytes(), []byte(f.Lineage.Source.ID)) {
		t.Fatal("recipient reached the original sender's trace")
	}
	t.Logf("exact browser lineage passed, browser=%s node=%s logins=%d traces=%d accessibility=%d egress=%d effects=%d", observed.Browser, observed.Node, observed.Logins, observed.Traces, observed.Accessibility, observed.Egress, observed.Effects)
}
