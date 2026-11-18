//go:build integration

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type nativeExchangeMCPTransport struct {
	next   http.RoundTripper
	token  *secure.Secret
	origin string
}

func (c nativeExchangeMCPTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme+"://"+r.URL.Host != c.origin {
		return nil, store.ErrForbidden
	}
	request := r.Clone(r.Context())
	request.Header.Set("Authorization", "Bearer "+string(c.token.Bytes))
	return c.next.RoundTrip(request)
}

func qualifyNativeExchangeIntegritySurfaces(t *testing.T, ctx context.Context, f exchangeProcessFixture, binary, work, origin string, client *http.Client, exchange store.ArtifactExchange) store.ExchangeIntegrityReport {
	t.Helper()
	cli := func(token, name string, extra ...string) ([]byte, error) {
		t.Helper()
		args := []string{name, "-dsn-file", f.DSN, "-token-file", token, "-tenant", f.Administrator.Tenant, "-partner", f.Administrator.Partner, "-storage", f.Storage}
		out, err := exec.CommandContext(ctx, binary, append(args, extra...)...).Output()
		if len(out) > 32<<10 {
			t.Fatal("native report result exceeded its evidence bound")
		}
		return out, err
	}
	requestFile := func(name string, value any) string {
		t.Helper()
		wire, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(work, name+".json")
		if err = os.WriteFile(path, wire, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	path := filepath.Join(work, "cli-report-input.bin")
	meta, err := cli(f.RecipientToken, "exchange-download", "-exchange-id", exchange.ID, "-output", path, "-prepare-integrity-report")
	if err != nil {
		var failed *exec.ExitError
		if errors.As(err, &failed) && bytes.Contains(failed.Stderr, []byte("flag provided but not defined: -prepare-integrity-report")) {
			t.Fatal("native exchange-download lacks the explicit integrity report preparation flag")
		}
		t.Fatal("native CLI could not prepare a report after verified publication", err)
	}
	var download struct {
		Output   string                          `json:"output"`
		Evidence string                          `json:"evidence"`
		Report   *store.ExchangeIntegrityCommand `json:"integrity_report"`
	}
	actual, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(actual, f.Payload) || json.Unmarshal(meta, &download) != nil || download.Output != path || download.Evidence != "local-file-verified-and-synced" || download.Report == nil {
		t.Fatal("native report preparation did not preserve the verified local output", err)
	}
	command := *download.Report
	if command != (store.ExchangeIntegrityCommand{Schema: 1, ExchangeID: exchange.ID, RequestHash: exchange.RequestHash, ReadAuthorization: command.ReadAuthorization, FileID: exchange.Request.Artifact.ID, Size: int64(len(actual)), SHA256: secure.Digest(actual)}) || !store.ValidID(command.ReadAuthorization) {
		t.Fatal("native report preparation did not bind the exact bytes and read event")
	}
	connect := func(reference string) *mcp.ClientSession {
		t.Helper()
		token, err := secure.ReadSecret(reference, 64)
		if err != nil {
			t.Fatal("could not open the SDK credential reference")
		}
		t.Cleanup(token.Close)
		transport := *client
		transport.Transport = nativeExchangeMCPTransport{next: client.Transport, token: token, origin: origin}
		endpoint := origin + "/v1/tenants/" + f.Administrator.Tenant + "/partners/" + f.Administrator.Partner + "/mcp"
		sdk := mcp.NewClient(&mcp.Implementation{Name: "freightctl-integrity-proof", Version: "1"}, &mcp.ClientOptions{Capabilities: &mcp.ClientCapabilities{}})
		session, err := sdk.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: endpoint, HTTPClient: &transport, MaxRetries: -1}, &mcp.ClientSessionOptions{ProtocolVersion: "2026-07-28"})
		if err != nil {
			t.Fatal("stock SDK could not authenticate to the native daemon", err)
		}
		t.Cleanup(func() { _ = session.Close() })
		return session
	}
	recipient, sender, other := connect(f.RecipientToken), connect(f.SenderToken), connect(f.OtherToken)
	call := func(client *mcp.ClientSession, name string, args any, allow bool) []byte {
		t.Helper()
		result, err := client.CallTool(ctx, &mcp.CallToolParams{Name: "freightctl." + name, Arguments: args})
		if err != nil || result == nil || result.IsError == allow {
			t.Fatal("stock SDK report call had the wrong authority result", name, allow, err)
		}
		if !allow {
			return nil
		}
		typed, err := json.Marshal(result.StructuredContent)
		if err != nil || len(typed) > 4096 || bytes.Contains(typed, actual) || bytes.Contains(typed, []byte(path)) {
			t.Fatal("stock SDK receipt exceeded its bounded metadata contract")
		}
		return typed
	}
	outgoing := store.ExchangeTraceRequest{ID: exchange.ID, Direction: "outgoing"}
	incoming := store.ExchangeTraceRequest{ID: exchange.ID, Direction: "incoming"}
	call(sender, "inspect_exchange_integrity", outgoing, false)
	call(recipient, "inspect_exchange_integrity", incoming, false)
	const key = "native-exchange-integrity-original"
	args := map[string]any{"request_key": key, "command": command}
	call(sender, "report_exchange_integrity", args, false)
	call(other, "report_exchange_integrity", args, false)
	var reported store.ExchangeIntegrityReport
	if json.Unmarshal(call(recipient, "report_exchange_integrity", args, true), &reported) != nil || reported.Profile != store.ExchangeIntegrityReportProfile ||
		reported.ReadAuthorization != command.ReadAuthorization || reported.Artifact != exchange.Request.Artifact || reported.RequestHash != exchange.RequestHash ||
		reported.ExchangeID != exchange.ID || reported.ReceiverPersistence != "unknown" || reported.BusinessProcessing != "unknown" || !store.ValidID(reported.EventID) {
		t.Fatal("stock SDK did not return the exact ordinary integrity report")
	}
	checkReceipt := func(raw []byte, err error) {
		t.Helper()
		var result store.ExchangeIntegrityReport
		if err != nil || json.Unmarshal(raw, &result) != nil || result != reported {
			t.Fatal("integrity report changed across surfaces or retries", err)
		}
	}
	checkReceipt(call(sender, "inspect_exchange_integrity", outgoing, true), nil)
	checkReceipt(call(recipient, "inspect_exchange_integrity", incoming, true), nil)
	call(other, "inspect_exchange_integrity", incoming, false)
	call(recipient, "inspect_exchange_integrity", outgoing, false)
	checkReceipt(cli(f.RecipientToken, "exchange-integrity-report", "-request-file", requestFile("integrity-command", command), "-idempotency-key", key))
	checkReceipt(cli(f.SenderToken, "exchange-integrity-inspect", "-request-file", requestFile("integrity-selection", outgoing)))
	incoming.Profile, outgoing.Profile = store.ExchangeEvidenceV3, store.ExchangeEvidenceV3
	checkTrace := func(trace store.ExchangeTrace, direction string) {
		t.Helper()
		if trace.Profile != store.ExchangeEvidenceV3 || trace.Direction != direction || trace.ID != exchange.ID ||
			trace.RequestHash != exchange.RequestHash || trace.IntegrityReport == nil || *trace.IntegrityReport != reported ||
			trace.Retrieval != "unknown" || trace.ReceiverPersistence != "unknown" || trace.BusinessProcessing != "unknown" {
			t.Fatal("combined evidence changed the original integrity report or its meaning")
		}
	}
	for _, pair := range []struct {
		client  *mcp.ClientSession
		request store.ExchangeTraceRequest
	}{{sender, outgoing}, {recipient, incoming}} {
		var trace store.ExchangeTrace
		if err := json.Unmarshal(call(pair.client, "exchange_trace", pair.request, true), &trace); err != nil {
			t.Fatal("stock SDK did not return v3 evidence", err)
		}
		checkTrace(trace, pair.request.Direction)
	}
	call(other, "exchange_trace", incoming, false)
	raw, err := cli(f.SenderToken, "exchange-trace", "-request-file", requestFile("evidence-v3", outgoing))
	var trace store.ExchangeTrace
	if err != nil || json.Unmarshal(raw, &trace) != nil {
		t.Fatal("native CLI did not return v3 evidence", err)
	}
	checkTrace(trace, "outgoing")
	selection := store.ExchangeTraceExportSelection{ExchangeTraceRequest: outgoing, RequestHash: exchange.RequestHash}
	exportPath := filepath.Join(work, "published-evidence-v3.json")
	raw, err = cli(f.SenderToken, "exchange-trace-export", "-request-file", requestFile("evidence-v3-export", selection), "-output", exportPath)
	var receipt custody.ExchangeTraceExportReceipt
	var portable custody.PortableExchangeTrace
	export, readErr := os.ReadFile(exportPath)
	if err != nil || readErr != nil || json.Unmarshal(raw, &receipt) != nil || json.Unmarshal(export, &portable) != nil ||
		receipt.Source != selection || portable.Source != selection || portable.Evidence == nil ||
		receipt.Size != len(export) || receipt.SHA256 != secure.Digest(export) {
		t.Fatal("native CLI did not publish the exact selected v3 evidence", err, readErr)
	}
	checkTrace(*portable.Evidence, "outgoing")
	changed := command
	changed.SHA256 = secure.Digest([]byte("changed bytes"))
	call(recipient, "report_exchange_integrity", map[string]any{"request_key": key, "command": changed}, false)
	call(recipient, "report_exchange_integrity", map[string]any{"request_key": key, "command": command, "receiver_persistence": "durable"}, false)
	t.Log("native CLI verified bytes and prepared a report, stock MCP committed once, and original sender/recipient reads and CLI retry matched")
	t.Log("stock MCP, native CLI and verified portable v3 evidence retained the original integrity report")
	return reported
}
