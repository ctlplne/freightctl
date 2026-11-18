//go:build integration && (linux || darwin)

package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type stockExchangeTools func(name string, arguments map[string]any, errorCode string) []byte

type stockExchangeMCPTransport struct {
	transport *http.Transport
	endpoint  *url.URL
	token     *secure.Secret
}

func (t stockExchangeMCPTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.String() != t.endpoint.String() {
		return nil, errors.New("MCP fixture credential is bound to one HTTPS endpoint")
	}
	request := r.Clone(r.Context())
	request.Header.Set("Authorization", "Bearer "+string(t.token.Bytes))
	return t.transport.RoundTrip(request)
}

func (c stockExchangeHTTPS) tools(t *testing.T, ctx context.Context, tokenFile string) stockExchangeTools {
	t.Helper()
	endpoint, err := url.Parse(c.prefix + "/mcp")
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() != "127.0.0.1" {
		t.Fatal("stock MCP fixture must use the task-owned HTTPS listener", err)
	}
	trust, err := secure.NativeProofClientTLS(c.certificate)
	if err != nil {
		t.Fatal("read the task-owned HTTPS certificate", err)
	}
	token, err := secure.ReadSecret(tokenFile, 64)
	if err != nil {
		t.Fatal("read the MCP fixture identity", err)
	}
	t.Cleanup(token.Close)
	transport := &http.Transport{TLSClientConfig: trust}
	t.Cleanup(transport.CloseIdleConnections)
	httpClient := &http.Client{Transport: stockExchangeMCPTransport{transport, endpoint, token}, Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	client := mcp.NewClient(&mcp.Implementation{Name: "stock-sftp-agent-qualification", Version: "1"}, &mcp.ClientOptions{
		Capabilities: &mcp.ClientCapabilities{},
	})
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: endpoint.String(), HTTPClient: httpClient, MaxRetries: -1},
		&mcp.ClientSessionOptions{ProtocolVersion: "2026-07-28"})
	if err != nil {
		t.Fatal("the stock SDK failed verified TLS discovery", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return func(name string, arguments map[string]any, errorCode string) []byte {
		t.Helper()
		result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "freightctl." + name, Arguments: arguments})
		if err != nil || result == nil || result.IsError != (errorCode != "") || len(result.Content) != 1 {
			t.Fatalf("stock MCP %s returned an unexpected outcome; expected error %q; transport error %v", name, errorCode, err)
		}
		content, ok := result.Content[0].(*mcp.TextContent)
		if !ok {
			t.Fatal("stock MCP returned non-metadata content", name)
		}
		if errorCode != "" {
			if content.Text != errorCode || result.StructuredContent != nil {
				t.Fatalf("stock MCP %s returned a different refusal; expected %q; response_sha256=%s", name, errorCode, secure.Digest([]byte(content.Text)))
			}
			return nil
		}
		wire, err := json.Marshal(result.StructuredContent)
		if err != nil || len(wire) > 32768 || !json.Valid([]byte(content.Text)) {
			t.Fatal("stock MCP metadata result exceeded its bound or failed JSON validation", name, err)
		}
		return wire
	}
}

func prepareAndOfferStockExchange(t *testing.T, sender, recipient stockExchangeTools, request store.ExchangeRequest, key string) store.ArtifactExchangeResult {
	t.Helper()
	args := map[string]any{"request": request}
	recipient("prepare_exchange", args, "permission_denied")
	preview := readStockExchangeJSON[custody.ExchangePreview](t, sender("prepare_exchange", args, ""))
	if preview.Request != request || preview.State != "metadata-review-only" || preview.StorageVerification != "not-checked" {
		t.Fatal("stock MCP offer review changed the exact request or overstated its effects")
	}
	args["request_hash"], args["request_key"] = secure.Digest([]byte("unreviewed")), key
	sender("offer_exchange", args, "revision_conflict")
	args["request_hash"] = preview.RequestHash
	offer := readStockExchangeJSON[store.ArtifactExchangeResult](t, sender("offer_exchange", args, ""))
	if offer.Exchange.RequestHash != preview.RequestHash || offer.Exchange.Request != request ||
		offer.Exchange.Sender != preview.Sender || offer.Exchange.Recipient != preview.Recipient {
		t.Fatal("stock MCP offer lost its review binding")
	}
	return offer
}

func verifyStockExchangeDiscovery(t *testing.T, client stockExchangeHTTPS, tools stockExchangeTools, endpoint string, offer store.ArtifactExchange, receive string) {
	t.Helper()
	page := readStockExchangeJSON[store.ArtifactExchangePage](t, tools("incoming_exchanges", map[string]any{"endpoint_id": endpoint, "limit": 1}, ""))
	if len(page.Exchanges) != 1 || page.Exchanges[0].ID != offer.ID || page.Exchanges[0].State != "offered" {
		t.Fatal("stock MCP poll lost the exact visible offer")
	}
	base, err := url.Parse(client.prefix)
	if err != nil {
		t.Fatal("invalid task-owned HTTPS prefix", err)
	}
	value := readStockExchangeJSON[map[string]any](t, tools("retrieval_descriptor", map[string]any{"exchange_id": offer.ID}, ""))
	expectedRaw, err := json.Marshal(map[string]any{"exchange_id": offer.ID, "artifact": offer.Request.Artifact,
		"request_hash": offer.RequestHash, "relative_download_path": base.Path + receive, "authority": "recheck-on-authenticated-download",
		"retrieval": "unknown", "receiver_persistence": "unknown", "business_processing": "unknown"})
	if err != nil || !reflect.DeepEqual(value, readStockExchangeJSON[map[string]any](t, expectedRaw)) {
		t.Fatal("stock MCP retrieval metadata changed the approved HTTPS byte route, disclosed bytes or overstated the receipt")
	}
}

func stockMCPWorkArguments(action stockOnwardAction, key string) map[string]any {
	args := map[string]any{"start": action.Start, "run_id": action.RunID, "receipt_key": action.ReceiptKey}
	if key != "" {
		args["request_key"] = key
	}
	return args
}

func startStockMCPOnward(t *testing.T, tools stockExchangeTools, review OnwardReview, key string) string {
	t.Helper()
	value := readStockExchangeJSON[OnwardReview](t, tools("prepare_onward", map[string]any{"request": review.Request}, ""))
	if !reflect.DeepEqual(value, review) {
		t.Fatal("stock MCP and HTTPS onward reviews differ")
	}
	type acceptance struct {
		RunID           string                 `json:"run_id"`
		Artifact        store.ExchangeArtifact `json:"artifact"`
		Workflow        Reference              `json:"workflow"`
		ReviewHash      string                 `json:"review_hash"`
		AcceptedState   string                 `json:"accepted_run_state"`
		CurrentState    string                 `json:"current_state"`
		Acceptance      string                 `json:"acceptance"`
		Persistence     string                 `json:"receiver_persistence"`
		BusinessOutcome string                 `json:"business_processing"`
		Replayed        bool                   `json:"replayed"`
	}
	args := map[string]any{"request": review.Request, "review_hash": review.ReviewHash, "request_key": key}
	first := readStockExchangeJSON[acceptance](t, tools("start_onward", args, ""))
	if !store.ValidID(first.RunID) || first.Artifact != review.Request.Artifact || first.Workflow != review.Request.Workflow ||
		first.ReviewHash != review.ReviewHash || first.AcceptedState != "queued" || first.CurrentState != "not-checked" ||
		first.Acceptance != "recorded-run-and-intents-only" || first.Persistence != "unknown" || first.BusinessOutcome != "unknown" || first.Replayed {
		t.Fatal("stock MCP acceptance changed the reviewed run or claimed receiver completion")
	}
	return first.RunID
}

func verifyStockMCPOnwardStatus(t *testing.T, tools stockExchangeTools, review OnwardReview, action stockOnwardAction) {
	t.Helper()
	status := readStockExchangeJSON[stockOnwardWorkResult](t, tools("onward_status", stockMCPWorkArguments(action, ""), ""))
	if status.RunID != action.RunID || status.Artifact != review.Request.Artifact || status.ObservedState != "queued" || status.ReceiverPersistence != "unknown" {
		t.Fatal("stock MCP stage observation changed the approved custody revision or claimed completion")
	}
}
