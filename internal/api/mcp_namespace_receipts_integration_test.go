//go:build integration

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/namespaceprops"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestMCPStockClientRecoversMetadataOnlyNamespaceReceiptWithoutRepeatingDelete(t *testing.T) {
	service, scope, admin, server := browserAPI(t, time.Minute)
	cookie, csrf := loginBrowser(t, server, scope, admin)
	prefix := "/v1/tenants/" + scope.Tenant + "/partners/" + scope.Partner
	other, _ := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "list", "manage_paths"})
	root, err := service.PathCommand(t.Context(), scope, "mcp-receipt-create", store.PathCommand{Operation: "mkdir", Path: "/mcp-receipt"})
	if err != nil {
		t.Fatal(err)
	}
	const contentCanary = "PRIVATE_RECEIPT_PROPERTY_CONTENT_CANARY"
	root, err = service.PathCommand(t.Context(), scope, "mcp-receipt-properties", store.PathCommand{Operation: "properties", Path: root.Entry.Path, ExpectedEntryID: root.Entry.ID, ExpectedRevision: &root.Entry.Revision, PropertyChanges: []namespaceprops.Change{{Operation: "set", Property: `<label xmlns="urn:example">` + contentCanary + `</label>`}}})
	if err != nil {
		t.Fatal(err)
	}
	selection := store.PathCommand{Operation: "remove_tree", Path: root.Entry.Path, ExpectedEntryID: root.Entry.ID, ExpectedRevision: &root.Entry.Revision}
	removed, err := service.PathCommand(t.Context(), scope, "mcp-receipt-delete", selection)
	if err != nil {
		t.Fatal(err)
	}
	counts := func() [2]int64 {
		t.Helper()
		tx, err := service.DB.Begin(t.Context(), scope)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Tx.Rollback(t.Context())
		var result [2]int64
		if err = tx.Tx.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM events),(SELECT count(*) FROM namespace_commands)`).Scan(&result[0], &result[1]); err != nil {
			t.Fatal(err)
		}
		return result
	}
	before := counts()
	connect := func(token *secure.Secret) *mcp.ClientSession {
		t.Helper()
		client := mcp.NewClient(&mcp.Implementation{Name: "freightctl-stock-receipt-caller", Version: "1"}, &mcp.ClientOptions{Capabilities: &mcp.ClientCapabilities{}})
		httpClient := *server.Client()
		httpClient.Timeout = 15 * time.Second
		httpClient.Transport = mcpCredentialTransport{next: httpClient.Transport, token: token, origin: server.URL}
		httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		session, err := client.Connect(t.Context(), &mcp.StreamableClientTransport{Endpoint: server.URL + prefix + "/mcp", HTTPClient: &httpClient, MaxRetries: -1}, &mcp.ClientSessionOptions{ProtocolVersion: mcpProtocolVersion})
		if err != nil {
			t.Fatal("stock receipt caller discovery failed", err)
		}
		t.Cleanup(func() { session.Close() })
		return session
	}
	client := connect(admin)
	unrelated := connect(other)
	catalog, err := client.ListTools(t.Context(), &mcp.ListToolsParams{})
	if err != nil || len(catalog.Tools) != 44 || catalog.TTLMs != 0 || catalog.CacheScope != "private" {
		t.Fatal("stock receipt caller lacks exact private catalog", err)
	}
	call := func(ctx context.Context, session *mcp.ClientSession, key string, expected bool) *mcp.CallToolResult {
		t.Helper()
		result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "freightctl.namespace_receipt", Arguments: map[string]any{"command": selection, "request_key": key}})
		if err != nil || result == nil || result.IsError == expected {
			t.Fatal("stock receipt call violated expected private outcome", err)
		}
		return result
	}
	result := call(t.Context(), client, "mcp-receipt-delete", true)
	var receipt store.PathCommandReceipt
	mcpDecodeResult(t, result, &receipt)
	if receipt.Profile != "namespace-command-receipt-v1" || receipt.Observation != "original-commit-not-current-state" || receipt.Result.Replayed || !receipt.Result.Entry.Deleted || receipt.Result.Entry.ID != removed.Entry.ID || receipt.Result.Changed != 1 || !store.ValidID(receipt.CompletedEventID) {
		t.Fatal("MCP receipt invented current state or lost exact original deletion")
	}
	wire, err := json.Marshal(result)
	if err != nil || bytes.Contains(wire, []byte(contentCanary)) {
		t.Fatal("metadata-only receipt disclosed stored XML content")
	}
	call(t.Context(), client, "mcp-receipt-delete", true)
	call(t.Context(), unrelated, "mcp-receipt-delete", false)
	call(t.Context(), client, "mcp-receipt-unknown", false)
	if counts() != before {
		t.Fatal("MCP receipt reads repeated commands or emitted domain events")
	}
	if strings.Contains(string(wire), "https://") {
		t.Fatal("metadata-only receipt acquired a network capability")
	}
}
