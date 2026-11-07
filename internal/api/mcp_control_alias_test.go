package api

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ctlplne/freightctl/internal/custody"
)

const mcpAliasEnvelope = `{"jsonrpc":"2.0","id":"alias-boundary","method":"tools/call","params":{"name":"guard-probe","arguments":{"request":{"expected_revision":0,"expected_reviſion":1}},"_meta":{"io.modelcontextprotocol/protocolVersion":"` + mcpProtocolVersion + `","io.modelcontextprotocol/clientCapabilities":{}}}}`

func TestMCPControlRejectsUnicodeASCIIFieldAliasesBeforeTypedDecoding(t *testing.T) {
	for _, raw := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"no execution","arguments":{"expected_revision":0,"expected_reviſion":1}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"no execution","arguments":{"expected_revision":0,"expected_revi\u017fion":1}}}`,
	} {
		if err := strictMCPJSON([]byte(raw)); err == nil {
			t.Error("MCP control preserved an ASCII field alias for a later typed decoder")
		}
	}
}

func TestMCPControlKeepsCamelCaseProtocolMetadataAndUnicodeData(t *testing.T) {
	raw := `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"_meta":{"clientVersion":"synthetic","étiquette":"été","σ":"réception"}}}`
	if err := strictMCPJSON([]byte(raw)); err != nil {
		t.Fatal("ASCII field-alias guard changed valid protocol metadata or Unicode data", err)
	}
}

func TestMCPControlAliasFailsBeforeIdentityOrToolResources(t *testing.T) {
	r := httptest.NewRequest("POST", "https://localhost/v1/tenants/00000001-1111-4111-8111-111111111111/partners/00000002-1111-4111-8111-111111111111/mcp", strings.NewReader(mcpAliasEnvelope))
	r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 64))
	r.Header.Set("Origin", "https://localhost")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	r.Header.Set("MCP-Protocol-Version", mcpProtocolVersion)
	r.Header.Set("Mcp-Method", "tools/call")
	r.Header.Set("Mcp-Name", "guard-probe")
	w := httptest.NewRecorder()
	New(&custody.Service{}, nil).ServeHTTP(w, r)
	if w.Code != 400 || !strings.Contains(w.Body.String(), `"error":"invalid_mcp_envelope"`) {
		t.Fatal("MCP alias reached identity resources or a different admission gate", w.Code)
	}
}
