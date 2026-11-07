package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/ctlplne/freightctl/internal/workflow"
)

const mcpProtocolVersion = "2026-07-28"
const mcpBodyLimit = 32 << 10

var errMCPInput = errors.New("invalid MCP request")

// Before either JSON library can erase duplicate keys or field aliases, bound
// and inspect the whole control envelope, including nested tool arguments.
func strictMCPJSON(raw []byte) error {
	if len(raw) == 0 || len(raw) > mcpBodyLimit || !utf8.Valid(raw) {
		return errMCPInput
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	tokens := 0
	var walk func(int) error
	walk = func(depth int) error {
		tokens++
		if depth > 16 || tokens > 8192 {
			return errMCPInput
		}
		token, err := d.Token()
		if err != nil || token == nil {
			return errMCPInput
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				name, ok := key.(string)
				tokens++
				fold := strings.ToLower(name)
				if err != nil || !ok || tokens > 8192 || workflow.HasASCIIFieldAlias(name) || seen[fold] {
					return errMCPInput
				}
				seen[fold] = true
				if err = walk(depth + 1); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return errMCPInput
			}
		case '[':
			for d.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return errMCPInput
			}
		default:
			return errMCPInput
		}
		return nil
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errMCPInput
	}
	return nil
}

type mcpEnvelope struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

func mcpFields(raw []byte, allowed ...string) (map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if len(raw) == 0 {
		raw = []byte(`{}`)
	}
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return nil, errMCPInput
	}
	for key := range fields {
		found := false
		for _, want := range allowed {
			if key == want {
				found = true
				break
			}
		}
		if !found {
			return nil, errMCPInput
		}
	}
	return fields, nil
}
func inspectMCPEnvelope(r *http.Request, raw []byte) (*mcpEnvelope, error) {
	if strictMCPJSON(raw) != nil {
		return nil, errMCPInput
	}
	if _, err := mcpFields(raw, "jsonrpc", "id", "method", "params"); err != nil {
		return nil, err
	}
	var e mcpEnvelope
	if json.Unmarshal(raw, &e) != nil || e.JSONRPC != "2.0" || len(e.ID) == 0 || len(e.ID) > 128 || len(e.Params) == 0 || e.Method == "" || len(e.Method) > 128 {
		return nil, errMCPInput
	}
	var id string
	if json.Unmarshal(e.ID, &id) != nil {
		var number json.Number
		if json.Unmarshal(e.ID, &number) != nil {
			return nil, errMCPInput
		}
		n, err := number.Int64()
		if err != nil || n < -9007199254740991 || n > 9007199254740991 {
			return nil, errMCPInput
		}
	}
	var allowed []string
	switch e.Method {
	case "server/discover", "ping":
		allowed = []string{"_meta"}
	case "tools/list":
		allowed = []string{"_meta", "cursor"}
	case "tools/call":
		allowed = []string{"_meta", "name", "arguments"}
	default:
		return &e, nil
	}
	fields, err := mcpFields(e.Params, allowed...)
	if err != nil {
		return nil, err
	}
	var meta map[string]json.RawMessage
	if json.Unmarshal(fields["_meta"], &meta) != nil || meta == nil {
		return nil, errMCPInput
	}
	var version string
	if json.Unmarshal(meta["io.modelcontextprotocol/protocolVersion"], &version) != nil || version == "" {
		return nil, errMCPInput
	}
	var capabilities map[string]json.RawMessage
	if json.Unmarshal(meta["io.modelcontextprotocol/clientCapabilities"], &capabilities) != nil || capabilities == nil {
		return nil, errMCPInput
	}
	return &e, nil
}
func mcpMedia(r *http.Request) bool {
	content, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || content != "application/json" {
		return false
	}
	for key, value := range params {
		if key != "charset" || !strings.EqualFold(value, "utf-8") {
			return false
		}
	}
	jsonOK, eventOK := false, false
	for _, value := range strings.Split(r.Header.Get("Accept"), ",") {
		media, params, err := mime.ParseMediaType(strings.TrimSpace(value))
		if err != nil || params["q"] == "0" {
			continue
		}
		jsonOK = jsonOK || media == "application/json"
		eventOK = eventOK || media == "text/event-stream"
	}
	return jsonOK && eventOK
}
