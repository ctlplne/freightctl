package store

import (
	"bytes"
	"encoding/json"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/namespaceprops"
)

func TestNamespacePropertyContentDoesNotEscapeThroughAuditPayloads(t *testing.T) {
	for _, kind := range []string{"PathAttrsChanged", "PathPublished"} {
		raw := json.RawMessage(`{"path":"/data","namespace_properties":{"{urn:example}p":"<p xmlns=\"urn:example\">private-property-content</p>"}}`)
		event := Event{ID: "event", Kind: kind, Payload: raw}
		redacted := redactOnboardingEvent(event)
		var result struct {
			Redacted bool   `json:"redacted"`
			Hash     string `json:"source_payload_sha256"`
			Reason   string `json:"reason"`
		}
		if json.Unmarshal(redacted.Payload, &result) != nil || !result.Redacted || result.Hash != secure.Digest(raw) || result.Reason != "namespace_property_content" || bytes.Contains(redacted.Payload, []byte("private-property-content")) || !bytes.Equal(event.Payload, raw) {
			t.Fatal("audit access acquired arbitrary property contents or mutated the journal")
		}
	}
	ordinary := Event{Kind: "PathAttrsChanged", Payload: json.RawMessage(`{"path":"/data","mode":416}`)}
	if !bytes.Equal(redactOnboardingEvent(ordinary).Payload, ordinary.Payload) {
		t.Fatal("historical ordinary namespace event meaning changed")
	}
}

func TestNamespacePropertyOptionalFieldsPreserveHistoricalCommandEncoding(t *testing.T) {
	for _, changes := range [][]namespaceprops.Change{nil, {}} {
		wire, err := json.Marshal(PathCommand{Operation: "mkdir", Path: "/inbox", PropertyChanges: changes})
		if err != nil || string(wire) != `{"operation":"mkdir","path":"/inbox"}` {
			t.Fatal("historical request hash input changed", err)
		}
	}
}
