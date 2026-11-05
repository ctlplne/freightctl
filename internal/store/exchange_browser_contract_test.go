package store

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestExchangeBrowserCanonicalFixtureMatchesServerBytes(t *testing.T) {
	raw, err := os.ReadFile("../../web/tests/fixtures/artifact-exchange.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Request           ExchangeRequest            `json:"request"`
		Canonical         string                     `json:"canonical"`
		SHA256            string                     `json:"sha256"`
		Endpoint          ExchangeEndpointDefinition `json:"endpoint"`
		EndpointCanonical string                     `json:"endpoint_canonical"`
		EndpointSHA256    string                     `json:"endpoint_sha256"`
		Closure           ExchangeClosureCommand     `json:"closure"`
		ClosureCanonical  string                     `json:"closure_canonical"`
		ClosureSHA256     string                     `json:"closure_sha256"`
		EndpointCommands  []struct {
			Command   ExchangeEndpointCommand `json:"command"`
			Canonical string                  `json:"canonical"`
			SHA256    string                  `json:"sha256"`
		} `json:"endpoint_commands"`
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.EndpointCommands) != 3 {
		t.Fatal("missing endpoint command canonical fixture")
	}
	for _, sample := range fixture.EndpointCommands {
		command, hash, err := canonicalExchangeEndpointCommand(sample.Command, ExchangeLimits{MaxLifetime: time.Hour, MaxSenders: 16})
		wire, marshalErr := json.Marshal(command)
		if err != nil || marshalErr != nil || string(wire) != sample.Canonical || hash != sample.SHA256 {
			t.Fatal("browser endpoint command differs from exact server meaning", err, marshalErr)
		}
	}

	data, hash, err := CanonicalExchangeRequest(fixture.Request, ExchangeLimits{MaxArtifactBytes: 1024, MaxLifetime: time.Hour, MaxSenders: 16})
	if err != nil || string(data) != fixture.Canonical || hash != fixture.SHA256 {
		t.Fatal("browser fixture does not describe actual server canonical meaning", err)
	}
	data, hash, err = CanonicalExchangeEndpoint(fixture.Endpoint, ExchangeLimits{MaxArtifactBytes: 1024, MaxLifetime: time.Hour, MaxSenders: 16})
	if err != nil || string(data) != fixture.EndpointCanonical || hash != fixture.EndpointSHA256 {
		t.Fatal("browser endpoint fixture differs from actual server canonical meaning", err)
	}
	data, hash, err = CanonicalExchangeClosure(fixture.Closure)
	if err != nil || string(data) != fixture.ClosureCanonical || hash != fixture.ClosureSHA256 {
		t.Fatal("browser closure fixture differs from exact server command meaning", err)
	}
}
