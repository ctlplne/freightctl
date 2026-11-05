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
		Request   ExchangeRequest `json:"request"`
		Canonical string          `json:"canonical"`
		SHA256    string          `json:"sha256"`
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	data, hash, err := CanonicalExchangeRequest(fixture.Request, ExchangeLimits{MaxArtifactBytes: 1024, MaxLifetime: time.Hour, MaxSenders: 16})
	if err != nil || string(data) != fixture.Canonical || hash != fixture.SHA256 {
		t.Fatal("browser fixture does not describe actual server canonical meaning", err)
	}
}
