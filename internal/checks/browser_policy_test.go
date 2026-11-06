package checks

import (
	"encoding/json"
	"os"
	"testing"
)

// Both languages consume these same policy definitions. This side reruns the
// actual Go normalization so a server change cannot leave a stale browser-only
// golden test green. The protected fixture includes literal Unicode and exact
// signer/scanner references; no real credentials or inference are involved.
func TestBrowserIntakePolicyGoldenMatchesCurrentGoNormalization(t *testing.T) {
	for _, name := range []string{"intake-policy.json", "intake-policy-protected.json", "intake-policy-json-records.json"} {
		t.Run(name, func(t *testing.T) {
			wire, err := os.ReadFile("../../web/tests/fixtures/" + name)
			if err != nil {
				t.Fatal(err)
			}
			var fixture struct {
				Definition Policy `json:"definition"`
				Hash       string `json:"definition_hash"`
			}
			if err = json.Unmarshal(wire, &fixture); err != nil {
				t.Fatal(err)
			}
			definition, err := Normalize(fixture.Definition)
			if err != nil {
				t.Fatal(err)
			}
			_, hash, err := canonical(definition)
			if err != nil || hash != fixture.Hash {
				t.Fatal("current Go policy hash differs from the browser contract", err)
			}
		})
	}
}
