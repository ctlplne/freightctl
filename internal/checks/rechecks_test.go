package checks

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestRecheckCanonicalDefinitionMatchesIndependentPythonAndBrowserGolden(t *testing.T) {
	raw, err := os.ReadFile("../../web/tests/fixtures/recheck-definition.json")
	if err != nil {
		t.Fatal(err)
	}
	expected, err := os.ReadFile("../../web/tests/fixtures/recheck-golden.sha256")
	if err != nil {
		t.Fatal(err)
	}
	var definition RecheckDefinition
	if err = json.Unmarshal(raw, &definition); err != nil {
		t.Fatal(err)
	}
	_, hash, err := canonical(definition)
	if err != nil || hash != strings.TrimSpace(string(expected)) {
		t.Fatal("approval hash differs from independent golden", hash, err)
	}
}

func TestConditionalRecheckCanonicalDefinitionRetainsPreviousFileGuard(t *testing.T) {
	raw, err := os.ReadFile("../../web/tests/fixtures/recheck-conditional-definition.json")
	if err != nil {
		t.Fatal(err)
	}
	expected, err := os.ReadFile("../../web/tests/fixtures/recheck-conditional-golden.sha256")
	if err != nil {
		t.Fatal(err)
	}
	var definition RecheckDefinition
	if err = json.Unmarshal(raw, &definition); err != nil {
		t.Fatal(err)
	}
	if definition.Plan.Source.Check.Binding.Target.ExpectedFileID != "00000041-1111-4111-8111-111111111111" || definition.Plan.Target.Command.ExpectedFileID != definition.Plan.Source.File.ID {
		t.Fatal("conditional fixture lost its previous file guard")
	}
	_, hash, err := canonical(definition)
	if err != nil || hash != strings.TrimSpace(string(expected)) {
		t.Fatal("conditional approval differs from independent golden", hash, err)
	}
}
