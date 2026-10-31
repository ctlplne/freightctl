package workflow

import (
	"encoding/json"
	"os"
	"testing"
)

func TestOnboardingPrepublicationGoBrowserCanonicalDefinition(t *testing.T) {
	data, err := os.ReadFile("../../web/tests/fixtures/onboarding-prepublication.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Selection OnboardingHandoffSelection `json:"selection"`
		Preview   OnboardingHandoffPreview   `json:"preview"`
	}
	if err = json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	_, hash, err := digest(f.Preview.Definition)
	if err != nil || hash != f.Preview.Hash || handoffSelection(f.Preview.Definition) != f.Selection {
		t.Fatal("handoff browser/Go meaning changed", hash, f.Preview.Hash, err)
	}
	_, source, err := digest(f.Preview.Definition.Source.Dispatch.Definition)
	if err != nil || source != f.Preview.Definition.Source.Dispatch.Hash {
		t.Fatal("source hash", err)
	}
	_, target, err := digest(f.Preview.Definition.Target)
	if err != nil || target != f.Preview.Definition.TargetHash {
		t.Fatal("target hash", err)
	}
}
