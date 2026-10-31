package workflow

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func TestOnboardingObservationGoBrowserDefinitionAndPreviewShape(t *testing.T) {
	data, err := os.ReadFile("../../web/tests/fixtures/onboarding-observation.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Selection OnboardingObservationSelection `json:"selection"`
		Preview   OnboardingObservationPreview   `json:"preview"`
	}
	if json.Unmarshal(data, &f) != nil {
		t.Fatal("fixture")
	}
	_, hash, err := digest(f.Preview.Definition)
	if err != nil || hash != f.Preview.Hash || observationSelection(f.Preview.Definition) != f.Selection {
		t.Fatal("Go/browser definition meaning", hash, err)
	}
	_, probe, err := digest(f.Preview.Definition.Observer)
	if err != nil || probe != f.Preview.Definition.Probe.Hash {
		t.Fatal("probe binding", err)
	}
	var raw map[string]json.RawMessage
	_ = json.Unmarshal(data, &raw)
	var expected, actual any
	_ = json.Unmarshal(raw["preview"], &expected)
	encoded, err := json.Marshal(f.Preview)
	if err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal(encoded, &actual)
	if !reflect.DeepEqual(expected, actual) {
		t.Fatal("preview flags or source fields changed meaning")
	}
}
