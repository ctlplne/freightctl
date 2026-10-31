package workflow

import (
	"encoding/json"
	"os"
	"testing"
)

func TestOnboardingTestBrowserAndGoCanonicalDefinition(t *testing.T) {
	data, err := os.ReadFile("../../web/tests/fixtures/onboarding-test.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Selection OnboardingTestPreviewRequest `json:"selection"`
		Preview   OnboardingTestPreview        `json:"preview"`
	}
	if json.Unmarshal(data, &fixture) != nil || !validTestPreview(fixture.Selection) {
		t.Fatal("invalid shared fixture")
	}
	_, hash, err := digest(fixture.Preview.Definition)
	if err != nil || hash != fixture.Preview.Hash {
		t.Fatal("Go/browser definition hash mismatch", hash, fixture.Preview.Hash, err)
	}
	if testPreviewRequest(fixture.Preview.Definition) != fixture.Selection {
		t.Fatal("review selection changed meaning")
	}
}
