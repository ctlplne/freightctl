package workflow

import (
	"encoding/json"
	"github.com/ctlplne/freightctl/internal/store"
	"os"
	"reflect"
	"testing"
)

func TestOnboardingApprovalGoBrowserDisclosureAndDefinitionHash(t *testing.T) {
	data, err := os.ReadFile("../../web/tests/fixtures/onboarding-approval.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Selection OnboardingApprovalSelection    `json:"selection"`
		Preview   OnboardingApprovalPreview      `json:"preview"`
		Review    store.OnboardingApprovalReview `json:"review"`
	}
	if json.Unmarshal(data, &f) != nil {
		t.Fatal("fixture")
	}
	_, hash, err := digest(f.Preview.Definition)
	if err != nil || hash != f.Preview.Hash || hash != f.Review.Hash {
		t.Fatal("review hash differs", err)
	}
	_, hash, err = digest(f.Preview.Definition.Release)
	if err != nil || hash != f.Selection.Hash || f.Selection.ReleaseID != f.Review.Definition.ReleaseID || f.Selection.ReviewerID != f.Review.Reviewer {
		t.Fatal("release/reviewer binding", err)
	}
	var raw map[string]json.RawMessage
	json.Unmarshal(data, &raw)
	var expected, actual any
	json.Unmarshal(raw["preview"], &expected)
	b, _ := json.Marshal(f.Preview)
	json.Unmarshal(b, &actual)
	if !reflect.DeepEqual(expected, actual) {
		t.Fatal("preview flags or disclosure changed")
	}
}
