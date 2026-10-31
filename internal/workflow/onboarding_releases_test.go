package workflow

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/ctlplne/freightctl/internal/store"
)

func TestOnboardingReleaseGoBrowserCanonicalAndFullRequirementBudget(t *testing.T) {
	data, err := os.ReadFile("../../web/tests/fixtures/onboarding-release.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Preview    OnboardingReleasePreview    `json:"preview"`
		Production OnboardingProductionPreview `json:"production"`
	}
	if err = json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []struct {
		value any
		hash  string
	}{{f.Preview.Definition, f.Preview.Hash}, {f.Production.Definition, f.Production.Hash}, {f.Preview.Tests[0].Definition, f.Preview.Tests[0].Hash}} {
		_, hash, err := digest(candidate.value)
		if err != nil || hash != candidate.hash {
			t.Fatal("canonical hash", hash, candidate.hash, err)
		}
	}
	// The existing 32 KiB event bound must accommodate all 64 requirements;
	// silently reducing the requirement count would change the product contract.
	r := store.OnboardingRelease{Definition: f.Preview.Definition}
	r.Definition.Proofs = nil
	for i := 0; i < 64; i++ {
		p := f.Preview.Definition.Proofs[0]
		p.RequirementID = fmt.Sprintf("%08x-1111-4111-8111-111111111111", i)
		p.TestID = p.RequirementID
		r.Definition.Proofs = append(r.Definition.Proofs, p)
	}
	data, err = json.Marshal(r)
	if err != nil || len(data) > 32<<10 {
		t.Fatal("full requirement event budget", len(data), err)
	}
}
