package workflow

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/ctlplne/freightctl/internal/store"
)

func collectedExchangeFixture(t *testing.T) CollectionView {
	t.Helper()
	raw, err := os.ReadFile("../../web/tests/fixtures/collections.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture map[string]struct {
		View CollectionView `json:"view"`
	}
	if json.Unmarshal(raw, &fixture) != nil {
		t.Fatal("invalid collection fixture")
	}
	return fixture["local"].View
}
func TestCollectedExchangeSourceRequiresCompleteExactManifestAndPrivateInputCorrelation(t *testing.T) {
	v := collectedExchangeFixture(t)
	id := v.Inputs[0].ID
	origin, input, err := collectedExchangeInput(v.Job, v.Inputs, id)
	if err != nil || input.FileID == nil || origin.CollectionID != v.Job.ID || origin.InputID != id || origin.ManifestHash != *v.Job.ManifestHash || origin.FirstCollectionID != input.JobID {
		t.Fatal("exact captured correlation refused", err)
	}
	raw, _ := json.Marshal(origin)
	for _, private := range []string{"source_name", "target_path", "namespace_root", "storage_id", "source_connection", "source_identity", "lease_owner"} {
		if strings.Contains(string(raw), private) {
			t.Fatal("private transport/path fields leaked")
		}
	}
	for _, change := range []func(*CollectionView){
		func(v *CollectionView) { v.Job.Captured = false }, func(v *CollectionView) { v.Job.ManifestHash = nil }, func(v *CollectionView) { h := strings.Repeat("f", 64); v.Job.ManifestHash = &h }, func(v *CollectionView) { v.Inputs[0].Size++ }, func(v *CollectionView) { v.Inputs[0].SHA256 = strings.Repeat("f", 64) }, func(v *CollectionView) { v.Inputs[0].SourceIdentity = "other-source" }, func(v *CollectionView) { v.Inputs[0].FileID = nil }, func(v *CollectionView) { v.Inputs[0].State = "pending" }, func(v *CollectionView) { v.Inputs[0].Identity = "private-path" }, func(v *CollectionView) { v.Inputs[0].Identity = strings.Repeat("f", 64) }, func(v *CollectionView) { v.Inputs = nil },
	} {
		bad := collectedExchangeFixture(t)
		change(&bad)
		if _, _, err = collectedExchangeInput(bad.Job, bad.Inputs, id); err == nil {
			t.Fatal("incomplete or changed collection became an artifact source hint")
		}
	}
	if _, _, err = collectedExchangeInput(v.Job, v.Inputs, "99999999-1111-4111-8111-111111111111"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("unknown input disclosed correlation", err)
	}
}
