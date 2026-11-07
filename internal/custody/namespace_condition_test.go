package custody

import (
	"encoding/json"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
)

func TestConditionalTargetPreservesHistoricalOrdinaryUploadMeanings(t *testing.T) {
	ordinary := UploadTarget{Path: "/kept.txt"}
	raw, err := json.Marshal(ordinary)
	if err != nil || string(raw) != `{"Path":"/kept.txt","ExpectedRevision":null,"Mode":null,"Modified":null}` {
		t.Fatal("ordinary target changed its historical request meaning")
	}
	digest := secure.Digest([]byte("inert"))
	first := pathMeaning(5, digest, "/kept.txt", &ordinary)
	conditional := ordinary
	conditional.RequireAbsent = true
	if first == pathMeaning(5, digest, "/kept.txt", &conditional) {
		t.Fatal("absent-resource condition disappeared from the exact request meaning")
	}
}
