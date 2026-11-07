package custody

import (
	"encoding/json"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
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

func TestConditionalReplacementMeaningAndReleaseCommandBindOldCustodyIdentity(t *testing.T) {
	previous := "10000000-1111-4111-8111-111111111111"
	newFile := "20000000-1111-4111-8111-111111111111"
	digest := secure.Digest([]byte("exact replacement"))
	target := UploadTarget{Path: "/replaced.txt", MatchFile: &FileCondition{ID: previous, SHA256: digest}}
	meaning := pathMeaning(17, digest, "/replaced.txt", &target)
	other := target
	other.MatchFile = &FileCondition{ID: newFile, SHA256: digest}
	if meaning == pathMeaning(17, digest, "/replaced.txt", &other) {
		t.Fatal("equal bytes under another custody identity reused a replacement key")
	}
	other.MatchFile = &FileCondition{ID: previous, SHA256: secure.Digest([]byte("other"))}
	if meaning == pathMeaning(17, digest, "/replaced.txt", &other) {
		t.Fatal("source digest disappeared from replacement meaning")
	}
	revision := int64(7)
	target.ExpectedRevision = &revision
	command := targetCommand(&target, newFile)
	if command.Operation != "publish" || !command.Replace || command.FileID != newFile || command.ExpectedFileID != previous || command.ExpectedRevision == nil || *command.ExpectedRevision != revision {
		t.Fatal("pending intake release lost its old identity or namespace revision")
	}
	encoded, err := json.Marshal(command)
	var retained store.PathCommand
	if err != nil || json.Unmarshal(encoded, &retained) != nil || retained.ExpectedFileID != previous {
		t.Fatal("persisted pending command lost the exact previous identity")
	}
	ordinary, err := json.Marshal(store.PathCommand{Operation: "publish", Path: "/kept.txt", FileID: newFile})
	if err != nil || string(ordinary) != `{"operation":"publish","path":"/kept.txt","file_id":"`+newFile+`"}` {
		t.Fatal("ordinary namespace commands changed historical request meanings")
	}
}
