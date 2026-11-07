package checks

import (
	"encoding/json"
	"testing"

	"github.com/ctlplne/freightctl/internal/store"
)

func TestRecheckPendingPublicationRetainsPreviousFileIdentityAfterCopy(t *testing.T) {
	parent := store.PathEntry{ID: "10000000-1111-4111-8111-111111111111", Revision: 1}
	entry := store.PathEntry{ID: "20000000-1111-4111-8111-111111111111", FileID: "30000000-1111-4111-8111-111111111111", Revision: 1, Mode: 0640, Kind: "file"}
	target := recheckPublicationTarget("/checked.csv", &parent, &entry)
	// CopyRecheck persists only Command in the held child's CheckBinding.
	// The preview's EntryID does not survive in that later release contract.
	binding := store.CheckBinding{Target: &target.Command}
	raw, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	var retained store.CheckBinding
	if json.Unmarshal(raw, &retained) != nil || retained.Target.ExpectedFileID != entry.FileID {
		t.Fatal("held recheck release lost the previous custody identity")
	}
	if !retained.Target.Replace || retained.Target.ExpectedRevision == nil || *retained.Target.ExpectedRevision != entry.Revision || target.EntryID != entry.ID || target.ParentID != parent.ID {
		t.Fatal("existing namespace snapshot guards changed")
	}
	entry.Revision++
	entry.Mode = 0600
	if *target.Command.ExpectedRevision != 1 || *target.Command.Mode != 0640 {
		t.Fatal("review did not freeze its revision and mode")
	}
	absent := recheckPublicationTarget("/absent.csv", &parent, nil)
	if absent.Command.ExpectedFileID != "" || absent.Command.ExpectedRevision != nil || absent.Command.Replace {
		t.Fatal("absent publication became a replacement")
	}
}
