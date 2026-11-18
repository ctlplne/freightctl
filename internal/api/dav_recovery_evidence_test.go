package api

import (
	"errors"
	"testing"

	"github.com/ctlplne/freightctl/internal/store"
)

type davRecoveryEvidence struct {
	MetadataHash, ReceiverHash string
	Writes, Reads, StageChecks int
}

func davAmbiguousRepeatWasRefused(returned *store.Delivery, err error, before, after davRecoveryEvidence) bool {
	return errors.Is(err, store.ErrState) && returned == nil && before.MetadataHash != "" && before.ReceiverHash != "" && before == after
}

func TestDAVAmbiguousRepeatRequiresExactRefusalAndUnchangedEvidence(t *testing.T) {
	before := davRecoveryEvidence{MetadataHash: "all-original-domain-rows", ReceiverHash: "exact-retained-receiver-bytes", Writes: 2, Reads: 1, StageChecks: 1}
	if !davAmbiguousRepeatWasRefused(nil, store.ErrState, before, before) {
		t.Fatal("original proof rejects a repeat-work refusal with unchanged complete state")
	}
	for _, bad := range []davRecoveryEvidence{
		{MetadataHash: "changed-event-or-intent", ReceiverHash: before.ReceiverHash, Writes: 2, Reads: 1, StageChecks: 1},
		{MetadataHash: before.MetadataHash, ReceiverHash: "changed-receiver", Writes: 2, Reads: 1, StageChecks: 1},
		{MetadataHash: before.MetadataHash, ReceiverHash: before.ReceiverHash, Writes: 3, Reads: 1, StageChecks: 1},
		{MetadataHash: before.MetadataHash, ReceiverHash: before.ReceiverHash, Writes: 2, Reads: 2, StageChecks: 1},
		{MetadataHash: before.MetadataHash, ReceiverHash: before.ReceiverHash, Writes: 2, Reads: 1, StageChecks: 2},
		{ReceiverHash: before.ReceiverHash, Writes: 2, Reads: 1, StageChecks: 1},
		{MetadataHash: before.MetadataHash, Writes: 2, Reads: 1, StageChecks: 1},
	} {
		if davAmbiguousRepeatWasRefused(nil, store.ErrState, before, bad) {
			t.Fatal("changed,missing or extra state/activity accepted as a no-effect refusal")
		}
	}
	for _, err := range []error{nil, errors.New("unclassified failure")} {
		if davAmbiguousRepeatWasRefused(nil, err, before, before) {
			t.Fatal("missing or different refusal accepted")
		}
	}
	if davAmbiguousRepeatWasRefused(&store.Delivery{State: "ambiguous", Attempts: 1, Fence: 1}, store.ErrState, before, before) {
		t.Fatal("error accompanied by an unexpected result accepted")
	}
}
