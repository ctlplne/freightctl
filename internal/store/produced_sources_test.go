package store

import (
	"encoding/json"
	"strings"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
)

func TestProducedSourcePinsAcceptedRevisionAndExactCurrentProducerWithoutEffectAuthority(t *testing.T) {
	actor := ExchangeParticipant{Tenant: secure.NewID(), Partner: secure.NewID(), Actor: secure.NewID(), AuthorityRevision: 7, RootPolicyDigest: secure.Digest([]byte("/worker"))}
	definition := json.RawMessage(`{"schema_version":2,"kind":"json_records"}`)
	c := &Configuration{ID: secure.NewID(), Version: 1, Hash: strings.Repeat("a", 64), Definition: definition, State: "output_active", Revision: 1}
	b := &ProcessingOutputBinding{Profile: "producer-processing-output-policy-v1", PolicyID: c.ID, Version: c.Version, Hash: c.Hash, Publisher: secure.NewID(), Producer: actor}
	f := &File{ID: secure.NewID(), Size: 17, SHA256: strings.Repeat("b", 64), Policy: JSONRecordsIntakePrefix + c.Hash, EventID: secure.NewID()}
	projection, hash := secure.NewID(), strings.Repeat("c", 64)
	got, err := producedSource(f, c, b, actor, projection, hash)
	if err != nil || got.File != *f || got.ProjectionID != projection || got.ProjectionHash != hash || got.Producer != *b {
		t.Fatal("generated source lineage lost immutable file/intent/producer", err)
	}
	for _, mutate := range []func(*File, *Configuration, *ProcessingOutputBinding, *ExchangeParticipant){
		func(f *File, _ *Configuration, _ *ProcessingOutputBinding, _ *ExchangeParticipant) { f.EventID = "" },
		func(f *File, _ *Configuration, _ *ProcessingOutputBinding, _ *ExchangeParticipant) {
			f.Policy = CSVIntakePrefix + c.Hash
		},
		func(_ *File, c *Configuration, _ *ProcessingOutputBinding, _ *ExchangeParticipant) {
			c.State = "output_revoked"
		},
		func(_ *File, _ *Configuration, b *ProcessingOutputBinding, _ *ExchangeParticipant) { b.Version++ },
		func(_ *File, _ *Configuration, _ *ProcessingOutputBinding, a *ExchangeParticipant) {
			a.Actor = secure.NewID()
		},
		func(_ *File, _ *Configuration, _ *ProcessingOutputBinding, a *ExchangeParticipant) {
			a.AuthorityRevision++
		},
		func(_ *File, _ *Configuration, _ *ProcessingOutputBinding, a *ExchangeParticipant) {
			a.RootPolicyDigest = secure.Digest([]byte("/other"))
		},
	} {
		file, policy, binding, participant := *f, *c, *b, actor
		mutate(&file, &policy, &binding, &participant)
		if _, err := producedSource(&file, &policy, &binding, participant, projection, hash); err == nil {
			t.Fatal("substituted or revoked source lineage accepted")
		}
	}
}
