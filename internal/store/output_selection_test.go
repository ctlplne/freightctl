package store

import (
	"strings"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
)

func TestProcessingOutputSelectionRequiresExactProducerAuthorityAndContract(t *testing.T) {
	p := ExchangeParticipant{Tenant: secure.NewID(), Partner: secure.NewID(), Actor: secure.NewID(), AuthorityRevision: 9, RootPolicyDigest: secure.Digest([]byte("/worker"))}
	c := &Configuration{ID: secure.NewID(), Version: 3, Hash: strings.Repeat("b", 64), State: "output_active", Revision: 1}
	b := &ProcessingOutputBinding{Profile: "producer-processing-output-policy-v1", PolicyID: c.ID, Version: c.Version, Hash: c.Hash, Publisher: secure.NewID(), Producer: p}
	if err := processingOutputSelection(c, b, p); err != nil {
		t.Fatal("exact producer cannot select its output contract", err)
	}
	for _, change := range []func(*Configuration, *ProcessingOutputBinding, *ExchangeParticipant){
		func(c *Configuration, _ *ProcessingOutputBinding, _ *ExchangeParticipant) { c.State = "output_retired" },
		func(c *Configuration, _ *ProcessingOutputBinding, _ *ExchangeParticipant) { c.State = "active" },
		func(c *Configuration, _ *ProcessingOutputBinding, _ *ExchangeParticipant) { c.Version++ },
		func(c *Configuration, _ *ProcessingOutputBinding, _ *ExchangeParticipant) {
			c.Hash = strings.Repeat("c", 64)
		},
		func(_ *Configuration, b *ProcessingOutputBinding, _ *ExchangeParticipant) { b.Profile = "invented" },
		func(_ *Configuration, b *ProcessingOutputBinding, _ *ExchangeParticipant) { b.Publisher = "" },
		func(_ *Configuration, _ *ProcessingOutputBinding, p *ExchangeParticipant) { p.Actor = secure.NewID() },
		func(_ *Configuration, _ *ProcessingOutputBinding, p *ExchangeParticipant) { p.Partner = secure.NewID() },
		func(_ *Configuration, _ *ProcessingOutputBinding, p *ExchangeParticipant) { p.AuthorityRevision++ },
		func(_ *Configuration, _ *ProcessingOutputBinding, p *ExchangeParticipant) {
			p.RootPolicyDigest = secure.Digest([]byte("/other"))
		},
	} {
		contract, binding, producer := *c, *b, p
		change(&contract, &binding, &producer)
		if processingOutputSelection(&contract, &binding, producer) == nil {
			t.Fatal("changed or unowned output contract selected")
		}
	}
	if processingOutputSelection(nil, b, p) == nil || processingOutputSelection(c, nil, p) == nil {
		t.Fatal("missing output binding selected")
	}
}
