package checks

import (
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestProducerProjectionReviewPinsIndependentOutputContractAndRejectsSubstitution(t *testing.T) {
	base, row, rules, now := projectionReviewFixture(t)
	base.CurrentPolicy.State = "output_active"
	producer := store.ExchangeParticipant{Tenant: secure.NewID(), Partner: secure.NewID(), Actor: secure.NewID(), AuthorityRevision: base.Plan.Authority, RootPolicyDigest: secure.Digest([]byte(base.Plan.Root))}
	binding := store.ProcessingOutputBinding{Profile: "producer-processing-output-policy-v1", PolicyID: base.Plan.Policy.ID, Version: base.Plan.Policy.Version, Hash: base.Plan.Policy.Hash, Publisher: secure.NewID(), Producer: producer}
	got, err := producerProjectionReview(base, row, rules, now, &binding, producer)
	if err != nil || got.Plan.Schema != 3 || got.Plan.Profile != ProducerProjectionProfile || got.Plan.OutputBinding == nil || *got.Plan.OutputBinding != binding || got.OutputPolicy.State != "output_active" || got.Plan.Context.Policy != base.Plan.Policy {
		t.Fatal("review lost separate producer contract", err)
	}
	if _, err = projectionReview(base, row, rules, now); err == nil {
		t.Fatal("legacy projection reinterpreted an output-only contract")
	}
	for _, mutate := range []func(*store.ProcessingOutputBinding, *store.ExchangeParticipant){
		func(b *store.ProcessingOutputBinding, _ *store.ExchangeParticipant) { b.Version++ },
		func(b *store.ProcessingOutputBinding, _ *store.ExchangeParticipant) { b.PolicyID = secure.NewID() },
		func(b *store.ProcessingOutputBinding, _ *store.ExchangeParticipant) {
			b.Hash = secure.Digest([]byte("other rules"))
		},
		func(_ *store.ProcessingOutputBinding, p *store.ExchangeParticipant) { p.Actor = secure.NewID() },
		func(_ *store.ProcessingOutputBinding, p *store.ExchangeParticipant) { p.AuthorityRevision++ },
		func(_ *store.ProcessingOutputBinding, p *store.ExchangeParticipant) {
			p.RootPolicyDigest = secure.Digest([]byte("/other"))
		},
	} {
		changed, actor := binding, producer
		mutate(&changed, &actor)
		if _, err = producerProjectionReview(base, row, rules, now, &changed, actor); err == nil {
			t.Fatal("substituted output contract/producer approved")
		}
	}
	binding.Producer.Actor = secure.NewID()
	if got.Plan.OutputBinding.Producer != producer {
		t.Fatal("caller changed a reviewed producer snapshot")
	}
}
