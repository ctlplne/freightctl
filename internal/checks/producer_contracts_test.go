package checks

import (
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestProducerProcessingContractsDescribeExactSelectionWithoutInputOrEffectGrant(t *testing.T) {
	base, row, _, now := projectionReviewFixture(t)
	base.CurrentPolicy.State = "output_active"
	producer := store.ExchangeParticipant{Tenant: secure.NewID(), Partner: secure.NewID(), Actor: secure.NewID(), AuthorityRevision: base.Plan.Authority, RootPolicyDigest: secure.Digest([]byte(base.Plan.Root))}
	b := store.ProcessingOutputBinding{Profile: "producer-processing-output-policy-v1", PolicyID: base.Plan.Policy.ID, Version: base.Plan.Policy.Version, Hash: base.Plan.Policy.Hash, Publisher: secure.NewID(), Producer: producer}
	view, err := processingContractsForProducer(base, row, now, &b, producer)
	if err != nil || view.Profile != "record-processing-contracts-v2" || view.OutputBinding == nil || *view.OutputBinding != b || view.Source.ID != row.FileID || view.OutputPolicy.Reference != base.Plan.Policy || view.OutputPolicy.State != "output_active" {
		t.Fatal("selected contract metadata lost exact owner/policy/source binding", err)
	}
	changed := producer
	changed.Actor = secure.NewID()
	if _, err = processingContractsForProducer(base, row, now, &b, changed); err == nil {
		t.Fatal("metadata selection borrowed another producer's contract")
	}
	b.Version++
	if _, err = processingContractsForProducer(base, row, now, &b, producer); err == nil {
		t.Fatal("metadata selection substituted a policy version")
	}
	if _, err = processingContracts(base, row, now); err == nil {
		t.Fatal("default profile reinterpreted an output-only contract")
	}
}
