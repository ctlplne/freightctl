package checks

import (
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

// Producer authority is resolved by the transaction, never from a request.
// This pure check then binds the complete immutable output contract into review.
func producerProjectionReview(base *RecheckPreview, row *store.FileCheck, rules RecordProjection, now time.Time, binding *store.ProcessingOutputBinding, producer store.ExchangeParticipant) (*ProjectionPreview, error) {
	if base == nil || binding == nil || binding.Producer != producer || producer.AuthorityRevision != base.Plan.Authority || producer.RootPolicyDigest != secure.Digest([]byte(base.Plan.Root)) {
		return nil, store.ErrRevision
	}
	raw, _, err := canonical(base.CurrentPolicy.Definition)
	if err != nil {
		return nil, err
	}
	ref := base.CurrentPolicy.Reference
	c := &store.Configuration{ID: ref.ID, Version: ref.Version, Hash: ref.Hash, Definition: raw, State: base.CurrentPolicy.State, Revision: 1}
	expected, err := outputPolicyBinding(store.Scope{Tenant: producer.Tenant, Partner: producer.Partner}, binding.Publisher, c, producer)
	if err != nil || *expected != *binding || base.Plan.Policy != ref {
		return nil, store.ErrRevision
	}
	return projectionReviewBound(base, row, rules, now, ProducerProjectionProfile, binding)
}
