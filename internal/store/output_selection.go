package store

import (
	"context"
	"encoding/hex"
	"errors"

	secure "github.com/ctlplne/freightctl/internal/crypto"
)

// Selection is a current contract observation. It grants no input access,
// approval, processing, release or delivery authority.
func processingOutputSelection(c *Configuration, b *ProcessingOutputBinding, producer ExchangeParticipant) error {
	if c == nil || b == nil || c.State != "output_active" || c.Revision != 1 || !ValidID(c.ID) || c.Version < 1 || len(c.Hash) != 64 || b.Profile != "producer-processing-output-policy-v1" || b.PolicyID != c.ID || b.Version != c.Version || b.Hash != c.Hash || !ValidID(b.Publisher) || b.Producer != producer || !ValidID(producer.Tenant) || !ValidID(producer.Partner) || !ValidID(producer.Actor) || producer.AuthorityRevision < 1 || len(producer.RootPolicyDigest) != 64 {
		return ErrRevision
	}
	if _, err := hex.DecodeString(c.Hash); err != nil {
		return ErrIsolation
	}
	if _, err := hex.DecodeString(producer.RootPolicyDigest); err != nil {
		return ErrIsolation
	}
	return nil
}

// ProcessingPolicy resolves the exact task reference. An output family can be
// selected only by its current producer. The ordinary default remains a distinct
// fallback lane and is never substituted for a stale explicit output reference.
func (t *Transaction) ProcessingPolicy(ctx context.Context, ref OnboardingReference) (*Configuration, error) {
	if !ValidID(ref.ID) || ref.Version < 1 || len(ref.Hash) != 64 {
		return nil, ErrRevision
	}
	if _, err := hex.DecodeString(ref.Hash); err != nil {
		return nil, ErrRevision
	}
	current, err := t.IntakePolicy(ctx, false)
	if err != nil {
		return nil, err
	}
	if current != nil && current.State == "active" && (OnboardingReference{ID: current.ID, Version: current.Version, Hash: current.Hash}) == ref {
		return current, nil
	}
	c, err := t.ProcessingOutputHead(ctx, ref.ID, false)
	if err != nil {
		return nil, err
	}
	if c == nil || c.Version != ref.Version || c.Hash != ref.Hash {
		return nil, ErrRevision
	}
	b, err := t.ProcessingOutputBinding(ctx, c.ID, c.Version)
	if errors.Is(err, ErrNotFound) {
		return nil, ErrRevision
	}
	if err != nil {
		return nil, err
	}
	producer := ExchangeParticipant{Tenant: t.Scope.Tenant, Partner: t.Scope.Partner, Actor: t.Actor, AuthorityRevision: t.AuthorityRevision, RootPolicyDigest: secure.Digest([]byte(t.Root))}
	if err = processingOutputSelection(c, b, producer); err != nil {
		return nil, err
	}
	actual, err := t.ProcessingOutputProducer(ctx, t.Actor)
	if errors.Is(err, ErrNotFound) {
		return nil, ErrRevision
	}
	if err != nil {
		return nil, err
	}
	if actual != producer {
		return nil, ErrRevision
	}
	return c, nil
}
