package delivery

import (
	"context"

	"github.com/ctlplne/freightctl/internal/store"
)

type ReviewedObservationTarget struct {
	DeliveryID string
	FileID     string
	Binding    store.ExecutionBinding
}

// ObserveReviewedDelivery runs within the transaction that established the
// original reviewed-run receipt and selected its exact step. This entry point
// can observe the bound final path but cannot acquire its publishing lease.
func (s *Service) ObserveReviewedDelivery(ctx context.Context, t *store.Transaction, target ReviewedObservationTarget, key, meaning string) (*Result, error) {
	if err := t.Require("workflow_execute"); err != nil {
		return nil, err
	}
	prior, err := t.DeliveryReplay(ctx, key, meaning)
	if err != nil {
		return nil, err
	}
	d, spec, err := scopedDelivery(ctx, t, target.DeliveryID, true)
	if err != nil {
		return nil, err
	}
	if spec.Binding == nil || *spec.Binding != target.Binding || d.FileID != target.FileID {
		return nil, store.ErrRevision
	}
	if prior != nil {
		if prior.ID != d.ID || prior.FileID != d.FileID || prior.DefinitionHash != d.DefinitionHash ||
			(prior.State != "ambiguous" && prior.State != "succeeded") {
			return nil, store.ErrIsolation
		}
		if err = t.Reauthorize(ctx); err != nil {
			return nil, err
		}
		return &Result{Delivery: prior, Replayed: true}, nil
	}
	if d.State == "succeeded" {
		return nil, store.ErrState
	}
	if err = s.reconcile(ctx, t, d, spec, false); err != nil {
		return nil, err
	}
	if err = t.DeliveryReceipt(ctx, key, meaning, d); err != nil {
		return nil, err
	}
	return &Result{Delivery: d}, nil
}
