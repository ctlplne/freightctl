package workflow

import (
	"context"
	"errors"
	"time"

	"github.com/ctlplne/freightctl/internal/store"
)

type CollectionReadiness struct {
	WorkDue    bool   `json:"work_due"`
	RouteReady bool   `json:"route_ready"`
	Reason     string `json:"reason"`
}

// CollectionReady only observes. A poll creates no events or command receipts
// while a lease, intake review or downstream queue prevents useful work.
// Every effect still repeats the authoritative checks in its own transaction.
func (s *Service) CollectionReady(ctx context.Context, scope store.Scope, id string) (*CollectionReadiness, error) {
	if !store.ValidID(id) {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.collectionRead(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if err = t.Require("workflow_execute"); err != nil {
		return nil, err
	}
	j, err := t.Collection(ctx, id, false)
	if err != nil {
		return nil, err
	}
	d, err := collectionDefinition(j)
	if err != nil {
		return nil, err
	}
	now, err := t.DatabaseTime(ctx)
	if err != nil {
		return nil, err
	}
	r := &CollectionReadiness{Reason: "collection_policy_or_cutoff"}
	if !j.Deadline.After(now) || j.State == "cancelled" || j.State == "expired" {
		return r, t.Tx.Commit(ctx)
	}
	if err = t.CollectionDefinitionCurrent(ctx, j.Definition); errors.Is(err, store.ErrCollection) {
		return r, t.Tx.Commit(ctx)
	} else if err != nil {
		return nil, err
	}
	if err = s.checkStorage(d.StorageID); err != nil {
		return nil, err
	}
	if !j.Captured {
		r.Reason = "collection_lease_cadence_or_manual_recovery"
		r.WorkDue = j.Attempts < 8 && !j.Next.After(now) && (j.State == "queued" || j.State == "retry" || (j.State == "reading" && j.Until != nil && !j.Until.After(now)))
		return r, t.Tx.Commit(ctx)
	}
	r.Reason = "collection_has_no_pending_routes"
	_, w, err := approved(ctx, t, d.Workflow)
	if err != nil {
		return nil, err
	}
	if len(d.Effects) == 0 && w.Schema == 1 {
		return r, t.Tx.Commit(ctx)
	}
	if len(d.Effects) > 0 {
		if err = t.Require("deliver"); err != nil {
			return nil, err
		}
	}
	inputs, err := t.CollectionInputs(ctx, j)
	if err != nil {
		return nil, err
	}
	for _, input := range inputs {
		if input.JobID != j.ID {
			continue
		}
		if input.FileID == nil {
			return nil, store.ErrState
		}
		if err = t.FileAvailable(ctx, *input.FileID); errors.Is(err, store.ErrState) {
			r.Reason = "whole_batch_intake_required"
			return r, t.Tx.Commit(ctx)
		} else if err != nil {
			return nil, err
		}
		if input.State == "accepted" {
			entry, err := t.Entry(ctx, input.Target)
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				return nil, err
			}
			if entry == nil || entry.Kind != "file" || entry.FileID != *input.FileID {
				r.Reason = "collected_file_not_published"
				return r, t.Tx.Commit(ctx)
			}
			if err = t.FileAccessible(ctx, *input.FileID); err != nil {
				return nil, err
			}
			r.RouteReady = true
		}
	}
	if r.RouteReady {
		counts := map[string]int{}
		if w.Schema == 2 {
			counts, err = s.collectionRoutingCounts(ctx, t, j, d, w, inputs)
			if errors.Is(err, ErrRouting) {
				r.RouteReady = false
				r.Reason = "routing_decision_required"
				return r, t.Tx.Commit(ctx)
			} else if err != nil {
				return nil, err
			}
		}
		r.RouteReady = false
		r.Reason = "delivery_capacity_required"
		for _, input := range inputs {
			if input.JobID != j.ID || input.State != "accepted" {
				continue
			}
			needed := len(d.Effects)
			if w.Schema == 2 {
				needed = counts[input.ID]
			}
			if needed == 0 {
				r.RouteReady = true
			} else if err = t.DeliveryCapacity(ctx, needed); err == nil {
				r.RouteReady = true
			} else if !errors.Is(err, store.ErrLimit) {
				return nil, err
			}
			if r.RouteReady {
				r.Reason = "ordinary_routes_ready"
				break
			}
		}
	}
	return r, t.Tx.Commit(ctx)
}
