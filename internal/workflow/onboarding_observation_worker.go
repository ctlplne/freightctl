package workflow

import (
	"context"
	"sync"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/delivery"
	"github.com/ctlplne/freightctl/internal/store"
)

// One approved record authorizes one contact. Terminal/expired work-key replay
// never contacts again. A new observation requires a fresh separate review.
func (s *Service) WorkOnboardingObservation(ctx context.Context, scope store.Scope, id, key string, r OnboardingProbeWorkRequest) (*OnboardingObservationView, error) {
	if !store.ValidID(id) || !keyPattern.MatchString(key) || !hashPattern.MatchString(r.Hash) {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	authority, err := s.testBegin(ctx, scope, false)
	if err != nil {
		return nil, err
	}
	if err = authority.Require("workflow_execute"); err == nil {
		err = authority.Reauthorize(ctx)
	}
	if err == nil {
		err = authority.Tx.Commit(ctx)
	} else {
		_ = authority.Tx.Rollback(ctx)
	}
	if err != nil {
		return nil, err
	}
	admission, err := s.OnboardingObservationStatus(ctx, scope, id)
	if err != nil {
		return nil, err
	}
	if admission.Observation.Hash != r.Hash {
		return nil, store.ErrConflict
	}
	slotCheck := func() error { return nil }
	if admission.Observation.State == "approved" && admission.Current {
		var release func()
		slotCheck, release, err = s.Custody.DB.OnboardingObservationWorkerSlot(ctx)
		if err != nil {
			return nil, err
		}
		defer release()
	}
	t, err := s.testBegin(ctx, scope, false)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if err = t.Require("workflow_execute"); err != nil {
		return nil, err
	}
	o, err := t.OnboardingObservation(ctx, id, true)
	if err != nil {
		return nil, err
	}
	if o.Hash != r.Hash || (o.WorkerKey != "" && o.WorkerKey != key) {
		return nil, store.ErrConflict
	}
	now, err := t.DatabaseTime(ctx)
	if err != nil {
		return nil, err
	}
	finish := func(state, code string) (*OnboardingObservationView, error) {
		previous := o.Revision
		o.Revision++
		o.State = state
		o.Result = observationResult(code)
		o.CompletedAt = &now
		if err := t.SaveOnboardingObservation(ctx, o, previous); err != nil {
			return nil, err
		}
		v, err := s.observationView(ctx, t, o)
		if err != nil {
			return nil, err
		}
		if err = t.Reauthorize(ctx); err != nil {
			return nil, err
		}
		return v, t.Tx.Commit(ctx)
	}
	if o.State == "running" && o.LeaseUntil != nil && !now.Before(*o.LeaseUntil) {
		return finish("expired", "lease_expired")
	}
	if o.State == "proposed" {
		return nil, store.ErrState
	}
	if o.State != "approved" {
		v, err := s.observationView(ctx, t, o)
		if err != nil {
			return nil, err
		}
		if err = t.Reauthorize(ctx); err != nil {
			return nil, err
		}
		return v, t.Tx.Commit(ctx)
	}
	if admission.Observation.State != "approved" {
		return nil, store.ErrRevision
	}
	o.WorkerKey = key
	preview, connection, err := s.observationPreview(ctx, t, observationSelection(o.Definition))
	if err != nil {
		if bindingChanged(err) {
			return finish("blocked", "binding_changed")
		}
		return nil, err
	}
	if preview.Hash != o.Hash {
		return finish("blocked", "binding_changed")
	}
	if !admission.Current {
		return nil, store.ErrRevision
	}
	owner := secure.NewID()
	lease := now.Add(30 * time.Second)
	o.Owner = owner
	o.StartedAt = &now
	o.LeaseUntil = &lease
	o.State = "running"
	o.Revision++
	o.Result = observationResult("observing")
	if err = t.SaveOnboardingObservation(ctx, o, 2); err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	if err = t.Tx.Commit(ctx); err != nil {
		return nil, err
	}
	network, stop := context.WithCancel(ctx)
	var mu sync.Mutex
	check := func() error {
		mu.Lock()
		defer mu.Unlock()
		if err := network.Err(); err != nil {
			return err
		}
		if err := slotCheck(); err != nil {
			return err
		}
		current, err := s.testBegin(network, scope, false)
		if err != nil {
			return err
		}
		defer current.Tx.Rollback(network)
		if err = current.Require("workflow_execute"); err != nil {
			return err
		}
		row, err := current.OnboardingObservation(network, id, false)
		if err != nil {
			return err
		}
		at, err := current.DatabaseTime(network)
		if err != nil {
			return err
		}
		if row.State != "running" || row.Revision != 3 || row.Owner != owner || row.WorkerKey != key || row.Hash != r.Hash || row.LeaseUntil == nil || !at.Before(*row.LeaseUntil) {
			return store.ErrRevision
		}
		v, _, err := s.observationPreview(network, current, observationSelection(row.Definition))
		if err != nil {
			return err
		}
		if v.Hash != row.Hash {
			return store.ErrRevision
		}
		if err = current.Reauthorize(network); err != nil {
			return err
		}
		return current.Tx.Commit(network)
	}
	done, closed := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(closed)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-network.Done():
				return
			case <-ticker.C:
				if check() != nil {
					stop()
					return
				}
			}
		}
	}()
	verified := delivery.ObserveSFTP(network, connection.Destination, connection.Directory, o.Definition.Source.Delivery.ID+"-"+o.Definition.Source.Dispatch.Definition.Effect.Filename, o.Definition.Wire.SHA256, o.Definition.Wire.Size, check)
	close(done)
	stop()
	<-closed
	if err = slotCheck(); err != nil {
		return nil, err
	}
	final, err := s.testBegin(ctx, scope, false)
	if err != nil {
		return nil, err
	}
	defer final.Tx.Rollback(ctx)
	if err = final.Require("workflow_execute"); err != nil {
		return nil, err
	}
	current, err := final.OnboardingObservation(ctx, id, true)
	if err != nil {
		return nil, err
	}
	if current.State != "running" || current.Revision != 3 || current.Owner != owner || current.WorkerKey != key || current.Hash != r.Hash {
		return nil, store.ErrRevision
	}
	at, err := final.DatabaseTime(ctx)
	if err != nil {
		return nil, err
	}
	current.CompletedAt = &at
	current.Revision++
	current.State = "unconfirmed"
	current.Result = observationResult("remote_postcondition_not_confirmed")
	if current.LeaseUntil == nil || !at.Before(*current.LeaseUntil) {
		current.State = "expired"
		current.Result = observationResult("lease_expired")
	} else {
		preview, _, err = s.observationPreview(ctx, final, observationSelection(current.Definition))
		if err != nil && !bindingChanged(err) {
			return nil, err
		}
		if err != nil || preview.Hash != current.Hash {
			current.State = "blocked"
			current.Result = observationResult("binding_changed")
		} else if verified {
			current.State = "succeeded"
			current.Result = observationResult("remote_file_integrity_observed")
			current.Result.Integrity = true
			current.Result.Reconciled = true
			current.Result.SHA256 = current.Definition.Wire.SHA256
			current.Result.Size = current.Definition.Wire.Size
		}
	}
	if err = final.SaveOnboardingObservation(ctx, current, 3); err != nil {
		return nil, err
	}
	v, err := s.observationView(ctx, final, current)
	if err != nil {
		return nil, err
	}
	if err = final.Reauthorize(ctx); err != nil {
		return nil, err
	}
	v.ExternalContact = true
	return v, final.Tx.Commit(ctx)
}
