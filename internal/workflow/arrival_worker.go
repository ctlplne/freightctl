package workflow

import (
	"context"
	"errors"
	"os"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

type ArrivalAction struct {
	Kind          string  `json:"kind"`
	ID            string  `json:"occurrence_id"`
	Hash          string  `json:"definition_hash"`
	State         string  `json:"state"`
	Revision      int64   `json:"revision"`
	CollectionID  *string `json:"collection_id"`
	ManifestHash  *string `json:"manifest_hash"`
	SourceContact bool    `json:"external_contact"`
}

func arrivalResult(ctx context.Context, t *store.Transaction, key, meaning string, a *store.ScheduleArrival, contact bool) (*Result, error) {
	return scheduleResult(t, ctx, key, meaning, a.ID, ArrivalAction{Kind: "workflow_schedule_arrival", ID: a.ID, Hash: a.Hash, State: a.State, Revision: a.Revision, CollectionID: a.JobID, ManifestHash: a.ManifestHash, SourceContact: contact})
}
func (s *Service) arrivalBegin(ctx context.Context, scope store.Scope) (*store.Transaction, error) {
	return s.scheduleBegin(ctx, scope, "workflow_execute")
}
func (s *Service) ProbeScheduleArrival(ctx context.Context, scope store.Scope, id, key string, x CollectionWorkRequest) (*Result, error) {
	if !store.ValidID(id) || !keyPattern.MatchString(key) || !hashPattern.MatchString(x.Hash) {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	_, meaning, _ := digest(struct {
		Kind, ID string
		Input    CollectionWorkRequest
	}{"probe_schedule_arrival", id, x})
	t, err := s.arrivalBegin(ctx, scope)
	if err != nil {
		return nil, err
	}
	a, err := t.ScheduleArrival(ctx, id, true)
	if err != nil {
		t.Tx.Rollback(ctx)
		return nil, err
	}
	if a.Hash != x.Hash {
		t.Tx.Rollback(ctx)
		return nil, store.ErrRevision
	}
	if prior, e := replay(t, ctx, key, meaning); e != nil || prior != nil {
		t.Tx.Rollback(ctx)
		return prior, e
	}
	binding, err := arrivalBinding(a)
	if err != nil {
		t.Tx.Rollback(ctx)
		return nil, err
	}
	now, err := t.DatabaseTime(ctx)
	if err != nil {
		t.Tx.Rollback(ctx)
		return nil, err
	}
	if a.State == "waiting" || a.State == "probing" || a.State == "attention" {
		if !binding.ArrivalDeadline.After(now) {
			before := a.Revision
			a.Revision++
			a.State = "missing"
			a.Owner = ""
			a.Until = nil
			a.Next = binding.ArrivalDeadline
			a.Reason = "no_verified_ready_manifest_by_cutoff"
			if err = t.SaveScheduleArrival(ctx, a, before); err != nil {
				t.Tx.Rollback(ctx)
				return nil, err
			}
			return arrivalResult(ctx, t, key, meaning, a, false)
		}
	}
	if a.State == "ready" || a.State == "admitted" || a.State == "missing" || a.State == "expired" || a.State == "cancelled" {
		return arrivalResult(ctx, t, key, meaning, a, false)
	}
	record, err := t.Schedule(ctx, a.ScheduleID, a.Version, false)
	if err != nil {
		t.Tx.Rollback(ctx)
		return nil, err
	}
	d, _, err := scheduleDefinition(record)
	if err == nil {
		err = s.checkArrivalCurrent(ctx, t, a, record, d)
	}
	if err != nil {
		t.Tx.Rollback(ctx)
		return nil, err
	}
	if err = t.Tx.Commit(ctx); err != nil {
		return nil, err
	}
	// No stream is occupied while metadata, future cadence or a live original
	// lease prevents admission. Recheck these before acquiring the shared pool.
	if a.Next.After(now) || (a.State == "probing" && a.Until != nil && a.Until.After(now)) {
		return nil, store.ErrArrival
	}
	slotCheck, release, err := s.Custody.DB.CollectionWorkerSlot(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	owner := secure.NewID()
	a, d, connection, err := s.claimArrivalProbe(ctx, scope, id, x.Hash, owner)
	if err != nil {
		return nil, err
	}
	fence := a.Fence
	// A probe has twenty seconds for its read and the original thirty-second
	// lease. It never extends or shortens the recorded takeover boundary.
	readCtx, stop := context.WithTimeout(ctx, 20*time.Second)
	defer stop()
	check := func() error {
		if err := slotCheck(); err != nil {
			return err
		}
		return s.checkArrivalProbe(readCtx, scope, id, owner, fence)
	}
	peer, err := openCollectionSourcePeer(readCtx, connection, d.Collection.Source.Kind, check)
	reason := "source_connection_unavailable"
	state := "attention"
	var manifest *CollectionManifest
	var hash string
	if err == nil {
		defer peer.Close()
		data, readErr := peer.ReadManifest(readCtx, binding.Manifest, check)
		if readErr != nil {
			reason = "ready_manifest_unavailable"
			if errors.Is(readErr, os.ErrNotExist) {
				state = "waiting"
				reason = "expected_ready_manifest_not_observed"
			}
		} else {
			manifest, hash, err = parseCollectionManifest(data, d.Collection.Source)
			if err != nil {
				reason = "producer_manifest_invalid"
			} else {
				state = "ready"
				reason = "verified_ready_manifest_observed"
			}
		}
	}
	return s.finishArrivalProbe(scope, id, owner, fence, key, meaning, state, reason, manifest, hash)
}
func (s *Service) claimArrivalProbe(ctx context.Context, scope store.Scope, id, hash, owner string) (*store.ScheduleArrival, *ScheduleDefinition, *ConnectionDefinition, error) {
	t, err := s.arrivalBegin(ctx, scope)
	if err != nil {
		return nil, nil, nil, err
	}
	defer t.Tx.Rollback(ctx)
	a, err := t.ScheduleArrival(ctx, id, true)
	if err != nil {
		return nil, nil, nil, err
	}
	binding, err := arrivalBinding(a)
	if err != nil {
		return nil, nil, nil, err
	}
	now, err := t.DatabaseTime(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	if a.Hash != hash || !binding.ArrivalDeadline.After(now) || a.Next.After(now) || (a.State != "waiting" && a.State != "attention" && a.State != "probing") || (a.State == "probing" && a.Until != nil && a.Until.After(now)) {
		return nil, nil, nil, store.ErrArrival
	}
	record, err := t.Schedule(ctx, a.ScheduleID, a.Version, false)
	if err != nil {
		return nil, nil, nil, err
	}
	d, _, err := scheduleDefinition(record)
	if err != nil {
		return nil, nil, nil, err
	}
	if err = s.checkArrivalCurrent(ctx, t, a, record, d); err != nil {
		return nil, nil, nil, err
	}
	_, connection, err := s.currentArrivalSource(ctx, t, d)
	if err != nil {
		return nil, nil, nil, err
	}
	limit := (d.Collection.Arrival.Deadline+d.Collection.Arrival.Poll-1)/d.Collection.Arrival.Poll + 1
	if a.Probes >= limit {
		return nil, nil, nil, store.ErrLimit
	}
	before := a.Revision
	a.Revision++
	a.Fence++
	a.Probes++
	a.State = "probing"
	a.Owner = owner
	a.Reason = "reading_expected_ready_manifest"
	until := now.Add(30 * time.Second)
	if until.After(binding.ArrivalDeadline) {
		until = binding.ArrivalDeadline
	}
	a.Until = &until
	if err = t.SaveScheduleArrival(ctx, a, before); err != nil {
		return nil, nil, nil, err
	}
	return a, d, connection, t.Tx.Commit(ctx)
}
func (s *Service) currentArrivalSource(ctx context.Context, t *store.Transaction, d *ScheduleDefinition) (*ConnectionView, *ConnectionDefinition, error) {
	connection, view, err := collectionConnection(ctx, t, &d.Collection.Source)
	return view, connection, err
}
func (s *Service) checkArrivalProbe(ctx context.Context, scope store.Scope, id, owner string, fence int64) error {
	t, err := s.Custody.DB.Begin(ctx, scope)
	if err != nil {
		return err
	}
	defer t.Tx.Rollback(ctx)
	if err = t.ScheduleLock(ctx, false); err != nil {
		return err
	}
	if err = t.CollectionLock(ctx, false); err != nil {
		return err
	}
	a, err := t.ScheduleArrival(ctx, id, false)
	if err != nil {
		return err
	}
	binding, err := arrivalBinding(a)
	if err != nil {
		return err
	}
	now, err := t.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if a.State != "probing" || a.Owner != owner || a.Fence != fence || a.Until == nil || !a.Until.After(now) || !binding.ArrivalDeadline.After(now) {
		return store.ErrArrival
	}
	record, err := t.Schedule(ctx, a.ScheduleID, a.Version, false)
	if err != nil {
		return err
	}
	d, _, err := scheduleDefinition(record)
	if err != nil {
		return err
	}
	if err = s.checkArrivalCurrent(ctx, t, a, record, d); err != nil {
		return err
	}
	return t.Tx.Commit(ctx)
}
func (s *Service) finishArrivalProbe(scope store.Scope, id, owner string, fence int64, key, meaning, state, reason string, m *CollectionManifest, hash string) (*Result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	t, err := s.arrivalBegin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if err = t.CollectionLock(ctx, false); err != nil {
		return nil, err
	}
	a, err := t.ScheduleArrival(ctx, id, true)
	if err != nil {
		return nil, err
	}
	if a.State != "probing" || a.Owner != owner || a.Fence != fence {
		return nil, store.ErrArrival
	}
	binding, err := arrivalBinding(a)
	if err != nil {
		return nil, err
	}
	record, err := t.Schedule(ctx, a.ScheduleID, a.Version, false)
	if err != nil {
		return nil, err
	}
	d, _, err := scheduleDefinition(record)
	if err != nil {
		return nil, err
	}
	now, err := t.DatabaseTime(ctx)
	if err != nil {
		return nil, err
	}
	previous := a.Revision
	a.Revision++
	a.State = state
	a.Reason = reason
	a.Owner = ""
	a.Until = nil
	a.Next = now.Add(time.Duration(d.Collection.Arrival.Poll) * time.Second)
	if a.Next.After(binding.ArrivalDeadline) {
		a.Next = binding.ArrivalDeadline
	}
	if !binding.ArrivalDeadline.After(now) {
		a.State = "missing"
		a.Reason = "no_verified_ready_manifest_by_cutoff"
		m = nil
	}
	if m != nil && a.State == "ready" {
		if err = s.checkArrivalCurrent(ctx, t, a, record, d); err != nil {
			return nil, err
		}
		encoded, actual, err := digest(m)
		if err != nil {
			return nil, err
		}
		if actual != hash {
			return nil, store.ErrState
		}
		a.Manifest = encoded
		a.ManifestHash = &hash
		a.Observed = &now
	}
	if err = t.SaveScheduleArrival(ctx, a, previous); err != nil {
		return nil, err
	}
	return arrivalResult(ctx, t, key, meaning, a, true)
}
func (s *Service) AdmitScheduleArrival(ctx context.Context, scope store.Scope, id, key string, x Decision) (*Result, error) {
	if !store.ValidID(id) || !keyPattern.MatchString(key) || !hashPattern.MatchString(x.Hash) || x.Revision < 1 {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.arrivalBegin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	_, meaning, _ := digest(struct {
		Kind, ID string
		Input    Decision
	}{"admit_schedule_arrival", id, x})
	if prior, e := replay(t, ctx, key, meaning); e != nil || prior != nil {
		return prior, e
	}
	a, err := t.ScheduleArrival(ctx, id, true)
	if err != nil {
		return nil, err
	}
	if a.Hash != x.Hash || a.Revision != x.Revision {
		return nil, store.ErrRevision
	}
	binding, err := arrivalBinding(a)
	if err != nil {
		return nil, err
	}
	now, err := t.DatabaseTime(ctx)
	if err != nil {
		return nil, err
	}
	if a.State == "ready" && !binding.Deadline.After(now) {
		previous := a.Revision
		a.Revision++
		a.State = "expired"
		a.Reason = "execution_cutoff_before_collection_admission"
		if err = t.SaveScheduleArrival(ctx, a, previous); err != nil {
			return nil, err
		}
	} else {
		if _, err = s.admitScheduleArrival(ctx, t, a); err != nil {
			return nil, err
		}
	}
	return arrivalResult(ctx, t, key, meaning, a, false)
}
func (s *Service) CancelScheduleArrival(ctx context.Context, scope store.Scope, id, key string, x Decision) (*Result, error) {
	if !store.ValidID(id) || !keyPattern.MatchString(key) || !hashPattern.MatchString(x.Hash) || x.Revision < 1 {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.arrivalBegin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	_, meaning, _ := digest(struct {
		Kind, ID string
		Input    Decision
	}{"cancel_schedule_arrival", id, x})
	if prior, e := replay(t, ctx, key, meaning); e != nil || prior != nil {
		return prior, e
	}
	a, err := t.ScheduleArrival(ctx, id, true)
	if err != nil {
		return nil, err
	}
	if a.Hash != x.Hash || a.Revision != x.Revision {
		return nil, store.ErrRevision
	}
	if a.State == "cancelled" || a.State == "missing" || a.State == "expired" {
		return nil, store.ErrState
	}
	previous := a.Revision
	a.Revision++
	a.State = "cancelled"
	a.Owner = ""
	a.Until = nil
	a.Reason = "operator_cancelled_arrival"
	if err = t.SaveScheduleArrival(ctx, a, previous); err != nil {
		return nil, err
	}
	return arrivalResult(ctx, t, key, meaning, a, false)
}
