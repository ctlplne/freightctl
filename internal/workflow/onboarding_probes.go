package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/delivery"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/vpath"
)

type OnboardingProbeView struct {
	Probe            *store.OnboardingProbe `json:"probe"`
	Connection       *ConnectionView        `json:"connection,omitempty"`
	Current          bool                   `json:"current_bindings"`
	Reason           string                 `json:"binding_reason"`
	Evidence         string                 `json:"evidence_strength"`
	FileExchange     bool                   `json:"file_exchange_performed"`
	ProductionActive bool                   `json:"production_active"`
}
type OnboardingProbeWorkRequest struct {
	Hash string `json:"definition_hash"`
}

func (s *Service) probeBegin(ctx context.Context, scope store.Scope) (*store.Transaction, error) {
	t, err := s.Custody.DB.BeginOnboardingManagement(ctx, scope)
	if err != nil {
		return nil, err
	}
	if err = t.Require("connections_manage"); err != nil {
		t.Tx.Rollback(ctx)
		return nil, err
	}
	return t, nil
}
func validProbeReference(r store.OnboardingReference) bool {
	return store.ValidID(r.ID) && r.Version > 0 && r.Version <= 2147483647 && hashPattern.MatchString(r.Hash)
}

// Locks last only for short database decisions, never during network contact.
func probeBindings(ctx context.Context, t *store.Transaction, d store.OnboardingProbeDefinition) (*ConnectionDefinition, *ConnectionView, error) {
	if d.Schema != 1 || d.Profile != "sftp-readonly-v1" || d.Authority != t.AuthorityRevision {
		return nil, nil, store.ErrRevision
	}
	p, err := t.OnboardingPlan(ctx, d.Plan.ID, 0)
	if err != nil {
		return nil, nil, err
	}
	if p.Version != d.Plan.Version || p.Hash != d.Plan.Hash {
		return nil, nil, store.ErrRevision
	}
	found := false
	for _, r := range p.Definition.Requirements {
		if r.ID == d.RequirementID {
			found = r.Protocol == "sftp" && r.Direction == "send"
			break
		}
	}
	if !found {
		return nil, nil, store.ErrState
	}
	c, err := t.Configuration(ctx, true, d.Connection.ID, d.Connection.Version, true)
	if err != nil {
		return nil, nil, err
	}
	if c.State != "active" || c.Hash != d.Connection.Hash {
		return nil, nil, store.ErrRevision
	}
	var conn ConnectionDefinition
	if json.Unmarshal(c.Definition, &conn) != nil {
		return nil, nil, store.ErrIsolation
	}
	_, hash, err := digest(conn)
	directory, pathErr := vpath.Canonical(conn.Directory)
	if err != nil || hash != c.Hash || conn.Schema != 1 || pathErr != nil || directory != conn.Directory || vpath.ControlPath(directory) {
		return nil, nil, store.ErrIsolation
	}
	view, err := viewConnection(c)
	return &conn, &view, err
}

func (s *Service) StartOnboardingProbe(ctx context.Context, scope store.Scope, key string, r store.OnboardingProbeRequest) (*Result, error) {
	if !keyPattern.MatchString(key) || !validProbeReference(r.Plan) || !validProbeReference(r.Connection) || !store.ValidID(r.RequirementID) || r.ExpectedAuthority < 1 {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.probeBegin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	_, meaning, _ := digest(struct {
		Kind    string
		Request store.OnboardingProbeRequest
	}{"onboarding_probe_start", r})
	if prior, err := replay(t, ctx, key, meaning); err != nil || prior != nil {
		return prior, err
	}
	d := store.OnboardingProbeDefinition{Schema: 1, Profile: "sftp-readonly-v1", Plan: r.Plan, RequirementID: r.RequirementID, Connection: r.Connection, Authority: r.ExpectedAuthority}
	if _, _, err = probeBindings(ctx, t, d); err != nil {
		return nil, err
	}
	if err = t.OnboardingProbeAdmission(ctx); err != nil {
		return nil, err
	}
	now, err := t.DatabaseTime(ctx)
	if err != nil {
		return nil, err
	}
	_, hash, _ := digest(d)
	p := &store.OnboardingProbe{ID: secure.NewID(), Author: t.Actor, Definition: d, Hash: hash, State: "queued", Revision: 1, CreatedAt: now, Observation: store.OnboardingProbeObservation{Code: "awaiting_worker"}}
	if err = t.SaveOnboardingProbe(ctx, p, 0); err != nil {
		return nil, err
	}
	return result(t, ctx, key, meaning, p.ID, p)
}
func probeView(ctx context.Context, t *store.Transaction, p *store.OnboardingProbe) (*OnboardingProbeView, error) {
	v := &OnboardingProbeView{Probe: p, Evidence: "connectivity_only", Reason: "current"}
	_, conn, err := probeBindings(ctx, t, p.Definition)
	if err == nil {
		v.Current = true
		v.Connection = conn
		return v, nil
	}
	if errors.Is(err, store.ErrRevision) || errors.Is(err, store.ErrState) || errors.Is(err, store.ErrNotFound) {
		v.Reason = "binding_changed"
		return v, nil
	}
	return nil, err
}
func (s *Service) OnboardingProbeStatus(ctx context.Context, scope store.Scope, id string) (*OnboardingProbeView, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.probeBegin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	p, err := t.OnboardingProbe(ctx, id, false)
	if err != nil {
		return nil, err
	}
	v, err := probeView(ctx, t, p)
	if err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return v, t.Tx.Commit(ctx)
}

func (s *Service) ListOnboardingProbes(ctx context.Context, scope store.Scope, plan, after string, limit int) (*store.OnboardingProbePage, error) {
	if !store.ValidID(plan) || (after != "" && !store.ValidID(after)) || limit < 1 || limit > 100 {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.probeBegin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if _, err = t.OnboardingPlan(ctx, plan, 0); err != nil {
		return nil, err
	}
	page, err := t.OnboardingProbes(ctx, plan, after, limit)
	if err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return page, t.Tx.Commit(ctx)
}

// Work makes at most one network contact. Exact work-key replay returns the
// recorded state. An expired run becomes expired and never starts another probe.
func (s *Service) WorkOnboardingProbe(ctx context.Context, scope store.Scope, id, key string, r OnboardingProbeWorkRequest) (*OnboardingProbeView, error) {
	if !store.ValidID(id) || !keyPattern.MatchString(key) || !hashPattern.MatchString(r.Hash) {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	// Authorize before competing for a shared worker slot.
	admission, err := s.OnboardingProbeStatus(ctx, scope, id)
	if err != nil {
		return nil, err
	}
	if admission.Probe.Hash != r.Hash {
		return nil, store.ErrConflict
	}
	// Recorded/live/expired work-key recovery does not need a network slot.
	// Only a queued intent can start contact, and it must acquire a real slot.
	check := func() error { return nil }
	if admission.Probe.State == "queued" {
		var release func()
		check, release, err = s.Custody.DB.OnboardingProbeWorkerSlot(ctx)
		if err != nil {
			return nil, err
		}
		defer release()
	}
	t, err := s.probeBegin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	p, err := t.OnboardingProbe(ctx, id, true)
	if err != nil {
		return nil, err
	}
	if p.Hash != r.Hash || (p.WorkerKey != "" && p.WorkerKey != key) {
		return nil, store.ErrConflict
	}
	if admission.Probe.State != "queued" && p.State == "queued" {
		return nil, store.ErrRevision
	}
	now, err := t.DatabaseTime(ctx)
	if err != nil {
		return nil, err
	}
	finishWithoutContact := func(state, code string) (*OnboardingProbeView, error) {
		previous := p.Revision
		p.State = state
		p.Revision++
		p.CompletedAt = &now
		p.Observation = store.OnboardingProbeObservation{Code: code}
		if err := t.SaveOnboardingProbe(ctx, p, previous); err != nil {
			return nil, err
		}
		v, err := probeView(ctx, t, p)
		if err != nil {
			return nil, err
		}
		if err = t.Reauthorize(ctx); err != nil {
			return nil, err
		}
		return v, t.Tx.Commit(ctx)
	}
	if p.State == "running" && p.LeaseUntil != nil && !now.Before(*p.LeaseUntil) {
		return finishWithoutContact("expired", "lease_expired")
	}
	if p.State != "queued" {
		v, err := probeView(ctx, t, p)
		if err != nil {
			return nil, err
		}
		if err = t.Reauthorize(ctx); err != nil {
			return nil, err
		}
		return v, t.Tx.Commit(ctx)
	}
	p.WorkerKey = key
	conn, _, err := probeBindings(ctx, t, p.Definition)
	if err != nil {
		if errors.Is(err, store.ErrRevision) || errors.Is(err, store.ErrState) || errors.Is(err, store.ErrNotFound) {
			return finishWithoutContact("blocked", "binding_changed")
		}
		return nil, err
	}
	owner := secure.NewID()
	lease := now.Add(20 * time.Second)
	p.Owner = owner
	p.StartedAt = &now
	p.LeaseUntil = &lease
	p.State = "running"
	p.Revision++
	p.Observation = store.OnboardingProbeObservation{Code: "probing"}
	if err = t.SaveOnboardingProbe(ctx, p, 1); err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	if err = t.Tx.Commit(ctx); err != nil {
		return nil, err
	}
	// The intent and fence are durable before contact. A lost slot cancels the
	// network stream, and the final write rechecks the same slot and database lease.
	probeCtx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-probeCtx.Done():
				return
			case <-ticker.C:
				if check() != nil {
					stop()
					return
				}
			}
		}
	}()
	observation := delivery.ProbeSFTP(probeCtx, conn.Destination, conn.Directory)
	close(done)
	stop()
	<-closed
	if err = check(); err != nil {
		return nil, err
	}
	final, err := s.probeBegin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer final.Tx.Rollback(ctx)
	current, err := final.OnboardingProbe(ctx, id, true)
	if err != nil {
		return nil, err
	}
	if current.State != "running" || current.Revision != 2 || current.Owner != owner || current.WorkerKey != key || current.Hash != r.Hash {
		return nil, store.ErrRevision
	}
	now, err = final.DatabaseTime(ctx)
	if err != nil {
		return nil, err
	}
	if current.LeaseUntil == nil || !now.Before(*current.LeaseUntil) {
		return nil, store.ErrRevision
	}
	current.State = "failed"
	if observation.Code == "connectivity_verified" {
		current.State = "succeeded"
	}
	if _, _, err = probeBindings(ctx, final, current.Definition); err != nil {
		if !errors.Is(err, store.ErrRevision) && !errors.Is(err, store.ErrState) && !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
		current.State = "blocked"
		observation = store.OnboardingProbeObservation{Code: "binding_changed"}
	}
	current.Revision++
	current.CompletedAt = &now
	current.Observation = observation
	if err = final.SaveOnboardingProbe(ctx, current, 2); err != nil {
		return nil, err
	}
	v, err := probeView(ctx, final, current)
	if err != nil {
		return nil, err
	}
	if err = final.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return v, final.Tx.Commit(ctx)
}
