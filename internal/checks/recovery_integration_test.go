//go:build integration

package checks

import (
	"errors"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
	"testing"
	"time"
)

func TestConditionalRecoveryRefusesLiveReservationChangedSelectorsAndPolicy(t *testing.T) {
	f := setup(t)
	s, p, file := policyAndFile(t, f, goodCSV, true)
	_, _, _, _, _, err := s.start(f.ctx, f.scope, file.ID, "original-worker")
	if err != nil {
		t.Fatal(err)
	}
	view, err := s.Get(f.ctx, f.scope, file.ID)
	if err != nil || view.Recovery == nil || view.Recovery.Eligible || view.Recovery.Code != "lease_active" {
		t.Fatal("live reservation offered recovery", err)
	}
	d := view.Recovery.Decision
	if _, err = s.Recover(f.ctx, f.scope, file.ID, "too-early", d); !errors.Is(err, store.ErrState) {
		t.Fatal("live reservation replaced", err)
	}
	for _, mutate := range []func(*RecoveryDecision){func(d *RecoveryDecision) { d.Revision++ }, func(d *RecoveryDecision) { d.WorkerID = secure.NewID() }, func(d *RecoveryDecision) { d.LeaseUntil = d.LeaseUntil.Add(-time.Second) }, func(d *RecoveryDecision) { d.SHA256 = secure.Digest([]byte("other source")) }, func(d *RecoveryDecision) { d.PolicyHash = secure.Digest([]byte("other policy")) }} {
		copy := d
		mutate(&copy)
		if _, err = s.Recover(f.ctx, f.scope, file.ID, secure.NewID(), copy); !errors.Is(err, store.ErrRevision) {
			t.Fatal("changed selector accepted", err)
		}
	}
	current, err := s.Get(f.ctx, f.scope, file.ID)
	if err != nil || current.Check.Attempts != 1 || current.Check.WorkerID != d.WorkerID || !current.Check.LeaseUntil.Equal(d.LeaseUntil) {
		t.Fatal("refusal changed reservation or attempt budget", err)
	}
	wrong := f.scope
	wrong.Tenant = secure.NewID()
	if _, err = s.Recover(f.ctx, wrong, file.ID, "wrong-tenant", d); !errors.Is(err, store.ErrUnauthorized) {
		t.Fatal("cross-tenant recovery", err)
	}
	if _, err = s.Revoke(f.ctx, f.scope, "revoke", PolicyDecision{Hash: p.Hash, Version: p.Version, Revision: p.Revision}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Recover(f.ctx, f.scope, file.ID, "revoked-policy", d); !errors.Is(err, store.ErrRevision) && !errors.Is(err, store.ErrState) {
		t.Fatal("revoked policy accepted", err)
	}
}
