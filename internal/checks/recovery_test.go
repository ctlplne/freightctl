package checks

import (
	"encoding/json"
	"errors"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
	"testing"
	"time"
)

func TestRecoveryStatusUsesObservedLeaseAndPreservesBounds(t *testing.T) {
	until := time.Date(2026, 10, 29, 12, 0, 0, 123456000, time.UTC)
	binding, _ := json.Marshal(store.CheckBinding{File: store.File{SHA256: secure.Digest([]byte("synthetic source"))}})
	c := &store.FileCheck{State: "running", WorkerID: secure.NewID(), Revision: 2, Attempts: 1, LeaseUntil: &until, PolicyHash: secure.Digest([]byte("policy")), Binding: binding}
	cases := []struct {
		name               string
		now                time.Time
		current, permitted bool
		attempts           int
		code               string
		ready              bool
	}{{"live", until.Add(-time.Nanosecond), true, true, 1, "lease_active", false}, {"expired", until, true, true, 1, "ready", true}, {"permission", until, true, false, 1, "permission_denied", false}, {"authority", until, false, true, 1, "authority_or_policy_changed", false}, {"budget", until, true, true, 3, "attempt_budget_exhausted", false}}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			c.Attempts = test.attempts
			r, err := recoveryView(c, test.now, test.current, test.permitted)
			if err != nil || r.Eligible != test.ready || r.Code != test.code || !r.Decision.LeaseUntil.Equal(until) || r.Decision.WorkerID != c.WorkerID || r.Decision.Revision != 2 {
				t.Fatal("recovery status changed authority or reservation", r, err)
			}
		})
	}
	c.State = "passed"
	if r, err := recoveryView(c, until, true, true); err != nil || r != nil {
		t.Fatal("completed check offered recovery", err)
	}
}
func TestRecoveryDecisionRejectsInvalidSelectorsAndSubmicrosecondRounding(t *testing.T) {
	d := RecoveryDecision{Revision: 2, WorkerID: secure.NewID(), LeaseUntil: time.Date(2026, 10, 29, 12, 0, 0, 123456000, time.FixedZone("fixture", -4*3600)), SHA256: secure.Digest([]byte("source")), PolicyHash: secure.Digest([]byte("policy"))}
	canonical, err := normalizeRecovery(d)
	if err != nil || canonical.LeaseUntil.Location() != time.UTC || !canonical.LeaseUntil.Equal(d.LeaseUntil) {
		t.Fatal(err)
	}
	for _, mutate := range []func(*RecoveryDecision){func(d *RecoveryDecision) { d.Revision = 0 }, func(d *RecoveryDecision) { d.WorkerID = "unknown" }, func(d *RecoveryDecision) { d.SHA256 = "bad" }, func(d *RecoveryDecision) { d.PolicyHash = "bad" }, func(d *RecoveryDecision) { d.LeaseUntil = time.Time{} }, func(d *RecoveryDecision) { d.LeaseUntil = d.LeaseUntil.Add(time.Nanosecond) }} {
		copy := d
		mutate(&copy)
		if _, err = normalizeRecovery(copy); !errors.Is(err, ErrInput) {
			t.Fatal("invalid recovery selector accepted", err)
		}
	}
}
