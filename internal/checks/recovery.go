package checks

import (
	"context"
	"encoding/json"
	"time"

	"github.com/ctlplne/freightctl/internal/store"
)

// These fields select one expired reservation. They grant no authority; start
// checks every value again under the same row lock as the replacement claim.
type RecoveryDecision struct {
	Revision   int64     `json:"expected_revision"`
	WorkerID   string    `json:"expected_worker_id"`
	LeaseUntil time.Time `json:"expected_lease_until"`
	SHA256     string    `json:"sha256"`
	PolicyHash string    `json:"policy_hash"`
}
type RecoveryView struct {
	ObservedAt time.Time        `json:"observed_at"`
	Eligible   bool             `json:"eligible"`
	Code       string           `json:"code"`
	Decision   RecoveryDecision `json:"decision"`
}

func normalizeRecovery(d RecoveryDecision) (RecoveryDecision, error) {
	if d.Revision < 1 || !store.ValidID(d.WorkerID) || d.LeaseUntil.IsZero() || !hashPattern.MatchString(d.SHA256) || !hashPattern.MatchString(d.PolicyHash) {
		return d, ErrInput
	}
	// PostgreSQL timestamps have microsecond precision. A different submicrosecond
	// selector is refused rather than silently rounding an approval to a match.
	d.LeaseUntil = d.LeaseUntil.UTC()
	if d.LeaseUntil.Year() < 1970 || d.LeaseUntil.Year() > 9999 || d.LeaseUntil.Nanosecond()%1000 != 0 {
		return d, ErrInput
	}
	return d, nil
}
func recoveryView(c *store.FileCheck, now time.Time, current, permitted bool) (*RecoveryView, error) {
	if c.State != "running" {
		return nil, nil
	}
	var binding store.CheckBinding
	if c.LeaseUntil == nil || !store.ValidID(c.WorkerID) || json.Unmarshal(c.Binding, &binding) != nil || !hashPattern.MatchString(binding.File.SHA256) {
		return nil, store.ErrState
	}
	r := &RecoveryView{ObservedAt: now.UTC(), Decision: RecoveryDecision{Revision: c.Revision, WorkerID: c.WorkerID, LeaseUntil: c.LeaseUntil.UTC(), SHA256: binding.File.SHA256, PolicyHash: c.PolicyHash}}
	switch {
	case !current:
		r.Code = "authority_or_policy_changed"
	case !permitted:
		r.Code = "permission_denied"
	case c.Attempts >= 3:
		r.Code = "attempt_budget_exhausted"
	case c.LeaseUntil.After(now):
		r.Code = "lease_active"
	default:
		r.Code = "ready"
		r.Eligible = true
	}
	return r, nil
}
func (s *Service) Recover(ctx context.Context, scope store.Scope, id, key string, decision RecoveryDecision) (*Result, error) {
	d, err := normalizeRecovery(decision)
	if err != nil {
		return nil, err
	}
	return s.run(ctx, scope, id, key, &d)
}
