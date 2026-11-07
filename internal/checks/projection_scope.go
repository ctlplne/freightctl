package checks

import (
	"context"
	"encoding/json"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/vpath"
)

func projectionReplayScope(t *store.Transaction, data json.RawMessage) error {
	var v struct {
		Kind       string                  `json:"kind"`
		Projection *store.RecordProjection `json:"projection"`
	}
	if json.Unmarshal(data, &v) != nil || v.Kind != "record_projection" {
		return store.ErrState
	}
	d, err := decodeProjection(v.Projection)
	if err != nil {
		return err
	}
	if d.Plan.Context.Root != t.Root {
		return store.ErrForbidden
	}
	return projectionAuthority(t, d.Plan.Profile)
}
func projectionReplayed(ctx context.Context, t *store.Transaction, data json.RawMessage) (*Result, error) {
	if err := projectionReplayScope(t, data); err != nil {
		return nil, err
	}
	return recheckReplayed(ctx, t, data)
}

const ScopedProjectionProfile = "scoped-record-projection-v1"
const ProducerProjectionProfile = "producer-record-projection-v1"

func projectionProfile(profile string) (string, int, error) {
	if profile == "" {
		profile = ProjectionReviewProfile
	}
	switch profile {
	case ProjectionReviewProfile:
		return profile, 1, nil
	case ScopedProjectionProfile:
		return profile, 2, nil
	case ProducerProjectionProfile:
		return profile, 3, nil
	}
	return "", 0, ErrInput
}
func validProjectionProfile(plan ProjectionPlan) bool {
	profile, schema, err := projectionProfile(plan.Profile)
	if err != nil || plan.Profile != profile || plan.Schema != schema || ((profile == ProducerProjectionProfile) != (plan.OutputBinding != nil)) {
		return false
	}
	if b := plan.OutputBinding; b != nil {
		return b.Profile == "producer-processing-output-policy-v1" && store.ValidID(b.Publisher) && store.ValidID(b.Producer.Tenant) && store.ValidID(b.Producer.Partner) && store.ValidID(b.Producer.Actor) && b.Producer.AuthorityRevision == plan.Context.Authority && b.Producer.AuthorityRevision > 0 && b.Producer.RootPolicyDigest == secure.Digest([]byte(plan.Context.Root)) && b.PolicyID == plan.Context.Policy.ID && b.Version == plan.Context.Policy.Version && b.Hash == plan.Context.Policy.Hash
	}
	return true
}

// Workflow grants govern processing over owned artifacts. They supply no
// administration,policy change,signature reuse,release or delivery rights.
func projectionAuthority(t *store.Transaction, profile string) error {
	profile, _, err := projectionProfile(profile)
	if err != nil {
		return err
	}
	root, err := vpath.Canonical(t.Root)
	if err != nil || root != t.Root {
		return store.ErrForbidden
	}
	grants := []string{"read", "write", "check_run"}
	if profile == ProjectionReviewProfile {
		if t.Root != "/" {
			return store.ErrForbidden
		}
		grants = []string{"admin", "read", "write", "intake_manage", "check_run", "check_release"}
	}
	for _, grant := range grants {
		if err = t.Require(grant); err != nil {
			return err
		}
	}
	if (profile == ScopedProjectionProfile || profile == ProducerProjectionProfile) && !t.Has("workflow_manage") && !t.Has("workflow_approve") && !t.Has("workflow_execute") {
		return store.ErrForbidden
	}
	return nil
}
func projectionActionAuthority(t *store.Transaction, profile, action string) error {
	if err := projectionAuthority(t, profile); err != nil {
		return err
	}
	profile, _, _ = projectionProfile(profile)
	if (profile == ScopedProjectionProfile || profile == ProducerProjectionProfile) && action != "" {
		return t.Require(action)
	}
	return nil
}
func (s *Service) projectionBegin(ctx context.Context, scope store.Scope, profile string) (*store.Transaction, error) {
	t, err := s.begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	if err = projectionActionAuthority(t, profile, "workflow_manage"); err != nil {
		t.Tx.Rollback(ctx)
		return nil, err
	}
	return t, nil
}

// Enforce the stored profile before any original receipt can be returned.
// A newly scoped grant cannot reinterpret a historical root-administration job.
func (s *Service) projectionExistingBegin(ctx context.Context, scope store.Scope, id string, action string) (*store.Transaction, error) {
	t, err := s.begin(ctx, scope, "read")
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*store.Transaction, error) { t.Tx.Rollback(ctx); return nil, err }
	if projectionAuthority(t, ProjectionReviewProfile) != nil && projectionAuthority(t, ScopedProjectionProfile) != nil {
		return fail(store.ErrForbidden)
	}
	r, err := t.RecordProjection(ctx, id, false)
	if err != nil {
		return fail(err)
	}
	d, err := decodeProjection(r)
	if err != nil {
		return fail(err)
	}
	if err = projectionActionAuthority(t, d.Plan.Profile, action); err != nil {
		return fail(err)
	}
	if d.Plan.Context.Root != t.Root {
		return fail(store.ErrForbidden)
	}
	if action == "workflow_execute" {
		if err = projectionWorkflowCurrent(ctx, t, d, false); err != nil {
			return fail(err)
		}
	}
	return t, nil
}
