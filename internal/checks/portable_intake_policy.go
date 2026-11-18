package checks

import (
	"context"
	"io"
	"time"

	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

const PortableIntakePolicyProfile = "freightctl-portable-intake-policy-v1"

type PortableIntakePolicy struct {
	SchemaVersion    int                `json:"schema_version"`
	Profile          string             `json:"profile"`
	SourceTenant     string             `json:"source_tenant_id"`
	SourcePartner    string             `json:"source_partner_id"`
	Source           workflow.Reference `json:"source"`
	ObservedState    string             `json:"observed_state"`
	Registration     PolicyRequest      `json:"destination_registration"`
	RequiredBindings []string           `json:"required_bindings"`
}

func (s *Service) PreparePortableIntakePolicy(ctx context.Context, scope store.Scope, ref workflow.Reference, output io.Writer) (*workflow.PortableExportReceipt, error) {
	if !store.ValidID(ref.ID) || ref.Version < 1 || !hashPattern.MatchString(ref.Hash) {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.begin(ctx, scope, "admin", "intake_manage")
	if err != nil {
		return nil, err
	}
	defer tx.Tx.Rollback(ctx)
	if tx.Root != "/" {
		return nil, store.ErrForbidden
	}
	stored, err := tx.IntakePolicyRevision(ctx, ref.ID, ref.Version)
	if err != nil {
		return nil, err
	}
	if stored.Hash != ref.Hash {
		return nil, store.ErrRevision
	}
	definition, err := decodePolicy(stored)
	if err != nil {
		return nil, err
	}
	manifest := PortableIntakePolicy{
		SchemaVersion: 1, Profile: PortableIntakePolicyProfile,
		SourceTenant: scope.Tenant, SourcePartner: scope.Partner, Source: ref, ObservedState: stored.State,
		// A negative version forces review even on an empty destination.
		Registration:     PolicyRequest{ExpectedVersion: -1, Definition: definition},
		RequiredBindings: portablePolicyBindings(definition, "expected_version"),
	}
	return workflow.WritePortableExport(ctx, tx, "PortableIntakePolicyExportPrepared", ref, manifest, output)
}
