package checks

import (
	"context"
	"io"
	"time"

	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

const PortableOutputPolicyProfile = "freightctl-portable-output-policy-v1"

type PortableOutputPolicy struct {
	SchemaVersion    int                            `json:"schema_version"`
	Profile          string                         `json:"profile"`
	SourceTenant     string                         `json:"source_tenant_id"`
	SourcePartner    string                         `json:"source_partner_id"`
	Source           workflow.Reference             `json:"source"`
	ObservedState    string                         `json:"observed_state"`
	SourceBinding    *store.ProcessingOutputBinding `json:"source_binding"`
	Registration     OutputPolicyRequest            `json:"destination_registration"`
	RequiredBindings []string                       `json:"required_bindings"`
}

func (s *Service) PreparePortableOutputPolicy(ctx context.Context, scope store.Scope, ref workflow.Reference, output io.Writer) (*workflow.PortableExportReceipt, error) {
	if !store.ValidID(ref.ID) || ref.Version < 1 || !hashPattern.MatchString(ref.Hash) {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.outputAdministration(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer tx.Tx.Rollback(ctx)
	stored, err := tx.ProcessingOutputPolicy(ctx, ref.ID, ref.Version, false)
	if err != nil {
		return nil, err
	}
	if stored.Hash != ref.Hash {
		return nil, store.ErrRevision
	}
	record, err := outputRecord(ctx, tx, stored)
	if err != nil {
		return nil, err
	}
	definition, err := decodePolicy(stored)
	if err != nil {
		return nil, err
	}
	manifest := PortableOutputPolicy{
		SchemaVersion: 1, Profile: PortableOutputPolicyProfile,
		SourceTenant: scope.Tenant, SourcePartner: scope.Partner, Source: ref, ObservedState: stored.State,
		SourceBinding: record.Binding, Registration: OutputPolicyRequest{Definition: definition},
		RequiredBindings: portablePolicyBindings(definition, "producer_id"),
	}
	return workflow.WritePortableExport(ctx, tx, "PortableOutputPolicyExportPrepared", ref, manifest, output)
}

func portablePolicyBindings(definition Policy, primary string) []string {
	bindings := []string{primary}
	if definition.Signature != nil {
		bindings = append(bindings, "definition.signature.key")
	}
	if definition.Scanner != nil {
		bindings = append(bindings, "definition.scanner")
	}
	return bindings
}
