package checks

import (
	"context"
	"encoding/json"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

// ProcessingContracts describes schemas and exact revisions, never file contents,
// host paths, secret references, approval or execution authority.
type ProcessingContracts struct {
	Profile       string                         `json:"profile"`
	Source        store.ExchangeArtifact         `json:"source"`
	SourcePolicy  RecheckPolicy                  `json:"source_policy"`
	OutputPolicy  RecheckPolicy                  `json:"output_policy"`
	Authority     int64                          `json:"authority_revision"`
	RootDigest    string                         `json:"namespace_root_digest"`
	ProofUntil    *time.Time                     `json:"source_proof_valid_until,omitempty"`
	Effects       string                         `json:"effects"`
	OutputBinding *store.ProcessingOutputBinding `json:"output_binding,omitempty"`
}

func processingContracts(base *RecheckPreview, row *store.FileCheck, now time.Time) (*ProcessingContracts, error) {
	return processingContractsBound(base, row, now, nil)
}

func processingContractsForProducer(base *RecheckPreview, row *store.FileCheck, now time.Time, binding *store.ProcessingOutputBinding, producer store.ExchangeParticipant) (*ProcessingContracts, error) {
	if err := validateProducerOutput(base, binding, producer); err != nil {
		return nil, err
	}
	return processingContractsBound(base, row, now, binding)
}

func processingContractsBound(base *RecheckPreview, row *store.FileCheck, now time.Time, binding *store.ProcessingOutputBinding) (*ProcessingContracts, error) {
	_, until, err := projectionSourceReport(base, row, now)
	if err != nil {
		return nil, err
	}
	wire, _, err := canonical(base)
	if err != nil {
		return nil, err
	}
	var owned RecheckPreview
	if json.Unmarshal(wire, &owned) != nil {
		return nil, store.ErrState
	}
	output, err := Normalize(owned.CurrentPolicy.Definition)
	if err != nil {
		return nil, err
	}
	_, hash, _ := canonical(output)
	state, profile := "active", "record-processing-contracts-v1"
	var outputBinding *store.ProcessingOutputBinding
	if binding != nil {
		state, profile = "output_active", "record-processing-contracts-v2"
		copy := *binding
		outputBinding = &copy
	}
	if owned.CurrentPolicy.State != state || owned.CurrentPolicy.Reference != owned.Plan.Policy || hash != owned.Plan.Policy.Hash {
		return nil, store.ErrRevision
	}
	f := owned.Plan.Source.File
	return &ProcessingContracts{Profile: profile, Source: store.ExchangeArtifact{ID: f.ID, Size: f.Size, SHA256: f.SHA256, Policy: f.Policy}, SourcePolicy: *owned.PreviousPolicy, OutputPolicy: owned.CurrentPolicy, Authority: owned.Plan.Authority, RootDigest: secure.Digest([]byte(owned.Plan.Root)), ProofUntil: until, Effects: "Metadata only. No approval,run,bytes,release or delivery.", OutputBinding: outputBinding}, nil
}
func (s *Service) DescribeProcessing(ctx context.Context, scope store.Scope, id string) (*ProcessingContracts, error) {
	return s.describeProcessing(ctx, scope, id, nil)
}

func (s *Service) DescribeProcessingOutput(ctx context.Context, scope store.Scope, id string, ref store.OnboardingReference) (*ProcessingContracts, error) {
	return s.describeProcessing(ctx, scope, id, &ref)
}

func (s *Service) describeProcessing(ctx context.Context, scope store.Scope, id string, ref *store.OnboardingReference) (*ProcessingContracts, error) {
	if !store.ValidID(id) {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if err = projectionAuthority(t, ScopedProjectionProfile); err != nil {
		return nil, err
	}
	if err = t.NamespaceLock(ctx); err != nil {
		return nil, err
	}
	var p *store.Configuration
	var binding *store.ProcessingOutputBinding
	if ref == nil {
		p, err = t.IntakePolicy(ctx, false)
	} else {
		p, err = t.ProcessingPolicy(ctx, *ref)
		if err == nil && p.State != "output_active" {
			return nil, store.ErrRevision
		}
		if err == nil {
			binding, err = t.ProcessingOutputBinding(ctx, p.ID, p.Version)
		}
	}
	if err != nil {
		return nil, err
	}
	if p == nil || (ref == nil && p.State != "active") {
		return nil, store.ErrState
	}
	output, err := decodePolicy(p)
	if err != nil {
		return nil, err
	}
	mode := "not_required"
	if output.Signature != nil {
		mode = "require_new"
	}
	var explicit *store.Configuration
	if ref != nil {
		explicit = p
	}
	base, err := s.recheckPlanPolicy(ctx, t, id, RecheckOptions{SignatureMode: mode, Reason: "Describe owned processing contracts"}, false, explicit)
	if err != nil {
		return nil, err
	}
	row, err := t.FileCheck(ctx, id, false)
	if err != nil {
		return nil, err
	}
	now, err := t.DatabaseTime(ctx)
	if err != nil {
		return nil, err
	}
	report, _, err := projectionSourceReport(base, row, now)
	if err != nil {
		return nil, err
	}
	if err = projectionProtectionCurrent(ctx, t, base.PreviousPolicy.Definition, report); err != nil {
		return nil, err
	}
	var view *ProcessingContracts
	if binding != nil {
		producer := store.ExchangeParticipant{Tenant: t.Scope.Tenant, Partner: t.Scope.Partner, Actor: t.Actor, AuthorityRevision: t.AuthorityRevision, RootPolicyDigest: secure.Digest([]byte(t.Root))}
		view, err = processingContractsForProducer(base, row, now, binding, producer)
	} else {
		view, err = processingContracts(base, row, now)
	}
	if err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return view, t.Tx.Commit(ctx)
}
