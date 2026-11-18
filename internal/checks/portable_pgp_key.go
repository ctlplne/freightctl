package checks

import (
	"context"
	"io"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

const PortablePGPKeyProfile = "freightctl-portable-openpgp-public-key-v1"

type PortablePGPKey struct {
	SchemaVersion    int                `json:"schema_version"`
	Profile          string             `json:"profile"`
	SourceTenant     string             `json:"source_tenant_id"`
	SourcePartner    string             `json:"source_partner_id"`
	Source           workflow.Reference `json:"source"`
	ObservedState    string             `json:"observed_state"`
	ValidUntil       *time.Time         `json:"valid_until,omitempty"`
	PublicSHA256     string             `json:"public_key_sha256"`
	Registration     PGPKeyRequest      `json:"destination_registration"`
	RequiredBindings []string           `json:"required_bindings"`
}

func (s *Service) PreparePortablePGPKey(ctx context.Context, scope store.Scope, ref workflow.Reference, output io.Writer) (*workflow.PortableExportReceipt, error) {
	if !store.ValidID(ref.ID) || ref.Version < 1 || !hashPattern.MatchString(ref.Hash) {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.begin(ctx, scope, "admin", "pgp_manage")
	if err != nil {
		return nil, err
	}
	defer tx.Tx.Rollback(ctx)
	if tx.Root != "/" {
		return nil, store.ErrForbidden
	}
	row, err := tx.PGPKeySnapshot(ctx, ref.ID, ref.Version)
	if err != nil {
		return nil, err
	}
	if row.Hash != ref.Hash {
		return nil, store.ErrRevision
	}
	definition, err := decodeKey(row)
	if err != nil {
		return nil, err
	}
	if secure.InspectStoredPGPPublicPackets(definition.Packets) != nil || (definition.Purpose != "" && definition.Purpose != "encrypt") {
		return nil, store.ErrState
	}
	manifest := PortablePGPKey{
		SchemaVersion: 1, Profile: PortablePGPKeyProfile,
		SourceTenant: scope.Tenant, SourcePartner: scope.Partner, Source: ref, ObservedState: row.State,
		ValidUntil: definition.ValidUntil, PublicSHA256: secure.Digest(definition.Packets),
		Registration:     PGPKeyRequest{ExpectedVersion: -1, Fingerprint: definition.Fingerprint, PublicKey: definition.Packets, Purpose: definition.Purpose},
		RequiredBindings: []string{"expected_version"},
	}
	return workflow.WritePortableExport(ctx, tx, "PortablePGPPublicKeyExportPrepared", ref, manifest, output)
}
