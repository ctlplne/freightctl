package workflow

import (
	"context"
	"io"
	"time"

	"github.com/ctlplne/freightctl/internal/store"
)

const PortablePartnerProfile = "freightctl-portable-partner-v1"

type PortablePartner struct {
	SchemaVersion      int                  `json:"schema_version"`
	Profile            string               `json:"profile"`
	SourceTenant       string               `json:"source_tenant_id"`
	Source             Reference            `json:"source"`
	SourceRegistration *store.Partner       `json:"source_registration"`
	Registration       store.PartnerCommand `json:"destination_registration"`
	RequiredBindings   []string             `json:"required_bindings"`
}

func (s *Service) PreparePortablePartner(ctx context.Context, scope store.Scope, partner, event string, output io.Writer) (*PortableExportReceipt, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer tx.Tx.Rollback(ctx)
	registered, err := tx.PartnerRegistrationForExport(ctx, partner, event)
	if err != nil {
		return nil, err
	}
	_, hash, err := digest(registered)
	if err != nil {
		return nil, err
	}
	ref := Reference{ID: registered.ID, Version: 1, Hash: hash}
	manifest := PortablePartner{
		SchemaVersion: 1, Profile: PortablePartnerProfile,
		SourceTenant: scope.Tenant, Source: ref, SourceRegistration: registered,
		Registration: store.PartnerCommand{Label: registered.Label, AdminLabel: registered.AdminLabel},
		RequiredBindings: []string{
			"partner_id", "admin_id", "--new-token-file", "permissions",
			"expected_authority_revision", "expected_tenant_revision",
		},
	}
	return WritePortableExport(ctx, tx, "PortablePartnerExportPrepared", ref, manifest, output)
}
