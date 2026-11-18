package custody

import (
	"context"
	"io"
	"time"

	"github.com/ctlplne/freightctl/internal/portability"
	"github.com/ctlplne/freightctl/internal/store"
)

const PortableAccountProfile = "freightctl-portable-account-policy-v1"

type AccountExportReference struct {
	ID       string `json:"account_id"`
	Revision int64  `json:"revision"`
}

type AccountExportReceipt = portability.JSONExportReceipt[AccountExportReference]

type PortableAccount struct {
	SchemaVersion    int                          `json:"schema_version"`
	Profile          string                       `json:"profile"`
	SourceTenant     string                       `json:"source_tenant_id"`
	SourcePartner    string                       `json:"source_partner_id"`
	Source           AccountExportReference       `json:"source"`
	RecordedPolicy   *store.AccountPolicySnapshot `json:"source_policy"`
	Registration     store.AccountCommand         `json:"destination_registration"`
	RequiredBindings []string                     `json:"required_bindings"`
}

func (s *Service) PreparePortableAccount(ctx context.Context, scope store.Scope, ref AccountExportReference, output io.Writer) (*AccountExportReceipt, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.DB.Begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer tx.Tx.Rollback(ctx)
	policy, err := tx.AccountPolicyForExport(ctx, ref.ID, ref.Revision)
	if err != nil {
		return nil, err
	}
	manifest := PortableAccount{
		SchemaVersion: 1, Profile: PortableAccountProfile,
		SourceTenant: scope.Tenant, SourcePartner: scope.Partner, Source: ref,
		RecordedPolicy: policy,
		Registration: store.AccountCommand{Operation: "create", Policy: &store.AccountPolicy{
			Label: policy.Policy.Label, ExpiresAt: policy.Policy.ExpiresAt,
		}},
		RequiredBindings: []string{"account_id", "policy.namespace_root", "policy.permissions", "--new-token-file"},
	}
	return portability.WritePreparedJSON(ctx, tx, "PortableAccountPolicyExportPrepared", ref.ID, ref, manifest, output)
}
