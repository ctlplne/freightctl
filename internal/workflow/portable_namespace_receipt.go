package workflow

import (
	"context"
	"io"
	"time"

	"github.com/ctlplne/freightctl/internal/store"
)

const PortableNamespaceReceiptProfile = "freightctl-portable-namespace-receipt-v1"

type PortableNamespaceReceipt struct {
	SchemaVersion int                       `json:"schema_version"`
	Profile       string                    `json:"profile"`
	SourceTenant  string                    `json:"source_tenant_id"`
	SourcePartner string                    `json:"source_partner_id"`
	SourceActor   string                    `json:"source_actor_id"`
	Source        Reference                 `json:"source"`
	Receipt       *store.PathCommandReceipt `json:"receipt"`
}

func (s *Service) PreparePortableNamespaceReceipt(ctx context.Context, scope store.Scope, key string, request store.PathCommand, output io.Writer) (*PortableExportReceipt, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	// Receipt reads use the acting participant's mount and permissions.
	tx, err := s.Custody.DB.Begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer tx.Tx.Rollback(ctx)
	receipt, err := tx.ReadPathCommandReceipt(ctx, key, request)
	if err != nil {
		return nil, err
	}
	_, hash, err := digest(receipt)
	if err != nil {
		return nil, err
	}
	ref := Reference{ID: receipt.CompletedEventID, Version: 1, Hash: hash}
	manifest := PortableNamespaceReceipt{
		SchemaVersion: 1, Profile: PortableNamespaceReceiptProfile,
		SourceTenant: scope.Tenant, SourcePartner: scope.Partner, SourceActor: tx.Actor,
		Source: ref, Receipt: receipt,
	}
	return WritePortableExport(ctx, tx, "PortableNamespaceReceiptExportPrepared", ref, manifest, output)
}
