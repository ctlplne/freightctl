package custody

import (
	"context"
	"io"
	"time"

	"github.com/ctlplne/freightctl/internal/portability"
	"github.com/ctlplne/freightctl/internal/store"
)

const PortableExchangeTraceProfile = "freightctl-portable-exchange-evidence-v1"

type ExchangeTraceExportReceipt = portability.JSONExportReceipt[store.ExchangeTraceExportSelection]

type PortableExchangeTrace struct {
	SchemaVersion int                                `json:"schema_version"`
	Profile       string                             `json:"profile"`
	Source        store.ExchangeTraceExportSelection `json:"source"`
	SourceActor   string                             `json:"source_actor_id"`
	Evidence      *store.ExchangeTrace               `json:"evidence"`
}

func (s *Service) PreparePortableExchangeTrace(ctx context.Context, scope store.Scope, request store.ExchangeTraceExportSelection, output io.Writer) (*ExchangeTraceExportReceipt, error) {
	if err := request.Validate(); err != nil {
		return nil, err
	}
	limits, _, err := s.ExchangeLimits()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.DB.Begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer tx.Tx.Rollback(ctx)
	trace, err := tx.TraceExchange(ctx, request.ExchangeTraceRequest, limits)
	if err != nil {
		return nil, err
	}
	if trace.Details != "authorized-records" {
		return nil, store.ErrState
	}
	if trace.RequestHash != request.RequestHash {
		return nil, store.ErrRevision
	}
	manifest := PortableExchangeTrace{
		SchemaVersion: 1, Profile: PortableExchangeTraceProfile, Source: request, SourceActor: tx.Actor, Evidence: trace,
	}
	return portability.WritePreparedJSON(ctx, tx, "PortableExchangeTraceExportPrepared", request.ID, request, manifest, output)
}
