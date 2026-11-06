package custody

import (
	"context"
	"io"
	"os"

	"github.com/ctlplne/freightctl/internal/store"
)

type ExchangeCopyResult struct {
	Profile             string                   `json:"profile"`
	Source              store.ExchangeCopyOrigin `json:"source"`
	Artifact            store.ExchangeArtifact   `json:"artifact"`
	EventID             string                   `json:"event_id"`
	Acceptance          string                   `json:"acceptance"`
	Replayed            bool                     `json:"replayed"`
	Observation         string                   `json:"observation"`
	CurrentState        string                   `json:"current_state"`
	ReceiverPersistence string                   `json:"receiver_persistence"`
	BusinessProcessing  string                   `json:"business_processing"`
}

type receivedCopy struct {
	request store.ExchangeCopyRequest
	limits  store.ExchangeLimits
}

func (s *Service) CopyReceivedExchange(ctx context.Context, scope store.Scope, key string, request store.ExchangeCopyRequest) (*ExchangeCopyResult, error) {
	if err := store.ValidateExchangeCopy(request, s.MaxFile); err != nil || !store.ValidBrowserOperationKey(key) {
		return nil, store.ErrExchangeInput
	}
	limits, _, err := s.ExchangeLimits()
	if err != nil {
		return nil, err
	}
	if s.Disk == nil {
		return nil, ErrStorageIdentity
	}
	mode := uint32(0600)
	f, replayed, err := s.accept(ctx, scope, key, request.Artifact.Size, request.Artifact.SHA256, nil, &UploadTarget{Path: request.Path, Mode: &mode}, nil, &receivedCopy{request: request, limits: limits})
	if err != nil {
		return nil, err
	}
	return &ExchangeCopyResult{Profile: "received-artifact-copy-v1", Source: request.ExchangeCopyOrigin, Artifact: store.ExchangeArtifact{ID: f.ID, Size: f.Size, SHA256: f.SHA256, Policy: f.Policy}, EventID: f.EventID, Acceptance: Acceptance(f), Replayed: replayed, Observation: "original-command-receipt", CurrentState: "not-checked", ReceiverPersistence: "unknown", BusinessProcessing: "unknown"}, nil
}

func (c *receivedCopy) check(ctx context.Context, t *store.Transaction, s *Service) error {
	if err := t.Reauthorize(ctx); err != nil {
		return err
	}
	for _, permission := range []string{"read", "list", "write"} {
		if err := t.Require(permission); err != nil {
			return err
		}
	}
	e, f, err := t.AuthorizeIncomingExchange(ctx, c.request.ExchangeID, c.limits)
	if err != nil {
		return err
	}
	if e.RequestHash != c.request.RequestHash || e.Request.Artifact != c.request.Artifact || f.ID != c.request.Artifact.ID || f.Size != c.request.Artifact.Size || f.SHA256 != c.request.Artifact.SHA256 || f.Policy != c.request.Artifact.Policy {
		return store.ErrRevision
	}
	if s.Disk == nil || s.Disk.Identity() != e.StorageID {
		return ErrStorageIdentity
	}
	return s.Disk.CheckIdentity()
}

func (c *receivedCopy) open(ctx context.Context, t *store.Transaction, s *Service) (io.ReadCloser, error) {
	// Serialize copy lock upgrades. Take the view/endpoint/source read locks
	// before upgrading the ordinary destination namespace lock in accept.
	if _, err := t.Tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, t.Scope.Tenant+":"+t.Scope.Partner+":exchange-copy-v1"); err != nil {
		return nil, err
	}
	if err := c.check(ctx, t, s); err != nil {
		return nil, err
	}
	f, err := s.Disk.VerifiedContext(ctx, Name(t.Scope.Tenant, t.Scope.Partner, c.request.Artifact.ID), c.request.Artifact.Size, c.request.Artifact.SHA256)
	if err != nil {
		return nil, err
	}
	return &receivedCopyReader{ctx: ctx, tx: t, service: s, source: c, data: f}, nil
}

type receivedCopyReader struct {
	ctx     context.Context
	tx      *store.Transaction
	service *Service
	source  *receivedCopy
	data    *os.File
}

func (r *receivedCopyReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if err := r.source.check(r.ctx, r.tx, r.service); err != nil {
		return 0, err
	}
	if len(p) > 256<<10 {
		p = p[:256<<10]
	}
	return r.data.Read(p)
}

func (r *receivedCopyReader) Close() error { return r.data.Close() }
