package custody

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ctlplne/freightctl/internal/store"
)

var ErrExchangeConfiguration = fmt.Errorf("artifact exchange limits are unconfigured or invalid: %w", store.ErrState)

// Settings are trusted deployment controls. A request cannot raise them and an
// unconfigured service does not silently enable the exchange adapter.
type ExchangeSettings struct {
	MaxLifetime  time.Duration
	MaxSenders   int
	MaxOpenViews int
	MaxEndpoints int
}

func (s *Service) ExchangeLimits() (store.ExchangeLimits, int, error) {
	settings := s.Exchanges
	if settings.MaxLifetime < time.Second || settings.MaxLifetime%time.Second != 0 || settings.MaxSenders < 1 || settings.MaxSenders > 128 || settings.MaxOpenViews < 1 || settings.MaxOpenViews > 10000 || settings.MaxEndpoints < 1 || settings.MaxEndpoints > 10000 || s.MaxFile < 0 {
		return store.ExchangeLimits{}, 0, ErrExchangeConfiguration
	}
	return store.ExchangeLimits{MaxArtifactBytes: s.MaxFile, MaxLifetime: settings.MaxLifetime, MaxSenders: settings.MaxSenders}, settings.MaxOpenViews, nil
}

func (s *Service) TraceExchange(ctx context.Context, scope store.Scope, r store.ExchangeTraceRequest) (*store.ExchangeTrace, error) {
	if err := store.ValidateExchangeTraceRequest(r); err != nil {
		return nil, err
	}
	limits, _, err := s.ExchangeLimits()
	if err != nil {
		return nil, err
	}
	return s.DB.TraceExchange(ctx, scope, r, limits)
}

func (s *Service) OfferExchange(ctx context.Context, scope store.Scope, key string, request store.ExchangeRequest) (*store.ArtifactExchangeResult, error) {
	limits, maximum, err := s.ExchangeLimits()
	if err != nil {
		return nil, err
	}
	_, meaning, err := store.CanonicalExchangeRequest(request, limits)
	if err != nil || !store.ValidBrowserOperationKey(key) {
		return nil, store.ErrExchangeInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.DB.Begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	for _, permission := range []string{"read", "deliver"} {
		if err = t.Require(permission); err != nil {
			return nil, err
		}
	}
	prior, err := t.ArtifactExchangeReplay(ctx, key, meaning, limits)
	if err != nil {
		return nil, err
	}
	if prior != nil {
		if err = t.Reauthorize(ctx); err != nil {
			return nil, err
		}
		return &store.ArtifactExchangeResult{Exchange: *prior, Replayed: true}, t.Tx.Commit(ctx)
	}
	e, err := t.PrepareArtifactExchange(ctx, request, limits, maximum)
	if err != nil {
		return nil, err
	}
	if s.Disk == nil {
		return nil, ErrStorageIdentity
	}
	if err = s.Disk.CheckIdentity(); err != nil {
		return nil, err
	}
	data, err := s.Disk.VerifiedContext(ctx, Name(scope.Tenant, scope.Partner, request.Artifact.ID), request.Artifact.Size, request.Artifact.SHA256)
	if err != nil {
		return nil, err
	}
	if err = data.Close(); err != nil {
		return nil, err
	}
	e.StorageID = s.Disk.Identity()
	if err = t.SaveArtifactExchange(ctx, key, e); err != nil {
		return nil, err
	}
	return &store.ArtifactExchangeResult{Exchange: *e}, t.Tx.Commit(ctx)
}

// Review metadata only. Publication still independently verifies the complete
// storage bytes, endpoint/head/participants, policy and every request binding.
func (s *Service) InspectExchangeSource(ctx context.Context, scope store.Scope, id string) (*store.ExchangeArtifact, error) {
	if !store.ValidID(id) {
		return nil, store.ErrExchangeInput
	}
	if _, _, err := s.ExchangeLimits(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.DB.Begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	f, err := t.AuthorizeExchangeSource(ctx, id)
	if err != nil {
		return nil, err
	}
	result := &store.ExchangeArtifact{ID: f.ID, Size: f.Size, SHA256: f.SHA256, Policy: f.Policy}
	return result, t.Tx.Commit(ctx)
}

func (s *Service) OpenExchangeReader(ctx context.Context, scope store.Scope, id string) (*store.File, *RevisionReader, error) {
	if !store.ValidID(id) {
		return nil, nil, store.ErrNotFound
	}
	limits, _, err := s.ExchangeLimits()
	if err != nil {
		return nil, nil, err
	}
	admission, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.DB.Begin(admission, scope)
	if err != nil {
		return nil, nil, err
	}
	defer t.Tx.Rollback(admission)
	e, f, err := t.AuthorizeIncomingExchange(admission, id, limits)
	if err != nil {
		return nil, nil, err
	}
	if s.Disk == nil || s.Disk.Identity() != e.StorageID {
		return nil, nil, ErrStorageIdentity
	}
	if err = s.Disk.CheckIdentity(); err != nil {
		return nil, nil, err
	}
	data, err := s.Disk.VerifiedContext(admission, Name(scope.Tenant, scope.Partner, f.ID), f.Size, f.SHA256)
	if err != nil {
		return nil, nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = data.Close()
		}
	}()
	if err = t.Reauthorize(admission); err != nil {
		return nil, nil, err
	}
	if _, err = t.Append(admission, "ArtifactExchangeRetrievalAuthorized", e.ID, map[string]string{"file_revision_id": f.ID, "sha256": f.SHA256, "evidence": "read-authorized-only"}); err != nil {
		return nil, nil, err
	}
	if err = t.Tx.Commit(admission); err != nil {
		return nil, nil, err
	}
	ok = true
	return f, &RevisionReader{service: s, ctx: ctx, scope: scope, file: f, data: data, exchangeID: e.ID}, nil
}

func (r *RevisionReader) checkExchangeRead(ctx context.Context, t *store.Transaction) error {
	limits, _, err := r.service.ExchangeLimits()
	if err != nil {
		return err
	}
	e, f, err := t.AuthorizeIncomingExchange(ctx, r.exchangeID, limits)
	if err != nil {
		return err
	}
	if *f != *r.file {
		return ErrIntegrity
	}
	if r.service.Disk == nil || r.service.Disk.Identity() != e.StorageID {
		return ErrStorageIdentity
	}
	return r.service.Disk.CheckIdentity()
}

func (s *Service) InspectExchange(ctx context.Context, scope store.Scope, id string) (*store.IncomingExchange, error) {
	if !store.ValidID(id) {
		return nil, store.ErrNotFound
	}
	limits, _, err := s.ExchangeLimits()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.DB.Begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	// This endpoint inspects incoming views. Senders recover their immutable
	// publication receipt by the original submission key; no receipt opens bytes.
	e, _, err := t.AuthorizeIncomingExchange(ctx, id, limits)
	if err != nil && !errors.Is(err, store.ErrState) {
		return nil, err
	}
	result := &store.IncomingExchange{ID: id, State: "held"}
	if err == nil {
		result.State, result.Exchange = "offered", e
	} else if !errors.Is(err, store.ErrState) {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return result, t.Tx.Commit(ctx)
}
