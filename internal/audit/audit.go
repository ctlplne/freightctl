// Package audit prepares scoped signed snapshots; it cannot execute transfers.
package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

var ErrUnconfigured = errors.New("audit signing identity not configured")

type Service struct {
	DB                  *store.Store
	KeyFile             string
	MaxEvents, MaxBytes int
	sign                func(string, []byte) (*secure.SignedAudit, error)
}

func (s *Service) Export(ctx context.Context, scope store.Scope) (*secure.SignedAudit, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	maxEvents, maxBytes := s.MaxEvents, s.MaxBytes
	if maxEvents == 0 {
		maxEvents = 10000
	}
	if maxBytes == 0 {
		maxBytes = 8 << 20
	}
	snapshot, err := s.DB.SnapshotEvents(ctx, scope, maxEvents, maxBytes)
	if err != nil {
		return nil, err
	}
	if s.KeyFile == "" {
		return nil, ErrUnconfigured
	}
	var payload bytes.Buffer
	encoder := json.NewEncoder(&payload)
	encoder.SetEscapeHTML(false)
	if err = encoder.Encode(snapshot); err != nil {
		return nil, err
	}
	if payload.Len() > maxBytes {
		return nil, store.ErrLimit
	}
	sign := secure.SignAuditPayload
	if s.sign != nil {
		sign = s.sign
	}
	envelope, err := sign(s.KeyFile, payload.Bytes())
	if err != nil {
		return nil, err
	}
	// The snapshot's repeatable-read authorization may be stale now. Recheck live state.
	t, err := s.DB.Begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	_, err = t.Append(ctx, "AuditSnapshotPrepared", snapshot.ID, map[string]any{"event_count": snapshot.EventCount, "snapshot_at": snapshot.At, "payload_sha256": secure.Digest(payload.Bytes()), "key_sha256_der": envelope.KeyFingerprint})
	if err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	if err = t.Tx.Commit(ctx); err != nil {
		return nil, err
	}
	return envelope, nil
}
