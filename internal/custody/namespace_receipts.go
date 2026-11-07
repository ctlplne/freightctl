package custody

import (
	"context"
	"time"

	"github.com/ctlplne/freightctl/internal/store"
)

func (s *Service) ReadPathCommandReceipt(ctx context.Context, scope store.Scope, key string, command store.PathCommand) (*store.PathCommandReceipt, error) {
	if !store.ValidNamespaceRequestKey(key) {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.DB.Begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	receipt, err := t.ReadPathCommandReceipt(ctx, key, command)
	if err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	if err = t.Tx.Commit(ctx); err != nil {
		return nil, err
	}
	return receipt, nil
}
