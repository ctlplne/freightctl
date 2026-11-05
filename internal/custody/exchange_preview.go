package custody

import (
	"context"
	"time"

	"github.com/ctlplne/freightctl/internal/store"
)

// A metadata preview is neither an offer receipt nor a reservation. In
// particular it has no exchange/event identity and verifies no physical bytes.
type ExchangePreview struct {
	Request             store.ExchangeRequest `json:"request"`
	RequestHash         string                `json:"request_hash"`
	Sender              string                `json:"sender_actor_id"`
	Recipient           string                `json:"recipient_actor_id"`
	State               string                `json:"state"`
	StorageVerification string                `json:"storage_verification"`
}

func (s *Service) PreviewExchange(ctx context.Context, scope store.Scope, request store.ExchangeRequest) (*ExchangePreview, error) {
	limits, maximum, err := s.ExchangeLimits()
	if err != nil {
		return nil, err
	}
	if _, _, err = store.CanonicalExchangeRequest(request, limits); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.DB.Begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	proposed, err := t.PrepareArtifactExchange(ctx, request, limits, maximum)
	if err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	// Roll back the read transaction: preparation cannot reserve an ID, append
	// events, consume a slot, or mint a receipt/authority for a subsequent call.
	result := &ExchangePreview{Request: proposed.Request, RequestHash: proposed.RequestHash, Sender: proposed.Sender, Recipient: proposed.Recipient, State: "metadata-review-only", StorageVerification: "not-checked"}
	return result, t.Tx.Rollback(ctx)
}
