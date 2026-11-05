//go:build integration

package custody_test

import (
	"errors"
	"testing"

	"github.com/ctlplne/freightctl/internal/store"
)

func TestExchangePreviewLeavesNoGrantReceiptReservationOrEvent(t *testing.T) {
	f := newExchangeFixture(t)
	file := actorFile(t, f, f.a, "preview-source", []byte("preview bytes\n"))
	request := exchangeRequest(file, f.endpoint)
	counts := func() (int, int, int) {
		t.Helper()
		tx, err := f.db.Begin(f.ctx, f.a)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Tx.Rollback(f.ctx)
		var views, receipts, events int
		if err = tx.Tx.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM artifact_exchanges),(SELECT count(*) FROM artifact_exchange_commands),(SELECT count(*) FROM events)`).Scan(&views, &receipts, &events); err != nil {
			t.Fatal(err)
		}
		return views, receipts, events
	}
	v0, r0, e0 := counts()
	for range 3 {
		preview, err := f.service.PreviewExchange(f.ctx, f.a, request)
		if err != nil || preview.State != "metadata-review-only" || preview.StorageVerification != "not-checked" || preview.Request != request || preview.Sender != f.actorA.Actor || preview.Recipient != f.actorB.Actor {
			t.Fatal("metadata review changed meaning or claimed acceptance", err)
		}
		_, hash, err := store.CanonicalExchangeRequest(request, f.limits)
		if err != nil || preview.RequestHash != hash {
			t.Fatal("preview changed canonical request hash", err)
		}
	}
	v1, r1, e1 := counts()
	if v1 != v0 || r1 != r0 || e1 != e0 {
		t.Fatal("preview created durable effects")
	}
	if _, err := f.service.PreviewExchange(f.ctx, f.b, request); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("receiving granted preparation authority", err)
	}
	changed := request
	changed.Artifact.Size++
	if _, err := f.service.PreviewExchange(f.ctx, f.a, changed); !errors.Is(err, store.ErrRevision) {
		t.Fatal("preview accepted a different revision", err)
	}
	if _, err := f.service.OfferExchange(f.ctx, f.a, "after-metadata-preview", request); err != nil {
		t.Fatal("preview consumed admission capacity", err)
	}
}
