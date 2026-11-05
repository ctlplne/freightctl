//go:build integration

package custody_test

import (
	"errors"
	"testing"

	"github.com/ctlplne/freightctl/internal/checks"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestExchangeSourceReviewUsesOwnSourceAuthorityAndCurrentPolicy(t *testing.T) {
	f := newExchangeFixture(t)
	file := actorFile(t, f, f.a, "source-review", []byte("row\nvalue\n"))
	source, err := f.service.InspectExchangeSource(f.ctx, f.a, file.ID)
	if err != nil || *source != (store.ExchangeArtifact{ID: file.ID, Size: file.Size, SHA256: file.SHA256, Policy: file.Policy}) {
		t.Fatal("source review changed exact metadata", err)
	}
	if _, err = f.service.InspectExchangeSource(f.ctx, f.other, file.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("unrelated sender reviewed private source", err)
	}
	if _, err = f.service.InspectExchangeSource(f.ctx, f.b, file.ID); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("receive-only role reviewed source", err)
	}
	checking := &checks.Service{Custody: f.service}
	if _, err = checking.Register(f.ctx, f.fixture.a, "review-policy-change", checks.PolicyRequest{Definition: checks.Policy{Schema: 1, Kind: "csv", Columns: []checks.Column{{Name: "row", Type: "text", Required: true}}}}); err != nil {
		t.Fatal(err)
	}
	if _, err = f.service.InspectExchangeSource(f.ctx, f.a, file.ID); !errors.Is(err, store.ErrState) {
		t.Fatal("source review ignored new intake policy", err)
	}
}
