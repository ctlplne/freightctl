package main

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func TestExchangeEvidenceCLIRefusesUnrequestedDataBeforeOpeningIdentityOrDatabase(t *testing.T) {
	for _, test := range []struct {
		body string
		want error
	}{
		{`{"exchange_id":"33333333-3333-4333-8333-333333333333","direction":"admin"}`, store.ErrExchangeInput},
		{`{"exchange_id":"not-an-id","direction":"incoming"}`, store.ErrExchangeInput},
		{`{"exchange_id":"33333333-3333-4333-8333-333333333333","direction":"incoming","raw_events":true}`, workflow.ErrInput},
		{`{"exchange_id":"33333333-3333-4333-8333-333333333333","direction":"incoming","DIRECTION":"outgoing"}`, workflow.ErrInput},
	} {
		path := filepath.Join(t.TempDir(), "request.json")
		writeProtectedCLIReference(t, path, []byte(test.body))
		err := runExchanges(context.Background(), "exchange-trace", exchangeOptions{Input: path, MaxFile: 1024, Settings: custody.ExchangeSettings{MaxLifetime: time.Hour, MaxSenders: 16, MaxOpenViews: 128, MaxEndpoints: 16}}, io.Discard)
		if !errors.Is(err, test.want) {
			t.Fatal("trace opened authentication/database before exact control validation", err)
		}
	}
}
