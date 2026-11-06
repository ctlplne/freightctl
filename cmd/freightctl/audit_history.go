package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

type auditHistoryOptions struct{ DSN, Token, Tenant, Partner, Input string }

func runAuditHistory(ctx context.Context, o auditHistoryOptions, output io.Writer) error {
	if !store.ValidID(o.Tenant) || !store.ValidID(o.Partner) {
		return store.ErrExchangeInput
	}
	input, err := secure.ReadSecret(o.Input, 8<<10)
	if err != nil {
		return errors.New("audit search must be a protected bounded regular file")
	}
	r, err := store.DecodeAuditHistory(input.Bytes)
	input.Close()
	if err != nil {
		return err
	}
	token, err := secure.ReadSecret(o.Token, 64)
	if err != nil {
		return err
	}
	if len(token.Bytes) != 64 {
		token.Close()
		return store.ErrUnauthorized
	}
	scope := store.Scope{Tenant: o.Tenant, Partner: o.Partner, TokenHash: secure.Digest(token.Bytes)}
	token.Close()
	db, err := store.Open(ctx, o.DSN)
	if err != nil {
		return err
	}
	defer db.Pool.Close()
	result, err := db.SearchAuditHistory(ctx, scope, *r)
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(result)
}
