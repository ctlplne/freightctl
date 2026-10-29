package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func runPartners(ctx context.Context, command, admin, dsn, token, tenant, partner, input, key, after, newToken, accountID string, limit int) error {
	if command == "tenant-admin-status" {
		r, err := store.TenantAdminStatus(ctx, admin, tenant, partner, accountID)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(r)
	}
	var data []byte
	if command != "partner-list" {
		f, err := os.Open(input)
		if err != nil {
			return errors.New("cannot open partner command reference")
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil || !st.Mode().IsRegular() || st.Size() > 16<<10 {
			return store.ErrPartnerInput
		}
		data, err = io.ReadAll(io.LimitReader(f, (16<<10)+1))
		if err != nil {
			return err
		}
		defer secure.Clear(data)
	}
	if strings.HasPrefix(command, "tenant-admin-") {
		var c store.TenantAdminCommand
		if workflow.Decode(data, &c) != nil || c.Operation != strings.TrimPrefix(command, "tenant-admin-") {
			return store.ErrPartnerInput
		}
		r, err := store.AdministerTenant(ctx, admin, tenant, partner, key, c)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(r)
	}
	secret, err := secure.ReadSecret(token, 64)
	if err != nil {
		return err
	}
	scope := store.Scope{Tenant: tenant, Partner: partner, TokenHash: secure.Digest(secret.Bytes)}
	secret.Close()
	db, err := store.Open(ctx, dsn)
	if err != nil {
		return err
	}
	defer db.Pool.Close()
	var result any
	if command == "partner-list" {
		result, err = db.Partners(ctx, scope, after, limit)
	} else {
		var c store.PartnerCommand
		if workflow.Decode(data, &c) != nil {
			return store.ErrPartnerInput
		}
		if newToken != "" {
			if c.Credential != "" {
				return store.ErrPartnerInput
			}
			credential, e := setupToken(newToken, false)
			if e != nil {
				return e
			}
			c.Credential = secure.Digest(credential.Bytes)
			credential.Close()
		}
		result, err = db.RegisterPartner(ctx, scope, key, c)
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}
