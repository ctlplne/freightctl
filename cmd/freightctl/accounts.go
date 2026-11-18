package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func runAccounts(ctx context.Context, command, dsn, token, tenant, partner, input, key, id, after, newToken, output string, revision int64, limit int) error {
	if command == "account-export" {
		if err := validatePortableOutput(output); err != nil {
			return err
		}
		if !store.ValidID(id) || revision < 1 {
			return store.ErrAccountInput
		}
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
	switch command {
	case "account-list":
		result, err = db.Accounts(ctx, scope, after, limit)
	case "account-status":
		result, err = db.Account(ctx, scope, id)
	case "account-export":
		service := &custody.Service{DB: db}
		ref := custody.AccountExportReference{ID: id, Revision: revision}
		return writePortableArtifact(ctx, output, "account-policy", func(staged io.Writer) (*custody.AccountExportReceipt, error) {
			return service.PreparePortableAccount(ctx, scope, ref, staged)
		}, os.Stdout)
	default:
		f, e := os.Open(input)
		if e != nil {
			return errors.New("cannot open account command reference")
		}
		defer f.Close()
		st, e := f.Stat()
		if e != nil || !st.Mode().IsRegular() || st.Size() > 32<<10 {
			return store.ErrAccountInput
		}
		data, e := io.ReadAll(io.LimitReader(f, (32<<10)+1))
		if e != nil {
			return e
		}
		defer secure.Clear(data)
		var request store.AccountCommand
		if workflow.Decode(data, &request) != nil || request.Operation != strings.TrimPrefix(command, "account-") {
			return store.ErrAccountInput
		}
		if newToken != "" {
			if (request.Operation != "create" && request.Operation != "rotate") || request.CredentialHash != "" {
				return store.ErrAccountInput
			}
			credential, e := secure.ReadSecret(newToken, 64)
			if e != nil {
				return e
			}
			if len(credential.Bytes) != 64 {
				credential.Close()
				return store.ErrAccountInput
			}
			request.CredentialHash = secure.Digest(credential.Bytes)
			credential.Close()
		}
		result, err = db.ChangeAccount(ctx, scope, key, request)
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}
