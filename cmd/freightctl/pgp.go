package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"

	"github.com/ctlplne/freightctl/internal/checks"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

type pgpOptions struct {
	DSN, Token, Tenant, Partner, Storage, Input, Key, KeyID, FileID, PublicFile, SignatureFile, DataSHA, PolicyHash, DefinitionHash string
	Version                                                                                                                         int
	Revision                                                                                                                        int64
	MaxStored                                                                                                                       int64
}

func runPGP(ctx context.Context, command string, o pgpOptions) error {
	secret, err := secure.ReadSecret(o.Token, 64)
	if err != nil {
		return err
	}
	scope := store.Scope{Tenant: o.Tenant, Partner: o.Partner, TokenHash: secure.Digest(secret.Bytes)}
	secret.Close()
	db, err := store.Open(ctx, o.DSN)
	if err != nil {
		return err
	}
	defer db.Pool.Close()
	service := &checks.Service{Custody: &custody.Service{DB: db, MaxStored: o.MaxStored}}
	var result any
	switch command {
	case "pgp-key-register":
		f, err := os.Open(o.Input)
		if err != nil {
			return errors.New("cannot open PGP registration reference")
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil || !st.Mode().IsRegular() || st.Size() > 32<<10 {
			return checks.ErrInput
		}
		data, err := io.ReadAll(io.LimitReader(f, (32<<10)+1))
		if err != nil {
			return err
		}
		var request checks.PGPKeyRequest
		if workflow.Decode(data, &request) != nil {
			return checks.ErrInput
		}
		if o.PublicFile != "" {
			if len(request.PublicKey) != 0 {
				return checks.ErrInput
			}
			public, err := secure.ReadSecret(o.PublicFile, secure.MaxPGPWire)
			if err != nil {
				return err
			}
			defer public.Close()
			request.PublicKey = public.Bytes
		}
		result, err = service.RegisterPGPKey(ctx, scope, o.Key, request)
	case "pgp-key-status":
		result, err = service.PGPKey(ctx, scope, o.KeyID, o.Version)
	case "pgp-key-revoke":
		result, err = service.RevokePGPKey(ctx, scope, o.KeyID, o.Version, o.Key, workflow.Decision{Hash: o.DefinitionHash, Revision: o.Revision})
	case "check-signature":
		disk, err := custody.OpenExisting(o.Storage)
		if err != nil {
			return err
		}
		defer disk.Close()
		service.Custody.Disk = disk
		signature, err := secure.ReadSecret(o.SignatureFile, secure.MaxPGPWire)
		if err != nil {
			return err
		}
		defer signature.Close()
		result, err = service.AttachSignature(ctx, scope, o.FileID, o.Key, o.DataSHA, o.PolicyHash, o.Revision, signature.Bytes)
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}
