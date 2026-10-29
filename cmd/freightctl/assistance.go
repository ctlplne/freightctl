package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"

	"github.com/ctlplne/freightctl/internal/assistance"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func runAssistance(ctx context.Context, command, dsn, token, tenant, partner, input, key, profileID, jobID, contextHash, profileHash string, version int, revision int64, enabled bool) error {
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
	service := &assistance.Service{DB: db, Enabled: enabled}
	decode := func(target any) error {
		f, err := os.Open(input)
		if err != nil {
			return errors.New("cannot open assistance request reference")
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil || !st.Mode().IsRegular() || st.Size() > 32<<10 {
			return errors.New("assistance request must be bounded regular JSON")
		}
		data, err := io.ReadAll(io.LimitReader(f, (32<<10)+1))
		if err != nil {
			return err
		}
		return workflow.Decode(data, target)
	}
	var result any
	switch command {
	case "ai-profile-register":
		var r assistance.ProfileRequest
		if err = decode(&r); err != nil {
			return err
		}
		result, err = service.Register(ctx, scope, key, r)
	case "ai-profile-status":
		result, err = service.Profile(ctx, scope, profileID, version)
	case "ai-profile-revoke":
		result, err = service.Revoke(ctx, scope, profileID, version, key, workflow.Decision{Hash: profileHash, Revision: revision})
	case "ai-propose", "ai-diagnose":
		var r assistance.PrepareRequest
		if err = decode(&r); err != nil {
			return err
		}
		expected := "propose"
		if command == "ai-diagnose" {
			expected = "diagnose"
		}
		if r.Kind != "" && r.Kind != expected {
			return assistance.ErrInput
		}
		r.Kind = expected
		result, err = service.Prepare(ctx, scope, key, r)
	case "ai-status":
		result, err = service.Get(ctx, scope, jobID)
	case "ai-approve":
		result, err = service.Approve(ctx, scope, jobID, key, assistance.Decision{Hash: contextHash, Revision: revision})
	case "ai-generate":
		result, err = service.Generate(ctx, scope, jobID, key)
	case "ai-adopt":
		result, err = service.Adopt(ctx, scope, jobID, key, assistance.Decision{Hash: contextHash, Revision: revision})
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}
