package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/delivery"
	"github.com/ctlplne/freightctl/internal/store"
)

type localSourceProfileReceipt struct {
	Schema            int    `json:"schema_version"`
	Profile           string `json:"profile"`
	ConfigurationHash string `json:"configuration_sha256"`
	ReferenceHash     string `json:"root_reference_sha256"`
	RootFingerprint   string `json:"root_fingerprint"`
	ReadOnly          bool   `json:"read_only"`
}

func writeLocalSourceProfile(ctx context.Context, directory, output string, check func() error) (localSourceProfileReceipt, error) {
	var receipt localSourceProfileReceipt
	if check == nil || len(output) > 4096 || !filepath.IsAbs(output) || filepath.Clean(output) != output || strings.ContainsAny(output, "\x00\r\n") {
		return receipt, delivery.ErrLocalSource
	}
	identity, err := delivery.InspectLocalCollectionRoot(ctx, directory, check)
	if err != nil {
		return receipt, err
	}
	producerPath, err := filepath.EvalSymlinks(directory)
	if err != nil {
		return receipt, delivery.ErrLocalSource
	}
	outputParent, err := filepath.EvalSymlinks(filepath.Dir(output))
	if err != nil {
		return receipt, delivery.ErrLocalSource
	}
	relative, err := filepath.Rel(producerPath, outputParent)
	if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return receipt, delivery.ErrLocalSource
	}
	profile := struct {
		Schema          int    `json:"schema_version"`
		Profile         string `json:"profile"`
		Directory       string `json:"directory"`
		RootFingerprint string `json:"root_fingerprint"`
	}{1, delivery.LocalCollectionProfile, directory, identity}
	raw, err := json.Marshal(profile)
	if err != nil {
		return receipt, err
	}
	raw = append(raw, '\n')
	defer clear(raw)
	root, err := os.OpenRoot(filepath.Dir(output))
	if err != nil {
		return receipt, store.ErrIsolation
	}
	defer root.Close()
	stage, err := stageExchangeBytesAt(ctx, int64(len(raw)), secure.Digest(raw), bytes.NewReader(raw), root)
	if err != nil {
		return receipt, err
	}
	defer root.Remove(stage.name)
	// Recheck both current management authority and the physical producer root
	// after private staging,immediately before giving the configuration a name.
	current, err := delivery.InspectLocalCollectionRoot(ctx, directory, check)
	if err != nil {
		return receipt, err
	}
	if current != identity {
		return receipt, delivery.ErrLocalSource
	}
	if err = stage.publish(output); err != nil {
		return receipt, err
	}
	return localSourceProfileReceipt{Schema: 1, Profile: delivery.LocalCollectionProfile, ConfigurationHash: secure.Digest(raw), ReferenceHash: secure.Digest([]byte(output)), RootFingerprint: identity, ReadOnly: true}, nil
}

func runLocalSourceProfile(ctx context.Context, dsn, token, tenant, partner, directory, output string, stdout io.Writer) error {
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
	tx, err := db.Begin(ctx, scope)
	if err != nil {
		return err
	}
	defer tx.Tx.Rollback(ctx)
	if tx.Root != "/" {
		return store.ErrForbidden
	}
	for _, permission := range []string{"admin", "connections_manage"} {
		if err = tx.Require(permission); err != nil {
			return err
		}
	}
	receipt, err := writeLocalSourceProfile(ctx, directory, output, func() error { return tx.Reauthorize(ctx) })
	if err != nil {
		return err
	}
	if err = tx.Tx.Commit(ctx); err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(receipt)
}
