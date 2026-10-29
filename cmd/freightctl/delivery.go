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
	"github.com/ctlplne/freightctl/internal/delivery"
	"github.com/ctlplne/freightctl/internal/store"
)

func runDelivery(ctx context.Context, command, dsn, token, tenant, partner, storage, input, key, id, hash string, revision, maxFile int64) error {
	if maxFile < 1 || maxFile > 1<<30 {
		return errors.New("invalid delivery file budget")
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
	custodyService := &custody.Service{DB: db, MaxFile: maxFile}
	if command == "delivery-create" || command == "delivery-work" || command == "delivery-reconcile" {
		disk, err := custody.OpenExisting(storage)
		if err != nil {
			return err
		}
		defer disk.Close()
		custodyService.Disk = disk
	}
	service := &delivery.Service{Custody: custodyService}
	var result any
	switch command {
	case "delivery-create":
		f, openErr := os.Open(input)
		if openErr != nil {
			return errors.New("cannot open delivery request reference")
		}
		defer f.Close()
		st, statErr := f.Stat()
		if statErr != nil || !st.Mode().IsRegular() || st.Size() > 16<<10 {
			return errors.New("delivery request must be bounded regular JSON")
		}
		decoder := json.NewDecoder(io.LimitReader(f, 16<<10))
		decoder.DisallowUnknownFields()
		var request delivery.Request
		if err = decoder.Decode(&request); err != nil {
			return errors.New("invalid delivery request JSON")
		}
		var extra any
		if decoder.Decode(&extra) != io.EOF {
			return errors.New("delivery request has trailing data")
		}
		result, err = service.Create(ctx, scope, key, request)
	case "delivery-status":
		result, err = service.Status(ctx, scope, id)
	case "delivery-approve", "delivery-cancel":
		result, err = service.Command(ctx, scope, id, key, strings.TrimPrefix(command, "delivery-"), hash, revision)
	case "delivery-work":
		result, err = service.Work(ctx, scope, id)
	case "delivery-reconcile":
		result, err = service.Reconcile(ctx, scope, id)
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}
