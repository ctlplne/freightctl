package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/portability"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func portableFilesRestore(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("bundle-restore", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	tenant := flags.String("tenant", "", "destination tenant UUID")
	partner := flags.String("partner", "", "destination partner UUID")
	token := flags.String("token-file", ".private/partner.token", "protected destination token")
	dsn := flags.String("dsn-file", ".private/pg-runtime.dsn", "protected destination runtime database reference")
	storage := flags.String("storage", ".private/custody", "private destination custody root")
	request := flags.String("request-file", "", "protected recovery selection")
	input := flags.String("input", "", "protected archive")
	key := flags.String("idempotency-key", "", "stable recovery key")
	maxFile := flags.Int64("max-file-bytes", 64<<20, "destination file budget")
	maxStored := flags.Int64("max-stored-bytes", 1<<30, "destination custody quota")
	maxEntries := flags.Int("namespace-max-entries", 10000, "destination namespace quota")
	const usage = "freightctl bundle-restore --tenant <uuid> --partner <uuid> --input <protected tar> --request-file <selection> --idempotency-key <key>"
	if err := flags.Parse(args); errors.Is(err, flag.ErrHelp) {
		_, err = io.WriteString(output, usage+"\n")
		return err
	} else if err != nil || flags.NArg() != 0 || *request == "" || *input == "" || *key == "" ||
		!store.ValidID(*tenant) || !store.ValidID(*partner) {
		return errors.New(usage)
	}
	if *maxFile < 1 || *maxFile > portability.MaxPayloadBytes || *maxStored < *maxFile || *maxEntries < 1 {
		return custody.ErrInput
	}
	selection, err := secure.ReadSecret(*request, 8192)
	if err != nil {
		return err
	}
	var restore struct {
		ArchiveSHA256 string `json:"archive_sha256"`
		RevisionID    string `json:"source_revision_id"`
		Path          string `json:"destination_path"`
	}
	err = workflow.Decode(selection.Bytes, &restore)
	selection.Close()
	if err != nil {
		return portability.ErrBundle
	}
	archive, size, err := openBundleFile(*input)
	if err != nil {
		return err
	}
	defer archive.Close()
	member, err := portability.VerifySelectedFile(archive, size, restore.ArchiveSHA256, restore.RevisionID)
	if err != nil {
		return err
	}
	secret, err := secure.ReadSecret(*token, 64)
	if err != nil {
		return err
	}
	scope := store.Scope{Tenant: *tenant, Partner: *partner, TokenHash: secure.Digest(secret.Bytes)}
	secret.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	db, err := store.Open(ctx, *dsn)
	if err != nil {
		return err
	}
	defer db.Pool.Close()
	disk, err := custody.Open(*storage)
	if err != nil {
		return err
	}
	defer disk.Close()
	service := custody.Service{DB: db, Disk: disk, MaxFile: *maxFile, MaxStored: *maxStored, NamespaceMaxEntries: *maxEntries}
	file, replayed, err := service.RestorePortableFile(ctx, scope, *key, restore.Path, member)
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(struct {
		File       *store.File                `json:"file"`
		Source     portability.RecoverySource `json:"source"`
		Acceptance string                     `json:"acceptance"`
		Replayed   bool                       `json:"replayed"`
	}{File: file, Source: member.Source(), Acceptance: custody.Acceptance(file), Replayed: replayed})
}
