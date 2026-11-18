package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/portability"
	"github.com/ctlplne/freightctl/internal/protectedfs"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func portableFilesExport(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("bundle-export", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	tenant := flags.String("tenant", "", "source tenant UUID")
	partner := flags.String("partner", "", "source partner UUID")
	token := flags.String("token-file", ".private/partner.token", "protected token")
	dsn := flags.String("dsn-file", ".private/pg-runtime.dsn", "protected runtime database reference")
	storage := flags.String("storage", ".private/custody", "existing private custody root")
	request := flags.String("request-file", "", "protected file revision selection")
	path := flags.String("output", "", "new archive file in a private directory")
	const usage = "freightctl bundle-export --tenant <uuid> --partner <uuid> --request-file <selection> --output <new tar> [--token-file <token>] [--dsn-file <dsn>] [--storage <custody root>]"
	if err := flags.Parse(args); errors.Is(err, flag.ErrHelp) {
		_, err = io.WriteString(output, usage+"\n")
		return err
	} else if err != nil || flags.NArg() != 0 || *request == "" || *path == "" || !store.ValidID(*tenant) || !store.ValidID(*partner) {
		return errors.New(usage)
	}
	if _, err := os.Lstat(*path); !errors.Is(err, os.ErrNotExist) {
		return errors.New("bundle output must be a new file")
	}
	input, err := secure.ReadSecret(*request, 8192)
	if err != nil {
		return err
	}
	var selection struct {
		FileIDs []string `json:"file_ids"`
	}
	err = workflow.Decode(input.Bytes, &selection)
	input.Close()
	if err != nil {
		return portability.ErrBundle
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
	disk, err := custody.OpenExisting(*storage)
	if err != nil {
		return err
	}
	defer disk.Close()
	root, err := os.OpenRoot(filepath.Dir(*path))
	if err != nil {
		return err
	}
	defer root.Close()
	var report *portability.Report
	service := custody.Service{DB: db, Disk: disk}
	stage, err := stageProtectedOutputAt(ctx, root, ".freightctl-bundle-", "bundle", func(writer io.Writer) error {
		var err error
		report, err = service.PreparePortableFiles(ctx, scope, selection.FileIDs, writer)
		return err
	})
	if err != nil {
		return err
	}
	if err = stage.publish(*path); err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(report)
}

func portableFilesVerify(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("bundle-verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("input", "", "protected archive")
	const usage = "freightctl bundle-verify --input <protected tar>"
	if err := flags.Parse(args); errors.Is(err, flag.ErrHelp) {
		_, err = io.WriteString(output, usage+"\n")
		return err
	} else if err != nil || flags.NArg() != 0 || *path == "" {
		return errors.New(usage)
	}
	file, _, err := openBundleFile(*path)
	if err != nil {
		return err
	}
	defer file.Close()
	report, err := portability.VerifyFiles(file)
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(report)
}

func openBundleFile(path string) (*os.File, int64, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > portability.MaxArchiveBytes {
		return nil, 0, portability.ErrBundle
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, 0, portability.ErrBundle
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() || opened.Size() > portability.MaxArchiveBytes ||
		protectedfs.ValidateFile(file) != nil {
		file.Close()
		return nil, 0, portability.ErrBundle
	}
	return file, opened.Size(), nil
}
