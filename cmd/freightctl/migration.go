package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/migration"
)

const sftpgoMigrationUsage = "freightctl migration-plan-sftpgo --source-file <protected SFTPGo Community format-17 JSON dump>"

func migrationPlanSFTPGo(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("migration-plan-sftpgo", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("source-file", "", "protected SFTPGo Community JSON dump")
	if err := flags.Parse(args); errors.Is(err, flag.ErrHelp) {
		_, err := io.WriteString(output, sftpgoMigrationUsage+"\n")
		return err
	} else if err != nil || flags.NArg() != 0 || *path == "" {
		return errors.New(sftpgoMigrationUsage)
	}
	input, err := secure.ReadSecret(*path, migration.MaxSFTPGoDumpBytes)
	if err != nil {
		return err
	}
	plan, err := migration.PlanSFTPGo(input.Bytes)
	input.Close()
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	return encoder.Encode(plan)
}
