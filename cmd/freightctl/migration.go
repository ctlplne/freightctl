package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/migration"
	"github.com/ctlplne/freightctl/internal/workflow"
)

const sftpgoMigrationUsage = "freightctl migration-plan-sftpgo --source-file <protected SFTPGo Community format-17 JSON dump>"
const sftpgoCalendarUsage = "freightctl migration-prepare-sftpgo-calendar --source-file <protected dump> --request-file <protected calendar mapping> [--occurrences-file <protected source record>]"

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
	plan, err := readSFTPGoPlan(*path)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	return encoder.Encode(plan)
}

func readSFTPGoPlan(path string) (migration.SFTPGoPlan, error) {
	input, err := secure.ReadSecret(path, migration.MaxSFTPGoDumpBytes)
	if err != nil {
		return migration.SFTPGoPlan{}, err
	}
	defer input.Close()
	return migration.PlanSFTPGo(input.Bytes)
}

type sftpgoCalendarRequest struct {
	SourceSHA256   string                     `json:"source_sha256"`
	SourceSchedule string                     `json:"source_schedule"`
	Selection      workflow.ScheduleSelection `json:"selection"`
}

type preparedSFTPGoCalendar struct {
	SourceSHA256    string                       `json:"source_sha256"`
	SourceSchedule  string                       `json:"source_schedule"`
	SourceRuleState string                       `json:"source_rule_state"`
	RuleDisposition string                       `json:"source_rule_disposition"`
	Selection       workflow.ScheduleSelection   `json:"selection"`
	Comparison      *migrationCalendarComparison `json:"comparison,omitempty"`
}

func migrationPrepareSFTPGoCalendar(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("migration-prepare-sftpgo-calendar", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	sourcePath := flags.String("source-file", "", "protected SFTPGo Community JSON dump")
	requestPath := flags.String("request-file", "", "protected calendar mapping")
	occurrencesPath := flags.String("occurrences-file", "", "protected source calendar occurrence record")
	if err := flags.Parse(args); errors.Is(err, flag.ErrHelp) {
		_, err := io.WriteString(output, sftpgoCalendarUsage+"\n")
		return err
	} else if err != nil || flags.NArg() != 0 || *sourcePath == "" || *requestPath == "" {
		return errors.New(sftpgoCalendarUsage)
	}
	input, err := secure.ReadSecret(*requestPath, 32<<10)
	if err != nil {
		return err
	}
	var request sftpgoCalendarRequest
	err = workflow.Decode(input.Bytes, &request)
	input.Close()
	if err != nil {
		return err
	}
	plan, err := readSFTPGoPlan(*sourcePath)
	if err != nil {
		return err
	}
	prepared, err := prepareSFTPGoCalendar(plan, request)
	if err != nil {
		return err
	}
	if *occurrencesPath != "" {
		prepared.Comparison, err = compareProtectedCalendarOccurrences(prepared, *occurrencesPath)
		if err != nil {
			return err
		}
	}
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	return encoder.Encode(prepared)
}

func prepareSFTPGoCalendar(plan migration.SFTPGoPlan, request sftpgoCalendarRequest) (preparedSFTPGoCalendar, error) {
	if plan.SourceSHA256 != request.SourceSHA256 {
		return preparedSFTPGoCalendar{}, errors.New("SFTPGo export differs from the selected source digest")
	}
	selected := request.Selection.Calendar
	if selected.Zone != "" || len(selected.Times) != 0 || len(selected.Weekdays) != 0 || len(selected.Holidays) != 0 {
		return preparedSFTPGoCalendar{}, errors.New("calendar mapping must leave the source time zone, times, weekdays and holidays empty")
	}
	for _, rule := range plan.Rules {
		for _, schedule := range rule.Schedules {
			if schedule.Source != request.SourceSchedule {
				continue
			}
			if schedule.Calendar == nil || rule.Disposition == "blocked" {
				return preparedSFTPGoCalendar{}, errors.New("source schedule needs a supported calendar and resolved action references")
			}
			selected.Zone = schedule.Calendar.Zone
			selected.Times = schedule.Calendar.Times
			selected.Weekdays = schedule.Calendar.Weekdays
			request.Selection.Calendar = selected
			selection, err := workflow.NormalizeScheduleSelection(request.Selection)
			if err != nil {
				return preparedSFTPGoCalendar{}, err
			}
			return preparedSFTPGoCalendar{
				SourceSHA256: plan.SourceSHA256, SourceSchedule: schedule.Source,
				SourceRuleState: rule.SourceState, RuleDisposition: rule.Disposition, Selection: selection,
			}, nil
		}
	}
	return preparedSFTPGoCalendar{}, errors.New("SFTPGo schedule was absent from the selected export")
}
