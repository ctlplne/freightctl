//go:build integration

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/ctlplne/freightctl/internal/calendar"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func qualifyPreparedSFTPGoCalendarPreview(t *testing.T, ctx context.Context, service *custody.Service, scope store.Scope, configuration store.Configuration, command func(string, ...string) ([]byte, error), requestFile func(any) string) {
	t.Helper()
	const dir = "/migration-preview"
	if _, err := service.PathCommand(ctx, scope, "cli-migration-preview-directory", store.PathCommand{Operation: "mkdir", Path: dir}); err != nil {
		t.Fatal("create ordinary review directory", err)
	}
	identity, err := service.DB.Identity(ctx, scope)
	if err != nil {
		t.Fatal("read live authority", err)
	}
	dump := json.RawMessage(`{"version":17,"event_actions":[{"name":"backup","type":4}],"event_rules":[
	  {"status":0,"trigger":3,"conditions":{"schedules":[{"hour":"07","day_of_week":"2","day_of_month":"*","month":"*"}]},
	   "actions":[{"name":"backup","order":1}]}]}`)
	sourcePath := requestFile(dump)
	sourceBytes, err := secure.ReadSecret(sourcePath, 8192)
	if err != nil {
		t.Fatal(err)
	}
	digest := secure.Digest(sourceBytes.Bytes)
	sourceBytes.Close()
	review, err := command("workflow-schedule-list")
	if err != nil {
		t.Fatal("schedule list before preview", err)
	}
	start := time.Now().UTC().Truncate(time.Second).Add(time.Hour)
	mapping := sftpgoCalendarRequest{
		SourceSHA256: digest, SourceSchedule: "/event_rules/0/conditions/schedules/0",
		Selection: workflow.ScheduleSelection{
			Name: "Reviewed imported schedule", Workflow: workflow.Reference{ID: configuration.ID, Version: configuration.Version, Hash: configuration.Hash},
			Source:            workflow.ScheduleSourceSelection{Directory: dir, Pattern: "*.csv", Kind: workflow.ProcessingScheduleSource},
			Calendar:          calendar.Selection{Start: start, End: start.Add(8 * 24 * time.Hour), Gap: "skip", Fold: "first"},
			ExpectedAuthority: identity.AuthorityRevision, Missed: "skip", CatchUp: 1, MaxActive: 1, MaxFiles: 2, Deadline: 900, Grace: 60,
		},
	}
	prepare := func(request sftpgoCalendarRequest) string {
		t.Helper()
		var encoded bytes.Buffer
		if err := migrationPrepareSFTPGoCalendar([]string{"--source-file", sourcePath, "--request-file", requestFile(request)}, &encoded); err != nil {
			t.Fatal("prepare ordinary schedule input", err)
		}
		var prepared preparedSFTPGoCalendar
		if json.Unmarshal(encoded.Bytes(), &prepared) != nil || prepared.SourceSHA256 != digest || prepared.SourceRuleState != "disabled" {
			t.Fatal("offline source binding disappeared")
		}
		return requestFile(prepared.Selection)
	}
	input := prepare(mapping)
	stale := mapping
	stale.Selection.ExpectedAuthority++
	if raw, err := command("workflow-schedule-preview", "--request-file", prepare(stale)); !errors.Is(err, store.ErrRevision) || len(raw) != 0 {
		t.Fatal("ordinary preview accepted a stale destination authority", err)
	}
	raw, err := command("workflow-schedule-preview", "--request-file", input)
	var result workflow.SchedulePreview
	if err != nil || json.Unmarshal(raw, &result) != nil || result.Hash == "" || !result.ApprovalRequired ||
		result.ExternalContact || len(result.Effects) != 0 || result.Definition.Processing == nil ||
		result.Definition.StorageID != service.Disk.Identity() || result.Definition.Workflow != mapping.Selection.Workflow ||
		result.Definition.Source.Directory != dir || len(result.Upcoming) == 0 {
		t.Fatal("ordinary PostgreSQL preview lost workflow, custody or review boundaries", err)
	}
	for _, occurrence := range result.Upcoming {
		if occurrence.At.UTC().Weekday() != time.Tuesday || occurrence.At.UTC().Format("15:04:05") != "07:00:00" {
			t.Fatal("preview changed the imported UTC calendar")
		}
	}
	token := filepath.Join(t.TempDir(), "migration-preview-reader.token")
	if err := secure.WriteToken(token); err != nil {
		t.Fatal(err)
	}
	credential, err := secure.ReadSecret(token, 64)
	if err != nil {
		t.Fatal(err)
	}
	credentialHash := secure.Digest(credential.Bytes)
	credential.Close()
	account := store.AccountCommand{Operation: "create", ID: secure.NewID(), CredentialHash: credentialHash, Policy: &store.AccountPolicy{
		Label: "Migration preview ordinary reader", Root: "/", Permissions: []string{"list", "read"},
	}}
	if _, err := service.DB.ChangeAccount(ctx, scope, "cli-migration-limited-preview-reader", account); err != nil {
		t.Fatal("create exact limited reader", err)
	}
	if raw, err := command("workflow-schedule-preview", "--token-file", token, "--request-file", input); !errors.Is(err, store.ErrForbidden) || len(raw) != 0 {
		t.Fatal("offline preparation gave the ordinary reader workflow access", err)
	}
	after, err := command("workflow-schedule-list")
	if err != nil || !bytes.Equal(after, review) {
		t.Fatal("preview changed stored schedule state", err)
	}
}
