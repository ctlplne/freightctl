//go:build integration

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/freightctl/internal/calendar"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func qualifyPortableScheduleDraft(t *testing.T, ctx context.Context, service *custody.Service, scope store.Scope, cfg store.Configuration, command func(string, ...string) ([]byte, error), requestFile func(any) string) {
	t.Helper()
	const directory = "/schedule-export-source"
	if _, err := service.PathCommand(ctx, scope, "portable-schedule-directory", store.PathCommand{Operation: "mkdir", Path: directory}); err != nil {
		t.Fatal(err)
	}
	identity, err := service.DB.Identity(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now().UTC().Truncate(time.Second).Add(time.Hour)
	selection := workflow.ScheduleSelection{
		Name: "Portable approved clock", Workflow: workflow.Reference{ID: cfg.ID, Version: cfg.Version, Hash: cfg.Hash},
		Source: workflow.ScheduleSourceSelection{Directory: directory, Pattern: "*.csv", Kind: workflow.ProcessingScheduleSource},
		Calendar: calendar.Selection{
			Zone: "America/New_York", Start: start, End: start.AddDate(1, 0, 5),
			Times: []string{"02:30:00"}, Weekdays: []int{0, 1, 2, 3, 4, 5, 6}, Gap: "skip", Fold: "first",
		},
		Missed: "skip", CatchUp: 1, MaxActive: 1, MaxFiles: 2, Deadline: 900, Grace: 60, ExpectedAuthority: identity.AuthorityRevision,
	}
	preview := func(input workflow.ScheduleSelection) workflow.SchedulePreview {
		t.Helper()
		var view workflow.SchedulePreview
		raw, err := command("workflow-schedule-preview", "--request-file", requestFile(input))
		if err != nil || json.Unmarshal(raw, &view) != nil || !view.ApprovalRequired || view.ExternalContact {
			t.Fatal("ordinary schedule preview failed", err)
		}
		return view
	}
	draft := func(input workflow.ScheduleSelection, hash, key string) store.ScheduleSummary {
		t.Helper()
		var receipt workflow.Result
		var stage workflow.ScheduleResource
		raw, err := command("workflow-schedule-draft", "--request-file", requestFile(workflow.ScheduleDraftRequest{Selection: input, Hash: hash}), "--idempotency-key", key)
		if err != nil || json.Unmarshal(raw, &receipt) != nil || json.Unmarshal(receipt.Resource, &stage) != nil || stage.Schedule.State != "draft" {
			t.Fatal("ordinary schedule draft failed", err)
		}
		return stage.Schedule
	}
	before := preview(selection)
	if len(before.Definition.Calendar.Rules) < 2 {
		t.Fatal("fixture did not cover a civil clock transition")
	}
	original := draft(selection, before.Hash, "portable-schedule-original")
	raw, err := command("workflow-schedule-activate", "--schedule-id", original.ID, "--version", strconv.Itoa(original.Version),
		"--request-file", requestFile(workflow.Decision{Hash: original.Hash, Revision: original.Revision}), "--idempotency-key", "portable-schedule-activate")
	var control workflow.Result
	var active workflow.ScheduleResource
	if err != nil || json.Unmarshal(raw, &control) != nil || json.Unmarshal(control.Resource, &active) != nil || active.Schedule.State != "active" {
		t.Fatal("fixture activation failed", err)
	}
	path := filepath.Join(t.TempDir(), "portable-calendar.json")
	raw, err = command("workflow-schedule-export", "--schedule-id", original.ID, "--version", strconv.Itoa(original.Version), "--definition-hash", original.Hash, "--output", path)
	var receipt workflow.PortableExportReceipt
	if err != nil || json.Unmarshal(raw, &receipt) != nil || receipt.Source != (workflow.Reference{ID: original.ID, Version: original.Version, Hash: original.Hash}) {
		t.Fatal("calendar export did not bind the exact selected revision", err)
	}
	requireSealedCLIOutput(t, path)
	data, err := os.ReadFile(path)
	var artifact workflow.PortableSchedule
	if err != nil || secure.Digest(data) != receipt.SHA256 || len(data) != receipt.Size || json.Unmarshal(data, &artifact) != nil ||
		artifact.Source != receipt.Source || artifact.ObservedState != "active" || artifact.Profile != workflow.PortableScheduleProfile ||
		artifact.Selection.ExpectedAuthority != 0 || !reflect.DeepEqual(artifact.FrozenCalendar, before.Definition.Calendar) {
		t.Fatal("archive did not retain the frozen source timing or discard destination activation authority", err)
	}
	if raw, err := command("workflow-schedule-preview", "--request-file", requestFile(artifact.Selection)); !errors.Is(err, workflow.ErrInput) || len(raw) != 0 {
		t.Fatal("archive supplied live authority", err)
	}
	artifact.Selection.ExpectedAuthority = identity.AuthorityRevision
	after := preview(artifact.Selection)
	if !reflect.DeepEqual(after.Definition.Calendar, artifact.FrozenCalendar) || after.Hash != before.Hash {
		t.Fatal("ordinary re-preview changed the calendar in the same workspace")
	}
	recreated := draft(artifact.Selection, after.Hash, "portable-schedule-recreated")
	if recreated.ID == original.ID || recreated.Hash != original.Hash || recreated.ApprovalAuthority != 0 || recreated.NextDue != nil {
		t.Fatal("archive carried approval or an active occurrence into the new draft")
	}
	mismatch := filepath.Join(t.TempDir(), "mismatch.json")
	if raw, err := command("workflow-schedule-export", "--schedule-id", original.ID, "--version", strconv.Itoa(original.Version), "--definition-hash", strings.Repeat("0", 64), "--output", mismatch); !errors.Is(err, store.ErrRevision) || len(raw) != 0 {
		t.Fatal("wrong source definition digest obtained export", err)
	}
	if _, err := os.Stat(mismatch); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("refused calendar has an output artifact", err)
	}
	t.Logf("schedule export SHA-256 %s, definition SHA-256 %s, %d frozen clock rules", receipt.SHA256, original.Hash, len(artifact.FrozenCalendar.Rules))
}
