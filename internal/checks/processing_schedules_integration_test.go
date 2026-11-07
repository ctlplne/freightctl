//go:build integration

package checks

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/freightctl/internal/calendar"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func processingCalendarFixture(t *testing.T, deadline int) (*fixture, *Service, *workflow.Service, store.Scope, store.ScheduleSummary, time.Time, string) {
	t.Helper()
	f := setup(t)
	s := &Service{Custody: f.wf.Custody}
	wf := &workflow.Service{Custody: s.Custody, Processor: s}
	registered, err := s.Register(f.ctx, f.scope, "calendar-input-policy", PolicyRequest{Definition: testPolicy(t)})
	if err != nil {
		t.Fatal(err)
	}
	var input store.Configuration
	if json.Unmarshal(registered.Resource, &input) != nil {
		t.Fatal("input policy")
	}
	mode := uint32(0777)
	if _, err = s.Custody.PathCommand(f.ctx, f.scope, "calendar-input-directory", store.PathCommand{Operation: "mkdir", Path: "/incoming", Mode: &mode}); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(t.TempDir(), "processor-token")
	if err := secure.WriteToken(tokenPath); err != nil {
		t.Fatal(err)
	}
	token, err := secure.ReadSecret(tokenPath, 64)
	if err != nil {
		t.Fatal(err)
	}
	tokenHash := secure.Digest(token.Bytes)
	token.Close()
	account := store.AccountCommand{Operation: "create", ID: secure.NewID(), CredentialHash: tokenHash, Policy: &store.AccountPolicy{Label: "Calendar processor without delivery", Root: "/", Permissions: []string{"list", "read", "write", "check_run", "check_release", "workflow_manage", "workflow_approve", "workflow_execute"}}}
	if _, err = s.Custody.DB.ChangeAccount(f.ctx, f.scope, "calendar-processor", account); err != nil {
		t.Fatal(err)
	}
	actor := store.Scope{Tenant: f.scope.Tenant, Partner: f.scope.Partner, TokenHash: account.CredentialHash}
	file, _, err := s.Custody.AcceptAt(f.ctx, actor, "calendar-source", int64(len(goodCSV)), secure.Digest([]byte(goodCSV)), strings.NewReader(goodCSV), custody.UploadTarget{Path: "/incoming/settlement.csv"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Run(f.ctx, actor, file.ID, "calendar-source-check"); err != nil {
		t.Fatal(err)
	}
	tx, err := s.Custody.DB.Begin(f.ctx, actor)
	if err != nil {
		t.Fatal(err)
	}
	if tx.Has("deliver") {
		tx.Tx.Rollback(f.ctx)
		t.Fatal("fixture has delivery permission")
	}
	check, err := tx.FileCheck(f.ctx, file.ID, false)
	tx.Tx.Rollback(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Release(f.ctx, actor, file.ID, "calendar-source-release", releaseDecision(check)); err != nil {
		t.Fatal(err)
	}
	_, output := registerOutputFixture(t, f, s, account, input)
	rules, err := NormalizeRecordProjection(testPolicy(t), RecordProjection{Schema: 1, Kind: "record_projection", SourcePolicyHash: input.Hash, OutputKind: "json_records", Columns: []ProjectionColumn{{Source: "account", Target: "account"}, {Source: "amount", Target: "total"}, {Source: "day", Target: "day"}}})
	if err != nil {
		t.Fatal(err)
	}
	definition := workflow.Definition{Schema: 3, Name: "Approved calendar processing", Processing: &workflow.ProcessingTask{ID: "project", Kind: "records.project", Definition: rules, OutputPolicy: workflow.Reference{ID: output.Policy.ID, Version: output.Policy.Version, Hash: output.Policy.Hash}, Reason: "Create held records without delivery permission"}}
	draft, err := wf.Draft(f.ctx, actor, "calendar-task-draft", workflow.DraftRequest{Definition: definition})
	if err != nil {
		t.Fatal(err)
	}
	var cfg store.Configuration
	if json.Unmarshal(draft.Resource, &cfg) != nil {
		t.Fatal("task draft")
	}
	if _, err = wf.Decide(f.ctx, actor, cfg.ID, cfg.Version, "calendar-task-approval", "approve", workflow.Decision{Hash: cfg.Hash, Revision: cfg.Revision}); err != nil {
		t.Fatal(err)
	}
	due := time.Now().UTC().Truncate(time.Second).Add(3 * time.Second)
	selection := workflow.ScheduleSelection{Name: "Owned released record calendar", Workflow: workflow.Reference{ID: cfg.ID, Version: cfg.Version, Hash: cfg.Hash}, Source: workflow.ScheduleSourceSelection{Kind: workflow.ProcessingScheduleSource, Directory: "/incoming", Pattern: "*.csv"}, Calendar: calendar.Selection{Zone: "UTC", Start: due, End: due.Add(30 * time.Second), Times: []string{due.Format("15:04:05"), due.Add(4 * time.Second).Format("15:04:05")}, Weekdays: []int{0, 1, 2, 3, 4, 5, 6}, Holidays: []string{}, Gap: "skip", Fold: "both"}, Missed: "all", CatchUp: 2, MaxActive: 2, MaxFiles: 2, Deadline: deadline, Grace: 1, ExpectedAuthority: 1}
	preview, err := wf.PreviewSchedule(f.ctx, actor, selection)
	if err != nil || preview.Definition.Schema != 2 || preview.Definition.Processing == nil || len(preview.Effects) != 0 || preview.ExternalContact {
		t.Fatal("processing schedule acquired delivery effects", err)
	}
	created, err := wf.DraftSchedule(f.ctx, actor, "calendar-draft", workflow.ScheduleDraftRequest{Selection: selection, Hash: preview.Hash})
	if err != nil {
		t.Fatal(err)
	}
	var record workflow.ScheduleResource
	if json.Unmarshal(created.Resource, &record) != nil || record.Profile != "owned-record-processing-schedule-v1" {
		t.Fatal("typed schedule receipt")
	}
	activated, err := wf.ControlSchedule(f.ctx, actor, record.Schedule.ID, record.Schedule.Version, "activate", "calendar-activate", workflow.Decision{Hash: record.Schedule.Hash, Revision: record.Schedule.Revision})
	if err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(activated.Resource, &record) != nil || record.Schedule.State != "active" {
		t.Fatal("active schedule")
	}
	return f, s, wf, actor, record.Schedule, due, tokenPath
}

func waitProcessingCalendar(t *testing.T, f *fixture, at time.Time) {
	t.Helper()
	until := time.Now().Add(12 * time.Second)
	for {
		var ready bool
		if err := f.admin.QueryRow(f.ctx, `SELECT clock_timestamp()>=$1`, at).Scan(&ready); err != nil {
			t.Fatal(err)
		}
		if ready {
			return
		}
		if time.Now().After(until) {
			t.Fatal("database clock wait expired")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestProcessingScheduleActualNoDeliveryGrantAtomicClaimReplayAndSeparateHeldOutput(t *testing.T) {
	f, s, wf, actor, record, due, _ := processingCalendarFixture(t, 30)
	current, err := wf.ScheduleStatus(f.ctx, actor, record.ID, record.Version)
	if err != nil {
		t.Fatal(err)
	}
	var legacy workflow.ScheduleDefinition
	if json.Unmarshal(current.Schedule.Definition, &legacy) != nil {
		t.Fatal("typed calendar")
	}
	legacy.Schema, legacy.Processing, legacy.Source.Kind = 1, nil, ""
	raw, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := s.Custody.DB.Begin(f.ctx, actor)
	if err != nil {
		t.Fatal(err)
	}
	now, err := tx.DatabaseTime(f.ctx)
	if err != nil {
		tx.Tx.Rollback(f.ctx)
		t.Fatal(err)
	}
	forged := &store.Schedule{ScheduleSummary: store.ScheduleSummary{ID: secure.NewID(), Version: 1, Name: legacy.Name, Hash: secure.Digest(raw), State: "draft", Revision: 1, CreatedAt: now}, Definition: raw}
	err = tx.SaveSchedule(f.ctx, forged, 0)
	tx.Tx.Rollback(f.ctx)
	if err == nil {
		t.Fatal("legacy empty effects acquired processing calendar authority")
	}
	waitProcessingCalendar(t, f, due)
	first, err := wf.TickSchedule(f.ctx, actor, record.ID, record.Version, "calendar-first-tick", workflow.ScheduleTickRequest{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	var tick workflow.ScheduleTickResult
	if json.Unmarshal(first.Resource, &tick) != nil || len(tick.RunIDs) != 1 || len(tick.Occurrences) != 1 || tick.Occurrences[0].InputCount != 1 || tick.Profile != "owned-record-processing-schedule-v1" {
		t.Fatal("calendar did not bind one processing input")
	}
	replay, err := wf.TickSchedule(f.ctx, actor, record.ID, record.Version, "calendar-first-tick", workflow.ScheduleTickRequest{Limit: 1})
	if err != nil || !bytes.Equal(first.Resource, replay.Resource) {
		t.Fatal("tick replay changed original claim", err)
	}
	worked, err := wf.Work(f.ctx, actor, tick.RunIDs[0], "calendar-work-attempt1")
	if err != nil || worked.Processing == nil || worked.Processing.State != "completed" || worked.Status.ObservedReason != "output_held" || worked.Status.Processing.Released {
		t.Fatal("scheduled processing did not leave separate held output", err)
	}
	if _, _, err = s.Custody.Download(f.ctx, actor, worked.Processing.FileID); !errors.Is(err, store.ErrState) {
		t.Fatal("calendar granted output release", err)
	}
	var deliveries, inputs, intents int
	if err = f.admin.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM delivery_intents WHERE tenant_id=$1 AND partner_id=$2),(SELECT count(*) FROM workflow_schedule_inputs WHERE tenant_id=$1 AND partner_id=$2),(SELECT count(*) FROM workflow_processing WHERE tenant_id=$1 AND partner_id=$2)`, actor.Tenant, actor.Partner).Scan(&deliveries, &inputs, &intents); err != nil || deliveries != 0 || inputs != 1 || intents != 1 {
		t.Fatal("calendar split claim or created a delivery", err)
	}
	waitProcessingCalendar(t, f, due.Add(4*time.Second))
	next, err := wf.TickSchedule(f.ctx, actor, record.ID, record.Version, "calendar-next-tick", workflow.ScheduleTickRequest{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(next.Resource, &tick) != nil || len(tick.RunIDs) != 0 || len(tick.Occurrences) != 1 || tick.Occurrences[0].Kind != "empty" {
		t.Fatal("unchanged input was processed twice")
	}
}

func TestProcessingScheduleActualSuspensionAndDeadlineFenceQueuedProcessing(t *testing.T) {
	for _, suspend := range []bool{true, false} {
		t.Run(map[bool]string{true: "suspend", false: "deadline"}[suspend], func(t *testing.T) {
			f, _, wf, actor, record, due, _ := processingCalendarFixture(t, 2)
			waitProcessingCalendar(t, f, due)
			queued, err := wf.TickSchedule(f.ctx, actor, record.ID, record.Version, "calendar-fenced-tick", workflow.ScheduleTickRequest{Limit: 1})
			if err != nil {
				t.Fatal(err)
			}
			var tick workflow.ScheduleTickResult
			if json.Unmarshal(queued.Resource, &tick) != nil || len(tick.RunIDs) != 1 {
				t.Fatal("queued processing")
			}
			if suspend {
				view, err := wf.ScheduleStatus(f.ctx, actor, record.ID, record.Version)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = wf.ControlSchedule(f.ctx, actor, record.ID, record.Version, "suspend", "calendar-suspend", workflow.Decision{Hash: record.Hash, Revision: view.Schedule.Revision}); err != nil {
					t.Fatal(err)
				}
			} else {
				waitProcessingCalendar(t, f, due.Add(2*time.Second))
			}
			if _, err = wf.Work(f.ctx, actor, tick.RunIDs[0], "calendar-fenced-work"); err == nil {
				t.Fatal("stale schedule permitted processing")
			}
			var completed int
			if err = f.admin.QueryRow(f.ctx, `SELECT count(*) FROM record_projections WHERE tenant_id=$1 AND partner_id=$2 AND new_file_id IS NOT NULL`, actor.Tenant, actor.Partner).Scan(&completed); err != nil || completed != 0 {
				t.Fatal("fenced work accepted new bytes", err)
			}
		})
	}
}

func TestProcessingScheduleNativeCLIWorkerUsesOrdinaryIntentAndWaitsForSeparateRelease(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "true" || runtime.GOOS != "linux" {
		t.Fatal("actual native CLI worker profile requires GitHub Linux")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	private := t.TempDir()
	binary := filepath.Join(private, "freightctl")
	buildLog, err := os.OpenFile(filepath.Join(private, "build.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	build := exec.CommandContext(t.Context(), "sh", "scripts/go.sh", "build", "-trimpath", "-buildvcs=false", "-o", binary, "./cmd/freightctl")
	build.Dir, build.Stdout, build.Stderr = root, buildLog, buildLog
	buildErr := build.Run()
	buildLog.Close()
	if buildErr != nil {
		t.Fatal("native CLI build failed;private log retained")
	}
	f, _, wf, actor, record, due, token := processingCalendarFixture(t, 60)
	waitProcessingCalendar(t, f, due)
	queued, err := wf.TickSchedule(f.ctx, actor, record.ID, record.Version, "native-calendar-cli-tick", workflow.ScheduleTickRequest{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	var tick workflow.ScheduleTickResult
	if json.Unmarshal(queued.Resource, &tick) != nil || len(tick.RunIDs) != 1 {
		t.Fatal("native CLI queued input")
	}
	for i := 0; i < 2; i++ {
		logPath := filepath.Join(private, "worker-"+string(rune('a'+i))+".log")
		log, err := os.OpenFile(logPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		command := exec.CommandContext(f.ctx, binary, "workflow-schedule-worker", "-dsn-file", f.runtimePath, "-token-file", token, "-tenant", actor.Tenant, "-partner", actor.Partner, "-storage", f.diskPath, "-schedule-id", record.ID, "-version", "1", "-execute", "-max-polls", "1", "-schedule-poll", "1s", "-max-file-bytes", "8388608", "-max-stored-bytes", "67108864")
		command.Stdout, command.Stderr = log, log
		err = command.Run()
		log.Close()
		if err != nil {
			t.Fatal("native calendar CLI worker failed;private log retained")
		}
		raw, err := os.ReadFile(logPath)
		if err != nil || len(raw) > 16384 {
			t.Fatal("native CLI has no bounded outcome", err)
		}
		if i == 0 && !bytes.Contains(raw, []byte(`"state":"worked"`)) {
			t.Fatal("native CLI did not execute ordinary task")
		}
		if i == 1 && !bytes.Contains(raw, []byte(`"reason":"processing_output_awaiting_checks_and_release"`)) {
			t.Fatal("native CLI did not wait for separate release")
		}
	}
	view, err := wf.Status(f.ctx, actor, tick.RunIDs[0])
	if err != nil || view.Processing == nil || view.Processing.State != "completed" || view.Processing.Attempts != 1 || view.Processing.Released || view.ObservedReason != "output_held" {
		t.Fatal("CLI replay changed held intent outcome", err)
	}
	var deliveries int
	if err = f.admin.QueryRow(f.ctx, `SELECT count(*) FROM delivery_intents WHERE tenant_id=$1 AND partner_id=$2`, actor.Tenant, actor.Partner).Scan(&deliveries); err != nil || deliveries != 0 {
		t.Fatal("native CLI acquired delivery effect", err)
	}
}
