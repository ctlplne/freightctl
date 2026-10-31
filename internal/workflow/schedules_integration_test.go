//go:build integration

package workflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ctlplne/freightctl/internal/calendar"
	"github.com/ctlplne/freightctl/internal/delivery"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/jackc/pgx/v5/pgconn"
)

func scheduleFixture(t *testing.T, deadline int, policy string, publish bool) (*fixture, ScheduleSelection, time.Time) {
	t.Helper()
	f := setup(t)
	f.s.Custody.NamespaceMaxEntries = 1000
	if _, e := f.s.Custody.PathCommand(f.ctx, f.scope, "source-dir", store.PathCommand{Operation: "mkdir", Path: "/incoming"}); e != nil {
		t.Fatal(e)
	}
	if publish {
		if _, e := f.s.Custody.PathCommand(f.ctx, f.scope, "publish-source", store.PathCommand{Operation: "publish", Path: "/incoming/settlement.csv", FileID: f.file.ID}); e != nil {
			t.Fatal(e)
		}
	}
	def := f.definition()
	def.Steps = def.Steps[:1]
	w := f.approved(t, def)
	due := time.Now().UTC().Truncate(time.Second).Add(2 * time.Second)
	return f, ScheduleSelection{Name: "Settlement calendar", Workflow: Reference{ID: w.ID, Version: w.Version, Hash: w.Hash}, Source: ScheduleSourceSelection{Directory: "/incoming", Pattern: "*.csv"}, Calendar: calendar.Selection{Zone: "UTC", Start: due, End: due.Add(time.Minute), Times: []string{due.Format("15:04:05"), due.Add(time.Second).Format("15:04:05")}, Weekdays: []int{0, 1, 2, 3, 4, 5, 6}, Holidays: []string{}, Gap: "skip", Fold: "both"}, Missed: policy, CatchUp: 4, MaxActive: 4, MaxFiles: 2, Deadline: deadline, Grace: 1, ExpectedAuthority: 1}, due
}
func saveSchedule(t *testing.T, f *fixture, x ScheduleSelection, id string, expected int, key string) store.ScheduleSummary {
	t.Helper()
	p, e := f.s.PreviewSchedule(f.ctx, f.scope, x)
	if e != nil {
		t.Fatal(e)
	}
	if p.ExternalContact || !p.ApprovalRequired || len(p.Effects) != 1 || len(p.Definition.Calendar.Rules) == 0 {
		t.Fatal("preview", p)
	}
	out, e := f.s.DraftSchedule(f.ctx, f.scope, key, ScheduleDraftRequest{ID: id, ExpectedVersion: expected, Selection: x, Hash: p.Hash})
	if e != nil {
		t.Fatal(e)
	}
	var r ScheduleResource
	if json.Unmarshal(out.Resource, &r) != nil || r.Kind != "workflow_schedule" {
		t.Fatal("draft receipt")
	}
	out, e = f.s.ControlSchedule(f.ctx, f.scope, r.Schedule.ID, r.Schedule.Version, "activate", key+"-activate", Decision{Hash: r.Schedule.Hash, Revision: r.Schedule.Revision})
	if e != nil {
		t.Fatal(e)
	}
	if json.Unmarshal(out.Resource, &r) != nil || r.Schedule.State != "active" {
		t.Fatal("activation")
	}
	return r.Schedule
}
func waitSchedule(t *testing.T, f *fixture, at time.Time) {
	t.Helper()
	until := time.Now().Add(10 * time.Second)
	for {
		var ready bool
		if e := f.admin.QueryRow(f.ctx, `SELECT clock_timestamp()>=$1`, at).Scan(&ready); e != nil {
			t.Fatal(e)
		}
		if ready {
			return
		}
		if time.Now().After(until) {
			t.Fatal("original database clock wait expired")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
func tickSchedule(t *testing.T, f *fixture, s store.ScheduleSummary, key string) (*Result, ScheduleTickResult) {
	t.Helper()
	r, e := f.s.TickSchedule(f.ctx, f.scope, s.ID, s.Version, key, ScheduleTickRequest{Limit: 1})
	if e != nil {
		t.Fatal(e)
	}
	var v ScheduleTickResult
	if json.Unmarshal(r.Resource, &v) != nil || v.Kind != "workflow_schedule_tick" || v.ExternalContact {
		t.Fatal("tick receipt")
	}
	return r, v
}
func TestScheduleAtomicOncePerRevisionAndOriginalNoopReceipt(t *testing.T) {
	f, x, due := scheduleFixture(t, 30, "all", true)
	s := saveSchedule(t, f, x, "", 0, "new-schedule")
	no, early := tickSchedule(t, f, s, "early-tick")
	if early.Reason != "not_due" || len(early.Occurrences) != 0 || no.Replayed {
		t.Fatal(early)
	}
	waitSchedule(t, f, due)
	old, e := f.s.TickSchedule(f.ctx, f.scope, s.ID, s.Version, "early-tick", ScheduleTickRequest{Limit: 1})
	if e != nil || !old.Replayed || !bytes.Equal(old.Resource, no.Resource) {
		t.Fatal("old noop receipt changed meaning", e)
	}
	first, v := tickSchedule(t, f, s, "due-tick")
	if len(v.RunIDs) != 1 || v.Occurrences[0].InputCount != 1 {
		t.Fatal(v)
	}
	same, e := f.s.TickSchedule(f.ctx, f.scope, s.ID, s.Version, "due-tick", ScheduleTickRequest{Limit: 1})
	if e != nil || !same.Replayed || !bytes.Equal(same.Resource, first.Resource) {
		t.Fatal("original queue receipt", e)
	}
	waitSchedule(t, f, due.Add(time.Second))
	_, second := tickSchedule(t, f, s, "next-occurrence")
	if len(second.RunIDs) != 0 || len(second.Occurrences) != 1 || second.Occurrences[0].Kind != "empty" {
		t.Fatal("repeated unchanged input", second)
	}
	view, e := f.s.ScheduleOccurrence(f.ctx, f.scope, v.Occurrences[0].ID)
	if e != nil || len(view.Inputs) != 1 || view.Inputs[0].FileID != f.file.ID || view.Inputs[0].RunID != v.RunIDs[0] {
		t.Fatal(view, e)
	}
	status, e := f.s.Status(f.ctx, f.scope, v.RunIDs[0])
	if e != nil || status.Steps[0].Attempts != 0 {
		t.Fatal(status, e)
	}
	var inputs, runs, occurrences int
	if e = f.admin.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM workflow_schedule_inputs),(SELECT count(*) FROM workflow_runs),(SELECT count(*) FROM workflow_schedule_occurrences)`).Scan(&inputs, &runs, &occurrences); e != nil || inputs != 1 || runs != 1 || occurrences != 2 {
		t.Fatal(inputs, runs, occurrences, e)
	}
}
func TestSchedulePublishedAfterDueWaitsForNextOccurrence(t *testing.T) {
	f, x, due := scheduleFixture(t, 30, "all", false)
	x.Calendar.Times[1] = due.Add(2 * time.Second).Format("15:04:05")
	s := saveSchedule(t, f, x, "", 0, "late-source-schedule")
	waitSchedule(t, f, due)
	_, first := tickSchedule(t, f, s, "before-publication")
	if len(first.RunIDs) != 0 || first.Occurrences[0].Kind != "empty" {
		t.Fatal(first)
	}
	old := time.Now().Add(-time.Hour)
	if _, e := f.s.Custody.PathCommand(f.ctx, f.scope, "late-publish", store.PathCommand{Operation: "publish", Path: "/incoming/late.csv", FileID: f.file.ID, Modified: &old}); e != nil {
		t.Fatal(e)
	}
	waitSchedule(t, f, due.Add(2*time.Second))
	_, second := tickSchedule(t, f, s, "after-publication")
	if len(second.RunIDs) != 1 {
		t.Fatal(second)
	}
}
func TestScheduleReceiptFailureRollsBackCursorOccurrenceClaimsAndRuns(t *testing.T) {
	f, x, due := scheduleFixture(t, 30, "all", true)
	s := saveSchedule(t, f, x, "", 0, "rollback-schedule")
	waitSchedule(t, f, due)
	_, e := f.admin.Exec(f.ctx, `CREATE FUNCTION freightctl_schedule_receipt_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.request_key='atomic-tick' THEN RAISE EXCEPTION 'injected exact schedule receipt failure';END IF;RETURN NEW;END $$;CREATE TRIGGER freightctl_schedule_receipt_failure BEFORE INSERT ON workflow_receipts FOR EACH ROW EXECUTE FUNCTION freightctl_schedule_receipt_failure()`)
	if e != nil {
		t.Fatal(e)
	}
	_, e = f.s.TickSchedule(f.ctx, f.scope, s.ID, s.Version, "atomic-tick", ScheduleTickRequest{Limit: 1})
	var pe *pgconn.PgError
	if !errors.As(e, &pe) || pe.Code != "P0001" {
		t.Fatal("expected exact receipt failure", e)
	}
	if _, e = f.admin.Exec(f.ctx, `DROP TRIGGER freightctl_schedule_receipt_failure ON workflow_receipts;DROP FUNCTION freightctl_schedule_receipt_failure()`); e != nil {
		t.Fatal(e)
	}
	var n int
	if e = f.admin.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM workflow_schedule_occurrences)+(SELECT count(*) FROM workflow_schedule_inputs)+(SELECT count(*) FROM workflow_runs)`).Scan(&n); e != nil || n != 0 {
		t.Fatal("partial scheduled acceptance", n, e)
	}
	status, e := f.s.ScheduleStatus(f.ctx, f.scope, s.ID, s.Version)
	if e != nil || status.Schedule.Revision != s.Revision || !status.Schedule.NextDue.Equal(*s.NextDue) {
		t.Fatal("cursor moved", status, e)
	}
	_, v := tickSchedule(t, f, s, "atomic-tick")
	if len(v.RunIDs) != 1 {
		t.Fatal(v)
	}
}
func TestScheduleConcurrentOriginalKeyCreatesOneClaimAndImmutableReceipt(t *testing.T) {
	f, x, due := scheduleFixture(t, 30, "all", true)
	s := saveSchedule(t, f, x, "", 0, "concurrent-schedule")
	waitSchedule(t, f, due)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	results := make(chan *Result, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, e := f.s.TickSchedule(f.ctx, f.scope, s.ID, s.Version, "same-tick", ScheduleTickRequest{Limit: 1})
			if e != nil {
				errs <- e
			} else {
				results <- r
			}
		}()
	}
	wg.Wait()
	close(errs)
	close(results)
	for e := range errs {
		t.Error(e)
	}
	var first []byte
	fresh := 0
	for r := range results {
		if !r.Replayed {
			fresh++
		}
		if first == nil {
			first = r.Resource
		} else if !bytes.Equal(first, r.Resource) {
			t.Fatal("different original-key results")
		}
	}
	if fresh != 1 {
		t.Fatal(fresh)
	}
	var n int
	if e := f.admin.QueryRow(f.ctx, `SELECT count(*) FROM workflow_schedule_inputs`).Scan(&n); e != nil || n != 1 {
		t.Fatal(n, e)
	}
}
func TestScheduleCommonSenderCutoffAndIndependentConsentRemainCumulative(t *testing.T) {
	f, x, due := scheduleFixture(t, 3, "all", true)
	if _, e := (&delivery.Service{Custody: f.s.Custody}).ChangeDispatchPolicy(f.ctx, f.scope, "outbound-policy", delivery.DispatchPolicyChange{Mode: "independent"}); e != nil {
		t.Fatal(e)
	}
	s := saveSchedule(t, f, x, "", 0, "cutoff-schedule")
	waitSchedule(t, f, due)
	_, v := tickSchedule(t, f, s, "cutoff-admission")
	runID := v.RunIDs[0]
	status, e := f.s.Status(f.ctx, f.scope, runID)
	if e != nil {
		t.Fatal(e)
	}
	sender := &delivery.Service{Custody: f.s.Custody}
	if _, e = sender.Work(f.ctx, f.scope, status.Steps[0].DeliveryID); !errors.Is(e, store.ErrDispatchApproval) {
		t.Fatal("schedule bypassed dispatch consent", e)
	}
	waitSchedule(t, f, due.Add(3*time.Second))
	if _, e = sender.Work(f.ctx, f.scope, status.Steps[0].DeliveryID); !errors.Is(e, store.ErrSchedule) {
		t.Fatal("deadline did not block direct sender", e)
	}
	check, e := f.s.Custody.DB.Begin(f.ctx, f.scope)
	if e != nil {
		t.Fatal(e)
	}
	defer check.Tx.Rollback(f.ctx)
	row, e := check.Delivery(f.ctx, status.Steps[0].DeliveryID, false)
	if e != nil {
		t.Fatal(e)
	}
	var spec delivery.Definition
	json.Unmarshal(row.Definition, &spec)
	if e = check.CheckExecutionBinding(f.ctx, spec.Binding); !errors.Is(e, store.ErrSchedule) {
		t.Fatal(e)
	}
	if e = check.CheckExecutionObservationBinding(f.ctx, spec.Binding); e != nil {
		t.Fatal("cutoff blocked read-only ordinary binding", e)
	}
	if row.Attempts != 0 {
		t.Fatal("attempt consumed", row)
	}
}
func TestSchedulePrivateHistoryAndExactDefinitionRevision(t *testing.T) {
	f, x, _ := scheduleFixture(t, 30, "all", true)
	s := saveSchedule(t, f, x, "", 0, "private-schedule")
	other, _ := approvalPeer(t, f, "Other schedule operator", []string{"workflow_manage", "workflow_approve", "workflow_execute", "list", "read", "deliver"})
	if _, e := f.s.ScheduleStatus(f.ctx, other, s.ID, s.Version); !errors.Is(e, store.ErrNotFound) {
		t.Fatal("private definition disclosed", e)
	}
	page, e := f.s.Schedules(f.ctx, other, "", 20)
	if e != nil || len(page.Schedules) != 0 {
		t.Fatal(page, e)
	}
	history, e := f.s.ScheduleHistory(f.ctx, other, s.ID, "", 20)
	if e != nil || len(history.Occurrences) != 0 {
		t.Fatal(history, e)
	}
	d, e := f.s.PreviewSchedule(f.ctx, f.scope, x)
	if e != nil {
		t.Fatal(e)
	}
	bad := strings.Repeat("a", 64)
	if bad == d.Hash {
		bad = strings.Repeat("b", 64)
	}
	if _, e = f.s.DraftSchedule(f.ctx, f.scope, "invent-preview", ScheduleDraftRequest{ID: s.ID, ExpectedVersion: 1, Selection: x, Hash: bad}); !errors.Is(e, store.ErrRevision) {
		t.Fatal(e)
	}
	if _, e = f.s.ControlSchedule(f.ctx, f.scope, s.ID, s.Version, "suspend", "stale-suspend", Decision{Hash: s.Hash, Revision: s.Revision - 1}); !errors.Is(e, store.ErrRevision) {
		t.Fatal(e)
	}
}

func TestScheduleVersionSwitchStopsOldWorkPreservesClaimsAndReleasesCapacity(t *testing.T) {
	f, x, due := scheduleFixture(t, 30, "all", true)
	second, _, e := f.s.Custody.Accept(f.ctx, f.scope, "second", 3, secure.Digest([]byte("xyz")), bytes.NewReader([]byte("xyz")))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.Custody.PathCommand(f.ctx, f.scope, "publish-second", store.PathCommand{Operation: "publish", Path: "/incoming/other.csv", FileID: second.ID}); e != nil {
		t.Fatal(e)
	}
	x.MaxActive = 1
	x.MaxFiles = 2
	s := saveSchedule(t, f, x, "", 0, "capacity-v1")
	waitSchedule(t, f, due)
	original, v := tickSchedule(t, f, s, "capacity-first")
	if len(v.RunIDs) != 1 {
		t.Fatal(v)
	}
	waitSchedule(t, f, due.Add(time.Second))
	_, held := tickSchedule(t, f, s, "capacity-held")
	if held.Reason != "schedule_concurrency" || len(held.Occurrences) != 0 {
		t.Fatal(held)
	}
	before, e := f.s.ScheduleStatus(f.ctx, f.scope, s.ID, 1)
	if e != nil || before.ActiveRuns != 1 {
		t.Fatal(before, e)
	}
	x.Name = "New reviewed revision"
	next := saveSchedule(t, f, x, s.ID, 1, "capacity-v2")
	old, e := f.s.ScheduleStatus(f.ctx, f.scope, s.ID, 1)
	if e != nil || old.Schedule.State != "suspended" || old.CurrentAuthority {
		t.Fatal(old, e)
	}
	current, e := f.s.ScheduleStatus(f.ctx, f.scope, s.ID, 2)
	if e != nil || current.ActiveRuns != 0 {
		t.Fatal("stale version kept new capacity occupied", current, e)
	}
	tx, e := f.s.Custody.DB.Begin(f.ctx, f.scope)
	if e != nil {
		t.Fatal(e)
	}
	if e = tx.CheckScheduleBinding(f.ctx, v.RunIDs[0]); !errors.Is(e, store.ErrSchedule) {
		t.Fatal("old queued work rebound", e)
	}
	tx.Tx.Rollback(f.ctx)
	_, newTick := tickSchedule(t, f, next, "capacity-second-file")
	if len(newTick.RunIDs) != 1 || newTick.RunIDs[0] == v.RunIDs[0] {
		t.Fatal(newTick)
	}
	var claims, distinctFiles int
	if e = f.admin.QueryRow(f.ctx, `SELECT count(*),count(DISTINCT file_id) FROM workflow_schedule_inputs`).Scan(&claims, &distinctFiles); e != nil || claims != 2 || distinctFiles != 2 {
		t.Fatal("input repeated across versions", claims, distinctFiles, e)
	}
	replay, e := f.s.TickSchedule(f.ctx, f.scope, s.ID, 1, "capacity-first", ScheduleTickRequest{Limit: 1})
	if e != nil || !replay.Replayed || !bytes.Equal(replay.Resource, original.Resource) {
		t.Fatal("historical receipt lost", e)
	}
	page, e := f.s.Schedules(f.ctx, f.scope, "", 20)
	if e != nil || len(page.Schedules) != 1 || page.Schedules[0].Version != 2 || page.Schedules[0].ActiveVersion != 2 {
		t.Fatal(page, e)
	}
}
func TestScheduleCatchUpIsBoundedAndNeverSelectsFuturePublishedInput(t *testing.T) {
	f, x, _ := scheduleFixture(t, 120, "all", true)
	past := time.Now().UTC().Truncate(time.Second).Add(-20 * time.Second)
	x.Calendar.Start = past
	x.Calendar.End = past.Add(time.Minute)
	x.Calendar.Times = []string{}
	for i := 0; i < 5; i++ {
		x.Calendar.Times = append(x.Calendar.Times, past.Add(time.Duration(i)*time.Second).Format("15:04:05"))
	}
	x.CatchUp = 2
	s := saveSchedule(t, f, x, "", 0, "catch-up")
	r, e := f.s.TickSchedule(f.ctx, f.scope, s.ID, 1, "bounded-two", ScheduleTickRequest{Limit: 2})
	if e != nil {
		t.Fatal(e)
	}
	var out ScheduleTickResult
	json.Unmarshal(r.Resource, &out)
	if len(out.Occurrences) != 2 || len(out.RunIDs) != 0 || out.Schedule.NextDue == nil || !out.Schedule.NextDue.Equal(past.Add(2*time.Second)) {
		t.Fatal(out)
	}
	for _, o := range out.Occurrences {
		if o.Kind != "empty" {
			t.Fatal("future publication selected for historical occurrence", o)
		}
	}
	if _, e = f.s.TickSchedule(f.ctx, f.scope, s.ID, 1, "too-many", ScheduleTickRequest{Limit: 3}); !errors.Is(e, store.ErrLimit) {
		t.Fatal(e)
	}
	r, e = f.s.TickSchedule(f.ctx, f.scope, s.ID, 1, "next-two", ScheduleTickRequest{Limit: 2})
	if e != nil {
		t.Fatal(e)
	}
	json.Unmarshal(r.Resource, &out)
	if len(out.Occurrences) != 2 || out.Schedule.NextDue == nil || !out.Schedule.NextDue.Equal(past.Add(4*time.Second)) {
		t.Fatal(out)
	}
}
func TestScheduleSkipAndLatestPoliciesMatchDatabaseCalendarProof(t *testing.T) {
	for _, policy := range []string{"skip", "latest"} {
		t.Run(policy, func(t *testing.T) {
			f, x, _ := scheduleFixture(t, 120, policy, true)
			past := time.Now().UTC().Truncate(time.Second).Add(-20 * time.Second)
			x.Calendar.Start = past
			x.Calendar.End = past.Add(time.Minute)
			x.Calendar.Times = []string{past.Format("15:04:05"), past.Add(time.Second).Format("15:04:05")}
			s := saveSchedule(t, f, x, "", 0, "missed-"+policy)
			r, e := f.s.TickSchedule(f.ctx, f.scope, s.ID, 1, "missed-tick", ScheduleTickRequest{Limit: 2})
			if e != nil {
				t.Fatal(e)
			}
			var v ScheduleTickResult
			json.Unmarshal(r.Resource, &v)
			if len(v.Occurrences) < 1 || v.Occurrences[0].Kind != "skipped" || v.Schedule.NextDue != nil || len(v.RunIDs) != 0 {
				t.Fatal(v)
			}
			if policy == "latest" && (len(v.Occurrences) != 2 || v.Occurrences[1].Kind != "empty" || !v.Occurrences[1].Due.Equal(past.Add(time.Second))) {
				t.Fatal(v)
			}
			if policy == "skip" && len(v.Occurrences) != 1 {
				t.Fatal(v)
			}
		})
	}
}
func TestScheduleSQLRejectsInventedDueTimeAndUnprojectedEvent(t *testing.T) {
	f, x, due := scheduleFixture(t, 30, "all", true)
	s := saveSchedule(t, f, x, "", 0, "sql-schedule")
	waitSchedule(t, f, due)
	tx, e := f.s.Custody.DB.Begin(f.ctx, f.scope)
	if e != nil {
		t.Fatal(e)
	}
	if e = tx.ScheduleLock(f.ctx, true); e != nil {
		t.Fatal(e)
	}
	o := store.NewScheduleOccurrence(s.ID, 1, due.Add(-time.Second), 30, "empty", 0)
	e = tx.SaveScheduleOccurrence(f.ctx, o)
	var pe *pgconn.PgError
	if !errors.As(e, &pe) || pe.Code != "23514" || !strings.Contains(pe.Message, "due calendar") {
		t.Fatal("forged clock admitted", e)
	}
	tx.Tx.Rollback(f.ctx)
	tx, e = f.s.Custody.DB.Begin(f.ctx, f.scope)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = tx.Append(f.ctx, "WorkflowScheduleInput", secure.NewID(), map[string]any{"untrusted": "cannot claim source or execute"}); e != nil {
		t.Fatal(e)
	}
	e = tx.Tx.Commit(f.ctx)
	if !errors.As(e, &pe) || pe.Code != "23514" {
		t.Fatal("unprojected schedule event committed", e)
	}
}
func TestScheduleActorPartnerAndTenantIsolationUsesValidForeignCredentials(t *testing.T) {
	f, x, due := scheduleFixture(t, 30, "all", true)
	s := saveSchedule(t, f, x, "", 0, "scoped-schedule")
	waitSchedule(t, f, due)
	_, tick := tickSchedule(t, f, s, "scope-tick")
	for _, sameTenant := range []bool{true, false} {
		tenant := f.scope.Tenant
		if !sameTenant {
			tenant = secure.NewID()
		}
		partner := secure.NewID()
		token := filepath.Join(t.TempDir(), "different-scope.token")
		if e := secure.WriteToken(token); e != nil {
			t.Fatal(e)
		}
		if e := store.Provision(f.ctx, f.adminPath, tenant, partner, token); e != nil {
			t.Fatal(e)
		}
		secret, e := secure.ReadSecret(token, 64)
		if e != nil {
			t.Fatal(e)
		}
		scope := store.Scope{Tenant: tenant, Partner: partner, TokenHash: secure.Digest(secret.Bytes)}
		secret.Close()
		if _, e = f.s.ScheduleStatus(f.ctx, scope, s.ID, 1); !errors.Is(e, store.ErrNotFound) {
			t.Fatal("foreign valid scope learned schedule", e)
		}
		if _, e = f.s.ScheduleOccurrence(f.ctx, scope, tick.Occurrences[0].ID); !errors.Is(e, store.ErrNotFound) {
			t.Fatal("foreign valid scope learned occurrence", e)
		}
		page, e := f.s.Schedules(f.ctx, scope, "", 20)
		if e != nil || len(page.Schedules) != 0 {
			t.Fatal(page, e)
		}
	}
}
func TestScheduleGuardAllowsStatusAndSerializesCredentialMutation(t *testing.T) {
	f, x, due := scheduleFixture(t, 30, "all", true)
	s := saveSchedule(t, f, x, "", 0, "authority-schedule")
	waitSchedule(t, f, due)
	_, v := tickSchedule(t, f, s, "authority-tick")
	managerScope, _ := approvalPeer(t, f, "Independent account manager", append([]string{}, store.DefaultPermissions...))
	worker, e := f.s.Custody.DB.Begin(f.ctx, f.scope)
	if e != nil {
		t.Fatal(e)
	}
	defer worker.Tx.Rollback(context.Background())
	if e = worker.CheckScheduleBinding(f.ctx, v.RunIDs[0]); e != nil {
		t.Fatal(e)
	}
	account, e := f.s.Custody.DB.Account(f.ctx, f.scope, worker.Actor)
	if e != nil {
		t.Fatal(e)
	}
	newHash := secure.Digest([]byte(secure.NewID()))
	done := make(chan error, 1)
	finished := false
	defer func() {
		worker.Tx.Rollback(context.Background())
		if !finished {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("credential mutation did not finish")
			}
		}
	}()
	go func() {
		_, e := f.s.Custody.DB.ChangeAccount(f.ctx, managerScope, "rotate-scheduled-owner", store.AccountCommand{Operation: "rotate", ID: worker.Actor, ExpectedRevision: account.Revision, CredentialHash: newHash})
		done <- e
	}()
	until := time.Now().Add(5 * time.Second)
	for {
		var waiting bool
		if e = f.admin.QueryRow(f.ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks l JOIN pg_stat_activity a USING(pid) WHERE a.datname=current_database() AND a.application_name='freightctl' AND l.locktype='advisory' AND NOT l.granted AND a.query LIKE 'INSERT INTO account_revisions%')`).Scan(&waiting); e != nil {
			t.Fatal(e)
		}
		if waiting {
			break
		}
		if time.Now().After(until) {
			t.Fatal("actual mutation did not wait at live schedule guard")
		}
		time.Sleep(10 * time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(f.ctx, time.Second)
	status, e := f.s.Status(ctx, f.scope, v.RunIDs[0])
	cancel()
	if e != nil || status.ObservedState != "queued" {
		t.Fatal("status waited behind credential mutation", status, e)
	}
	worker.Tx.Rollback(f.ctx)
	select {
	case e = <-done:
		finished = true
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("writer remained blocked")
	}
	nextScope := f.scope
	nextScope.TokenHash = newHash
	current, e := f.s.ScheduleStatus(f.ctx, nextScope, s.ID, 1)
	if e != nil || current.CurrentAuthority {
		t.Fatal("rotation silently rebound schedule", current, e)
	}
	check, e := f.s.Custody.DB.Begin(f.ctx, nextScope)
	if e != nil {
		t.Fatal(e)
	}
	defer check.Tx.Rollback(f.ctx)
	if e = check.CheckScheduleBinding(f.ctx, v.RunIDs[0]); !errors.Is(e, store.ErrSchedule) {
		t.Fatal("old certificate authorized current execution", e)
	}
}

func TestScheduleSelectorHonorsCurrentGroupAndPrivateModesBeforeItsLimit(t *testing.T) {
	f, x, _ := scheduleFixture(t, 30, "all", false)
	parent := f.scope
	second, _, e := f.s.Custody.Accept(f.ctx, parent, "second-mode", 3, secure.Digest([]byte("xyz")), bytes.NewReader([]byte("xyz")))
	if e != nil {
		t.Fatal(e)
	}
	privateFile, groupFile := f.file, second
	if privateFile.ID > groupFile.ID {
		privateFile, groupFile = groupFile, privateFile
	}
	privateMode, groupMode := uint32(0600), uint32(0660)
	for _, v := range []struct {
		path string
		file *store.File
		mode *uint32
	}{{"/incoming/private.csv", privateFile, &privateMode}, {"/incoming/shared.csv", groupFile, &groupMode}} {
		if _, e = f.s.Custody.PathCommand(f.ctx, parent, "publish-"+v.file.ID, store.PathCommand{Operation: "publish", Path: v.path, FileID: v.file.ID, Mode: v.mode}); e != nil {
			t.Fatal(e)
		}
	}
	child, account := approvalPeer(t, f, "Scheduled group reader", append([]string{}, store.DefaultPermissions...))
	registered, e := f.s.RegisterConnection(f.ctx, child, "child-connection", f.request)
	if e != nil {
		t.Fatal(e)
	}
	var conn ConnectionView
	if json.Unmarshal(registered.Resource, &conn) != nil {
		t.Fatal("connection")
	}
	permissions := []string{}
	for _, g := range store.DefaultPermissions {
		if g != "admin" {
			permissions = append(permissions, g)
		}
	}
	if _, e = f.s.Custody.DB.ChangeAccount(f.ctx, parent, "remove-child-admin", store.AccountCommand{Operation: "update", ID: account.ID, ExpectedRevision: 1, Policy: &store.AccountPolicy{Label: "Scheduled group reader", Root: "/", Permissions: permissions}}); e != nil {
		t.Fatal(e)
	}
	f.scope = child
	f.connection = conn
	def := f.definition()
	def.Steps = def.Steps[:1]
	workflow := f.approved(t, def)
	x.Workflow = Reference{ID: workflow.ID, Version: workflow.Version, Hash: workflow.Hash}
	x.ExpectedAuthority = 2
	x.MaxFiles = 1
	due := time.Now().UTC().Truncate(time.Second).Add(2 * time.Second)
	x.Calendar.Start = due
	x.Calendar.End = due.Add(time.Minute)
	x.Calendar.Times = []string{due.Format("15:04:05"), due.Add(time.Second).Format("15:04:05")}
	s := saveSchedule(t, f, x, "", 0, "group-schedule")
	waitSchedule(t, f, due)
	_, v := tickSchedule(t, f, s, "group-first")
	if len(v.RunIDs) != 1 {
		t.Fatal("readable group file starved behind private file", v)
	}
	o, e := f.s.ScheduleOccurrence(f.ctx, child, v.Occurrences[0].ID)
	if e != nil || len(o.Inputs) != 1 || o.Inputs[0].FileID != groupFile.ID {
		t.Fatal(o, e)
	}
	waitSchedule(t, f, due.Add(time.Second))
	_, next := tickSchedule(t, f, s, "group-second")
	if len(next.RunIDs) != 0 || len(next.Occurrences) != 1 || next.Occurrences[0].Kind != "empty" {
		t.Fatal("private file selected", next)
	}
}
