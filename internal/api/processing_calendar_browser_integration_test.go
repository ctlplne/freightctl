//go:build integration && jsonbrowser

package api

import (
	"encoding/base64"
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
	"github.com/ctlplne/freightctl/internal/checks"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func TestProcessingCalendarNativeBrowserReviewRecoveryQueuesOwnedInputAndKeepsOutputHeld(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "true" || runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Fatal("actual calendar Chrome profile requires native GitHub Linux x86_64")
	}
	s, manager, _, server := browserAPI(t, 600*time.Second)
	private, err := os.MkdirTemp("../../.private", "freightctl-processing-calendar-browser-")
	if err != nil {
		t.Fatal(err)
	}
	private, err = filepath.Abs(private)
	if err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(private, "processor.token")
	if err = secure.WriteToken(tokenPath); err != nil {
		t.Fatal(err)
	}
	token, err := secure.ReadSecret(tokenPath, 64)
	if err != nil {
		t.Fatal(err)
	}
	tokenHash := secure.Digest(token.Bytes)
	token.Close()
	account := store.AccountCommand{Operation: "create", ID: secure.NewID(), CredentialHash: tokenHash, Policy: &store.AccountPolicy{Label: "Calendar browser processor without delivery", Root: "/", Permissions: []string{"list", "read", "write", "check_run", "check_release", "workflow_manage", "workflow_approve", "workflow_execute"}}}
	if _, err = s.DB.ChangeAccount(t.Context(), manager, "calendar-browser-account", account); err != nil {
		t.Fatal(err)
	}
	actor := store.Scope{Tenant: manager.Tenant, Partner: manager.Partner, TokenHash: tokenHash}
	control := &checks.Service{Custody: s}
	wf := &workflow.Service{Custody: s, Processor: control}
	input, err := checks.Normalize(checks.Policy{Schema: 1, Kind: "csv", Columns: []checks.Column{{Name: "account", Type: "text", Required: true, MaxBytes: 32}}, MaxBytes: 8192, MaxRows: 4, MaxRecordBytes: 1024, TimeoutSeconds: 2})
	if err != nil {
		t.Fatal(err)
	}
	registered, err := control.Register(t.Context(), manager, "calendar-browser-input-policy", checks.PolicyRequest{Definition: input})
	if err != nil {
		t.Fatal(err)
	}
	var in store.Configuration
	if json.Unmarshal(registered.Resource, &in) != nil {
		t.Fatal("input policy")
	}
	body := "account\n0001\n"
	source, _, err := s.AcceptAt(t.Context(), actor, "calendar-browser-source", int64(len(body)), secure.Digest([]byte(body)), strings.NewReader(body), custody.UploadTarget{Path: "/settlement.csv"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = control.Run(t.Context(), actor, source.ID, "calendar-browser-source-check"); err != nil {
		t.Fatal(err)
	}
	tx, err := s.DB.Begin(t.Context(), actor)
	if err != nil {
		t.Fatal(err)
	}
	if tx.Has("deliver") {
		t.Fatal("calendar processor gained delivery")
	}
	check, err := tx.FileCheck(t.Context(), source.ID, false)
	tx.Tx.Rollback(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = control.Release(t.Context(), actor, source.ID, "calendar-browser-source-release", checks.ReleaseDecision{SHA256: source.SHA256, PolicyHash: check.PolicyHash, ReportHash: check.ReportHash, Revision: check.Revision}); err != nil {
		t.Fatal(err)
	}
	output := input
	output.Schema, output.Kind = 2, "json_records"
	registered, err = control.RegisterOutputPolicy(t.Context(), manager, "calendar-browser-output-policy", checks.OutputPolicyRequest{Producer: account.ID, Definition: output})
	if err != nil {
		t.Fatal(err)
	}
	var out checks.OutputPolicyRecord
	if json.Unmarshal(registered.Resource, &out) != nil || out.Policy == nil {
		t.Fatal("output contract")
	}
	rules, err := checks.NormalizeRecordProjection(input, checks.RecordProjection{Schema: 1, Kind: "record_projection", SourcePolicyHash: in.Hash, OutputKind: "json_records", Columns: []checks.ProjectionColumn{{Source: "account", Target: "account"}}})
	if err != nil {
		t.Fatal(err)
	}
	drafted, err := wf.Draft(t.Context(), actor, "calendar-browser-task", workflow.DraftRequest{Definition: workflow.Definition{Schema: 3, Name: "Browser calendar processing", Processing: &workflow.ProcessingTask{ID: "project", Kind: "records.project", Definition: rules, OutputPolicy: workflow.Reference{ID: out.Policy.ID, Version: out.Policy.Version, Hash: out.Policy.Hash}, Reason: "Create held records without delivery authority"}}})
	if err != nil {
		t.Fatal(err)
	}
	var cfg store.Configuration
	if json.Unmarshal(drafted.Resource, &cfg) != nil {
		t.Fatal("task")
	}
	if _, err = wf.Decide(t.Context(), actor, cfg.ID, cfg.Version, "calendar-browser-task-approval", "approve", workflow.Decision{Hash: cfg.Hash, Revision: cfg.Revision}); err != nil {
		t.Fatal(err)
	}
	due := time.Now().UTC().Truncate(time.Second).Add(90 * time.Second)
	selection := workflow.ScheduleSelection{Name: "Browser owned processing calendar", Workflow: workflow.Reference{ID: cfg.ID, Version: cfg.Version, Hash: cfg.Hash}, Source: workflow.ScheduleSourceSelection{Kind: workflow.ProcessingScheduleSource, Directory: "/", Pattern: "settlement.csv"}, Calendar: calendar.Selection{Zone: "UTC", Start: due, End: due.Add(time.Minute), Times: []string{due.Format("15:04:05")}, Weekdays: []int{0, 1, 2, 3, 4, 5, 6}, Holidays: []string{}, Gap: "skip", Fold: "both"}, Missed: "all", CatchUp: 1, MaxActive: 1, MaxFiles: 1, Deadline: 600, Grace: 1, ExpectedAuthority: 1}
	config, result := filepath.Join(private, "config.json"), filepath.Join(private, "result.json")
	raw, _ := json.Marshal(map[string]any{"url": server.URL, "tenant": actor.Tenant, "partner": actor.Partner, "token": tokenPath, "source": source.ID, "workflow_hash": cfg.Hash, "selection": selection, "due_at": due, "private": private, "result": result, "certificate_der": base64.StdEncoding.EncodeToString(server.Certificate().Raw)})
	if err = os.WriteFile(config, raw, 0600); err != nil {
		t.Fatal(err)
	}
	log, err := os.OpenFile(filepath.Join(private, "browser.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	cmd := exec.CommandContext(t.Context(), "node", "../../scripts/processing-calendar-browser.mjs", config)
	cmd.Stdout, cmd.Stderr = log, log
	cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
	cmd.WaitDelay = 5 * time.Second
	runErr := cmd.Run()
	raw, err = os.ReadFile(result)
	if err != nil || len(raw) > 4096 {
		t.Fatal("calendar browser has no bounded safe result;private evidence retained")
	}
	var summary struct {
		State         string `json:"state"`
		Schedule      string `json:"schedule"`
		Run           string `json:"run"`
		File          string `json:"file"`
		Hash          string `json:"workflow_hash"`
		DraftRequests int    `json:"draft_requests"`
		TickRequests  int    `json:"tick_requests"`
		Accessibility int    `json:"accessibility_checks"`
		Egress        int    `json:"external_egress"`
		Errors        int    `json:"runtime_errors"`
		Sandbox       bool   `json:"browser_sandbox"`
		Inference     bool   `json:"inference_performed"`
		Failure       string `json:"failure_sha256"`
	}
	if runErr != nil || workflow.Decode(raw, &summary) != nil || summary.State != "passed" || !store.ValidID(summary.Schedule) || !store.ValidID(summary.Run) || !store.ValidID(summary.File) || summary.Hash != cfg.Hash || summary.DraftRequests != 2 || summary.TickRequests != 2 || summary.Accessibility != 6 || summary.Egress != 0 || summary.Errors != 0 || !summary.Sandbox || summary.Inference || summary.Failure != "" {
		t.Fatalf("calendar browser failed;safe result SHA256=%s", secure.Digest(raw))
	}
	observed, err := wf.Status(t.Context(), actor, summary.Run)
	if err != nil || observed.Processing == nil || observed.Processing.FileID != summary.File || observed.Processing.Released || observed.ObservedReason != "output_held" {
		t.Fatal("calendar browser output is not held", err)
	}
	if _, _, err = s.Download(t.Context(), actor, summary.File); !errors.Is(err, store.ErrState) {
		t.Fatal("calendar execution silently released output", err)
	}
	tx, err = s.DB.Begin(t.Context(), actor)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Tx.Rollback(t.Context())
	var claims, runs, deliveries, projections int
	if err = tx.Tx.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM workflow_schedule_inputs WHERE schedule_id=$1),(SELECT count(*) FROM workflow_runs),(SELECT count(*) FROM delivery_intents),(SELECT count(*) FROM record_projections)`, summary.Schedule).Scan(&claims, &runs, &deliveries, &projections); err != nil || claims != 1 || runs != 1 || deliveries != 0 || projections != 1 {
		t.Fatal("calendar recovery duplicated work or acquired delivery effect", err)
	}
	finalCheck, err := tx.FileCheck(t.Context(), summary.File, false)
	if err != nil || finalCheck.State != "held" || finalCheck.Attempts != 0 || finalCheck.ReportHash != "" {
		t.Fatal("calendar execution inherited input checks", err)
	}
}
