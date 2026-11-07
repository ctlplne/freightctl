//go:build integration && jsonbrowser

package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/freightctl/internal/calendar"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/delivery"
	"github.com/ctlplne/freightctl/internal/protectedfs"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func TestLocalCalendarNativeBrowserExactManifestCaptureAndOriginalKeyRecovery(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "true" || runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Fatal("actual local calendar Chrome profile requires native GitHub Linux x86_64")
	}
	s, manager, _, server := browserAPI(t, 1200*time.Second)
	t.Cleanup(func() { _ = s.Disk.Close() })
	private, err := os.MkdirTemp("../../.private", "freightctl-local-calendar-browser-")
	if err != nil {
		t.Fatal(err)
	}
	private, err = filepath.Abs(private)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, body []byte) {
		t.Helper()
		f, err := protectedfs.CreateExclusive(name)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if _, err = f.Write(body); err != nil {
			t.Fatal(err)
		}
		if err = f.Sync(); err != nil {
			t.Fatal(err)
		}
		if err = f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	token := filepath.Join(private, "collector.token")
	if err = secure.WriteToken(token); err != nil {
		t.Fatal(err)
	}
	credential, err := secure.ReadSecret(token, 64)
	if err != nil {
		t.Fatal(err)
	}
	tokenHash := secure.Digest(credential.Bytes)
	credential.Close()
	account := store.AccountCommand{Operation: "create", ID: secure.NewID(), CredentialHash: tokenHash, Policy: &store.AccountPolicy{Label: "Local calendar collector without delivery", Root: "/", Permissions: []string{"admin", "connections_manage", "workflow_manage", "workflow_approve", "workflow_execute", "list", "read", "write"}}}
	if _, err = s.DB.ChangeAccount(t.Context(), manager, "local-calendar-collector", account); err != nil {
		t.Fatal(err)
	}
	scope := store.Scope{Tenant: manager.Tenant, Partner: manager.Partner, TokenHash: tokenHash}
	authority, err := s.DB.Begin(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	canDeliver := authority.Has("deliver")
	authority.Tx.Rollback(t.Context())
	if canDeliver {
		t.Fatal("calendar collector starts with delivery authority")
	}
	directory := filepath.Join(private, "producer")
	if err = protectedfs.EnsureDirectory(directory); err != nil {
		t.Fatal(err)
	}
	identity, err := delivery.InspectLocalCollectionRoot(t.Context(), directory, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	configuration := filepath.Join(private, "source.json")
	profile, err := json.Marshal(map[string]any{"schema_version": 1, "profile": delivery.LocalCollectionProfile, "directory": directory, "root_fingerprint": identity})
	if err != nil {
		t.Fatal(err)
	}
	write(configuration, profile)
	control := &workflow.Service{Custody: s}
	registered, err := control.RegisterConnection(t.Context(), scope, "calendar-local-source", workflow.ConnectionRequest{Directory: "/", Local: &delivery.LocalCollectionSource{Schema: 1, Reference: configuration, SHA256: secure.Digest(profile), RootFingerprint: identity}})
	var connection workflow.ConnectionView
	if err != nil || json.Unmarshal(registered.Resource, &connection) != nil {
		t.Fatal("native local calendar source registration", err)
	}
	d := workflow.Definition{Schema: 1, Name: "Local calendar immutable producer", Steps: []workflow.Step{}, Source: &workflow.CollectionSource{Kind: "local.collect", Connection: workflow.Reference{ID: connection.ID, Version: connection.Version, Hash: connection.Hash}, Manifest: "settlement-{due_utc}.ready.json", Directory: "/", Contract: workflow.ScheduledCollectionContract, MaxFiles: 1, MaxFile: 1024, MaxTotal: 1024}}
	draft, err := control.Draft(t.Context(), scope, "local-calendar-task", workflow.DraftRequest{Definition: d})
	var w store.Configuration
	if err != nil || json.Unmarshal(draft.Resource, &w) != nil {
		t.Fatal("native local calendar task", err)
	}
	if _, err = control.Decide(t.Context(), scope, w.ID, w.Version, "local-calendar-task-approval", "approve", workflow.Decision{Hash: w.Hash, Revision: w.Revision}); err != nil {
		t.Fatal(err)
	}
	due := time.Now().UTC().Truncate(time.Second).Add(90 * time.Second)
	body := []byte("actual immutable local calendar bytes\n")
	write(filepath.Join(directory, "one.csv"), body)
	manifest, err := json.Marshal(workflow.CollectionManifest{Schema: 1, Batch: secure.NewID(), Files: []workflow.CollectionFile{{Name: "one.csv", Size: int64(len(body)), SHA256: secure.Digest(body)}}})
	if err != nil {
		t.Fatal(err)
	}
	manifestName := strings.Replace(d.Source.Manifest, "{due_utc}", due.Format("20060102T150405Z"), 1)
	write(filepath.Join(directory, manifestName), manifest)
	selection := workflow.ScheduleSelection{Name: "Browser local immutable calendar", Workflow: workflow.Reference{ID: w.ID, Version: w.Version, Hash: w.Hash}, Source: workflow.ScheduleSourceSelection{Kind: d.Source.Kind, Directory: d.Source.Directory, Pattern: d.Source.Manifest}, Calendar: calendar.Selection{Zone: "UTC", Start: due, End: due.Add(time.Minute), Times: []string{due.Format("15:04:05")}, Weekdays: []int{0, 1, 2, 3, 4, 5, 6}, Holidays: []string{}, Gap: "skip", Fold: "both"}, Missed: "all", CatchUp: 1, MaxActive: 1, MaxFiles: 1, Deadline: 600, Grace: 1, ExpectedAuthority: 1, Arrival: &workflow.ScheduleArrivalSelection{LateAfter: 0, Deadline: 300, Poll: 1}}
	config, result, failure := filepath.Join(private, "config.json"), filepath.Join(private, "result.json"), filepath.Join(private, "failure.log")
	settings, err := json.Marshal(map[string]any{"url": server.URL, "tenant": scope.Tenant, "partner": scope.Partner, "token": token, "selection": selection, "root_fingerprint": identity, "configuration_sha256": secure.Digest(profile), "manifest_name": manifestName, "directory": directory, "configuration": configuration, "private": private, "result": result, "failure": failure, "certificate_der": base64.StdEncoding.EncodeToString(server.Certificate().Raw)})
	if err != nil {
		t.Fatal(err)
	}
	write(config, settings)
	log, err := protectedfs.CreateExclusive(filepath.Join(private, "browser.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	command := exec.CommandContext(t.Context(), "node", "../../scripts/local-calendar-browser.mjs", config)
	command.Stdout, command.Stderr = log, log
	command.Cancel = func() error { return command.Process.Signal(os.Interrupt) }
	command.WaitDelay = 5 * time.Second
	runErr := command.Run()
	raw, err := secure.ReadSecret(result, 4096)
	if err != nil {
		t.Fatal("native local calendar browser missing bounded result;private evidence retained")
	}
	defer raw.Close()
	var summary struct {
		State         string         `json:"state"`
		Phase         string         `json:"phase"`
		Schedule      string         `json:"schedule"`
		Occurrence    string         `json:"occurrence"`
		Job           string         `json:"job"`
		Commands      map[string]int `json:"commands"`
		Accessibility *int           `json:"accessibility_checks"`
		Egress        *int           `json:"external_egress"`
		Errors        *int           `json:"runtime_errors"`
		Navigation    *int           `json:"navigation_status"`
		Asset         *int           `json:"asset_status"`
		HTML          *bool          `json:"document_html"`
		Sandbox       *bool          `json:"browser_sandbox"`
		Inference     *bool          `json:"inference_performed"`
		Browser       string         `json:"browser_version"`
		Node          string         `json:"node_version"`
		Axe           string         `json:"axe_version"`
	}
	decodeErr := workflow.Decode(raw.Bytes, &summary)
	if runErr != nil || decodeErr != nil || summary.State != "passed" || summary.Phase != "complete" || !store.ValidID(summary.Schedule) || !store.ValidID(summary.Occurrence) || !store.ValidID(summary.Job) || len(summary.Commands) != 5 || summary.Accessibility == nil || *summary.Accessibility != 7 || summary.Egress == nil || *summary.Egress != 0 || summary.Errors == nil || *summary.Errors != 0 || summary.Navigation == nil || *summary.Navigation != 200 || summary.Asset == nil || *summary.Asset != 200 || summary.HTML == nil || !*summary.HTML || summary.Sandbox == nil || !*summary.Sandbox || summary.Inference == nil || *summary.Inference || !regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){1,3}$`).MatchString(summary.Browser) || summary.Node != "v26.13.0" || summary.Axe != "4.14.0" {
		trace := safeBrowserFailureTrace(failure, "local-calendar-browser.mjs")
		runtimeTrace := safeBrowserFailureTrace(filepath.Join(private, "runtime-error.log"), "app.js")
		phase, errors, navigation, asset := "unavailable", -1, -1, -1
		if decodeErr == nil {
			phase = safeNativeBrowserStage(summary.Phase)
			if summary.Errors != nil && *summary.Errors >= 0 && *summary.Errors <= 1000 {
				errors = *summary.Errors
			}
			if summary.Navigation != nil && *summary.Navigation >= 0 && *summary.Navigation <= 599 {
				navigation = *summary.Navigation
			}
			if summary.Asset != nil && *summary.Asset >= 0 && *summary.Asset <= 599 {
				asset = *summary.Asset
			}
		}
		t.Fatalf("native local calendar browser failed;phase=%s;navigation=%d;asset=%d;runtime_errors=%d;runtime_class=%s;runtime_source=%d:%d;runtime_log_sha256=%s;safe result SHA256=%s;class=%s;source=%d:%d;private log SHA256=%s", phase, navigation, asset, errors, runtimeTrace.Class, runtimeTrace.Line, runtimeTrace.Column, runtimeTrace.SHA256, secure.Digest(raw.Bytes), trace.Class, trace.Line, trace.Column, trace.SHA256)
	}
	for _, name := range []string{"draft", "tick", "probe", "admit", "work"} {
		if summary.Commands[name] != 2 {
			t.Fatal("calendar original-key recovery cardinality differs")
		}
	}
	arrival, err := control.ScheduleArrivalStatus(t.Context(), scope, summary.Occurrence)
	if err != nil || arrival.Schedule.ID != summary.Schedule || arrival.Arrival.State != "admitted" || arrival.Arrival.Probes != 1 || arrival.Collection == nil {
		t.Fatal("native local calendar observation/admission differs", err)
	}
	view := arrival.Collection
	if view.Job.ID != summary.Job || view.Job.State != "captured" || !view.Job.Captured || view.Job.Attempts != 1 || view.Job.Fence != 1 || len(view.Inputs) != 1 || view.Inputs[0].FileID == nil || view.Inputs[0].RunID != nil || view.BusinessAcceptance != "unknown" {
		t.Fatal("native local calendar capture/replay differs")
	}
	var frozen workflow.CollectionDefinition
	if workflow.Decode(view.Job.Definition, &frozen) != nil || frozen.Schedule == nil || frozen.Schedule.OccurrenceID != summary.Occurrence || !frozen.Schedule.Due.Equal(due) || frozen.Schedule.ManifestName != manifestName || frozen.Connection.Local == nil || frozen.Connection.Local.RootFingerprint != identity || len(frozen.Effects) != 0 {
		t.Fatal("local calendar lost exact frozen source,UTC or effect binding")
	}
	file, stream, err := s.DownloadPath(t.Context(), scope, view.Inputs[0].Target)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(io.LimitReader(stream, int64(len(body))+1))
	stream.Close()
	if err != nil || !bytes.Equal(got, body) || file.ID != *view.Inputs[0].FileID || file.SHA256 != secure.Digest(body) {
		t.Fatal("independent local calendar custody readback differs", err)
	}
	proof, err := s.DB.Begin(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	defer proof.Tx.Rollback(t.Context())
	if proof.Has("deliver") {
		t.Fatal("calendar collector gained delivery authority")
	}
	var occurrences, jobs, accepted, intents, runs int
	if err = proof.Tx.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM workflow_schedule_occurrences WHERE schedule_id=$1),(SELECT count(*) FROM workflow_collection_jobs),(SELECT count(*) FROM events WHERE kind='FileAccepted' AND resource_id=$2),(SELECT count(*) FROM delivery_intents),(SELECT count(*) FROM workflow_runs)`, summary.Schedule, file.ID).Scan(&occurrences, &jobs, &accepted, &intents, &runs); err != nil || occurrences != 1 || jobs != 1 || accepted != 1 || intents != 0 || runs != 0 {
		t.Fatal("calendar recovery duplicated custody or granted forwarding", occurrences, jobs, accepted, intents, runs, err)
	}
	for name, want := range map[string][]byte{"one.csv": body, manifestName: manifest} {
		got, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("calendar changed producer bytes", err)
		}
	}
	if entries, err := os.ReadDir(directory); err != nil || len(entries) != 2 {
		t.Fatal("calendar wrote producer state", err)
	}
	t.Logf("native local calendar browser passed;exact result SHA256=%s;Chrome=%s", secure.Digest(raw.Bytes), summary.Browser)
}
