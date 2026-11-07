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
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/delivery"
	"github.com/ctlplne/freightctl/internal/protectedfs"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func TestLocalCollectionNativeBrowserReviewCaptureAndOriginalKeyRecovery(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "true" || runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Fatal("actual local collection Chrome profile requires native GitHub Linux x86_64")
	}
	s, scope, credential, server := browserAPI(t, 600*time.Second)
	t.Cleanup(func() { _ = s.Disk.Close() })
	private, err := os.MkdirTemp("../../.private", "freightctl-local-collection-browser-")
	if err != nil {
		t.Fatal(err)
	}
	private, err = filepath.Abs(private)
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(private, "producer")
	if err = protectedfs.EnsureDirectory(directory); err != nil {
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
	registered, err := control.RegisterConnection(t.Context(), scope, "browser-local-source", workflow.ConnectionRequest{Directory: "/", Local: &delivery.LocalCollectionSource{Schema: 1, Reference: configuration, SHA256: secure.Digest(profile), RootFingerprint: identity}})
	var connection workflow.ConnectionView
	if err != nil || json.Unmarshal(registered.Resource, &connection) != nil {
		t.Fatal("native browser local source registration", err)
	}
	d := workflow.Definition{Schema: 1, Name: "Reviewed local producer", Steps: []workflow.Step{}, Source: &workflow.CollectionSource{Kind: "local.collect", Connection: workflow.Reference{ID: connection.ID, Version: connection.Version, Hash: connection.Hash}, Manifest: "one.ready.json", Directory: "/", Contract: workflow.CollectionContract, MaxFiles: 1, MaxFile: 1024, MaxTotal: 1024}}
	draft, err := control.Draft(t.Context(), scope, "browser-local-draft", workflow.DraftRequest{Definition: d})
	var w store.Configuration
	if err != nil || json.Unmarshal(draft.Resource, &w) != nil {
		t.Fatal("native browser local workflow draft", err)
	}
	if _, err = control.Decide(t.Context(), scope, w.ID, w.Version, "browser-local-approve", "approve", workflow.Decision{Hash: w.Hash, Revision: w.Revision}); err != nil {
		t.Fatal(err)
	}
	body := []byte("actual local browser source\n")
	write(filepath.Join(directory, "one.csv"), body)
	manifest, err := json.Marshal(workflow.CollectionManifest{Schema: 1, Batch: secure.NewID(), Files: []workflow.CollectionFile{{Name: "one.csv", Size: int64(len(body)), SHA256: secure.Digest(body)}}})
	if err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(directory, d.Source.Manifest), manifest)
	token, config, result, failure := filepath.Join(private, "credential"), filepath.Join(private, "config.json"), filepath.Join(private, "result.json"), filepath.Join(private, "failure.log")
	write(token, credential.Bytes)
	settings, err := json.Marshal(map[string]any{"url": server.URL, "tenant": scope.Tenant, "partner": scope.Partner, "token": token, "workflow": workflow.Reference{ID: w.ID, Version: w.Version, Hash: w.Hash}, "root_fingerprint": identity, "directory": directory, "configuration": configuration, "result": result, "failure": failure, "certificate_der": base64.StdEncoding.EncodeToString(server.Certificate().Raw)})
	if err != nil {
		t.Fatal(err)
	}
	write(config, settings)
	log, err := protectedfs.CreateExclusive(filepath.Join(private, "browser.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	command := exec.CommandContext(t.Context(), "node", "../../scripts/local-collection-browser.mjs", config)
	command.Stdout, command.Stderr = log, log
	command.Cancel = func() error { return command.Process.Signal(os.Interrupt) }
	command.WaitDelay = 5 * time.Second
	runErr := command.Run()
	raw, err := secure.ReadSecret(result, 4096)
	if err != nil {
		trace := safeBrowserFailureTrace(failure, "local-collection-browser.mjs")
		t.Fatalf("native local browser missing result;class=%s;source=%d:%d;private log SHA256=%s", trace.Class, trace.Line, trace.Column, trace.SHA256)
	}
	defer raw.Close()
	var summary struct {
		State         string `json:"state"`
		Phase         string `json:"phase"`
		Job           string `json:"job"`
		Egress        *int   `json:"external_egress"`
		Errors        *int   `json:"runtime_errors"`
		Accessibility *int   `json:"accessibility_checks"`
		Work          *int   `json:"work_requests"`
		Sandbox       *bool  `json:"browser_sandbox"`
		Inference     *bool  `json:"inference_performed"`
		Browser       string `json:"browser_version"`
		Node          string `json:"node_version"`
		Axe           string `json:"axe_version"`
	}
	decodeErr := workflow.Decode(raw.Bytes, &summary)
	if runErr != nil || decodeErr != nil || summary.State != "passed" || summary.Phase != "complete" || !store.ValidID(summary.Job) || summary.Egress == nil || *summary.Egress != 0 || summary.Errors == nil || *summary.Errors != 0 || summary.Accessibility == nil || *summary.Accessibility != 4 || summary.Work == nil || *summary.Work != 2 || summary.Sandbox == nil || !*summary.Sandbox || summary.Inference == nil || *summary.Inference || len(summary.Browser) > 80 || !regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){1,3}$`).MatchString(summary.Browser) || summary.Node != "v26.13.0" || summary.Axe != "4.14.0" {
		phase := "unavailable"
		if decodeErr == nil {
			switch summary.Phase {
			case "launch", "login", "review", "preview", "queue", "capture-replay", "receipt", "complete":
				phase = summary.Phase
			}
		}
		trace := safeBrowserFailureTrace(failure, "local-collection-browser.mjs")
		t.Fatalf("native local browser failed;phase=%s;safe result SHA256=%s;class=%s;source=%d:%d;private log SHA256=%s", phase, secure.Digest(raw.Bytes), trace.Class, trace.Line, trace.Column, trace.SHA256)
	}
	view, err := control.CollectionStatus(t.Context(), scope, summary.Job)
	if err != nil || view.Job.State != "captured" || !view.Job.Captured || view.Job.Attempts != 1 || view.Job.Fence != 1 || len(view.Inputs) != 1 || view.Inputs[0].FileID == nil || view.Inputs[0].RunID != nil || view.BusinessAcceptance != "unknown" {
		t.Fatal("browser local capture exact receipt differs", err)
	}
	file, stream, err := s.DownloadPath(t.Context(), scope, view.Inputs[0].Target)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(io.LimitReader(stream, int64(len(body))+1))
	stream.Close()
	if err != nil || !bytes.Equal(got, body) || file.ID != *view.Inputs[0].FileID || file.SHA256 != secure.Digest(body) || file.Size != int64(len(body)) {
		t.Fatal("independent local-browser custody readback differs", err)
	}
	proof, err := s.DB.Begin(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	defer proof.Tx.Rollback(t.Context())
	var accepted, intents, runs, receipts int
	if err = proof.Tx.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM events WHERE kind='FileAccepted' AND resource_id=$1),(SELECT count(*) FROM delivery_intents),(SELECT count(*) FROM workflow_runs),(SELECT count(*) FROM workflow_receipts WHERE resource_id=$2)`, file.ID, summary.Job).Scan(&accepted, &intents, &runs, &receipts); err != nil || accepted != 1 || intents != 0 || runs != 0 || receipts != 2 {
		t.Fatal("browser local replay or implicit forwarding changed cardinality", accepted, intents, runs, receipts, err)
	}
	for name, want := range map[string][]byte{"one.csv": body, d.Source.Manifest: manifest} {
		got, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("browser collector changed producer bytes", err)
		}
	}
	if entries, err := os.ReadDir(directory); err != nil || len(entries) != 2 {
		t.Fatal("browser collector wrote producer state", err)
	}
	t.Logf("native local collection browser passed;exact result SHA256=%s;Chrome=%s", secure.Digest(raw.Bytes), summary.Browser)
}
