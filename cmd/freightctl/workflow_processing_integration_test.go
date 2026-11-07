//go:build integration

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/freightctl/internal/checks"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
	"github.com/jackc/pgx/v5"
)

func TestProcessingWorkflowCLIUsesApprovedTaskAndSeparateOutputRelease(t *testing.T) {
	ctx := context.Background()
	adminRef, runtimeRef := os.Getenv("FREIGHTCTL_TEST_ADMIN_FILE"), os.Getenv("FREIGHTCTL_TEST_RUNTIME_FILE")
	if adminRef == "" || runtimeRef == "" {
		t.Fatal("actual task-owned PostgreSQL references required")
	}
	secret, err := secure.ReadSecret(adminRef, 4096)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := pgx.Connect(ctx, string(secret.Bytes))
	secret.Close()
	if err != nil {
		t.Fatal("fixture administration unavailable")
	}
	name := "freightctl_cli_processing_" + strings.ReplaceAll(secure.NewID(), "-", "")
	if _, err = admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		admin.Close(ctx)
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(ctx, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)"); err != nil {
			t.Error(err)
		}
		admin.Close(ctx)
	})
	refs := []string{}
	for _, original := range []string{adminRef, runtimeRef} {
		secret, err := secure.ReadSecret(original, 4096)
		if err != nil {
			t.Fatal(err)
		}
		dsn, err := url.Parse(string(secret.Bytes))
		secret.Close()
		if err != nil {
			t.Fatal("fixture reference invalid")
		}
		dsn.Path = "/" + name
		path := filepath.Join(t.TempDir(), "database.dsn")
		if err = os.WriteFile(path, []byte(dsn.String()), 0600); err != nil {
			t.Fatal(err)
		}
		refs = append(refs, path)
	}
	if err = store.Migrate(ctx, refs[0], filepath.Join(filepath.Dir(adminRef), "pg-runtime-password")); err != nil {
		t.Fatal(err)
	}
	token := filepath.Join(t.TempDir(), "owner.token")
	if err = secure.WriteToken(token); err != nil {
		t.Fatal(err)
	}
	scope := store.Scope{Tenant: secure.NewID(), Partner: secure.NewID()}
	if err = store.Provision(ctx, refs[0], scope.Tenant, scope.Partner, token); err != nil {
		t.Fatal(err)
	}
	secret, err = secure.ReadSecret(token, 64)
	if err != nil {
		t.Fatal(err)
	}
	scope.TokenHash = secure.Digest(secret.Bytes)
	secret.Close()
	db, err := store.Open(ctx, refs[1])
	if err != nil {
		t.Fatal(err)
	}
	defer db.Pool.Close()
	storage := filepath.Join(t.TempDir(), "custody")
	disk, err := custody.Open(storage)
	if err != nil {
		t.Fatal(err)
	}
	defer disk.Close()
	service := &custody.Service{DB: db, Disk: disk, MaxFile: 1 << 20, MaxStored: 16 << 20}
	control := &checks.Service{Custody: service}
	policy, err := checks.Normalize(checks.Policy{Schema: 1, Kind: "csv", Columns: []checks.Column{{Name: "account", Type: "text", Required: true, MaxBytes: 32}}, MaxBytes: 8192, MaxRows: 4, MaxRecordBytes: 1024, TimeoutSeconds: 2})
	if err != nil {
		t.Fatal(err)
	}
	registered, err := control.Register(ctx, scope, "cli-processing-input-policy", checks.PolicyRequest{Definition: policy})
	if err != nil {
		t.Fatal(err)
	}
	var sourcePolicy store.Configuration
	if json.Unmarshal(registered.Resource, &sourcePolicy) != nil {
		t.Fatal("source policy")
	}
	body := "account\n0001\n"
	source, _, err := service.Accept(ctx, scope, "cli-processing-source", int64(len(body)), secure.Digest([]byte(body)), strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = control.Run(ctx, scope, source.ID, "cli-processing-source-check"); err != nil {
		t.Fatal(err)
	}
	output := policy
	output.Schema = 2
	output.Kind = "json_records"
	registered, err = control.Register(ctx, scope, "cli-processing-output-policy", checks.PolicyRequest{ExpectedVersion: 1, Definition: output})
	if err != nil {
		t.Fatal(err)
	}
	var outputPolicy store.Configuration
	if json.Unmarshal(registered.Resource, &outputPolicy) != nil {
		t.Fatal("output policy")
	}
	rules, err := checks.NormalizeRecordProjection(policy, checks.RecordProjection{Schema: 1, Kind: "record_projection", SourcePolicyHash: sourcePolicy.Hash, OutputKind: "json_records", Columns: []checks.ProjectionColumn{{Source: "account", Target: "account"}}})
	if err != nil {
		t.Fatal(err)
	}
	definition := workflow.Definition{Schema: 3, Name: "CLI approved processing", Processing: &workflow.ProcessingTask{ID: "project", Kind: "records.project", Definition: rules, OutputPolicy: workflow.Reference{ID: outputPolicy.ID, Version: outputPolicy.Version, Hash: outputPolicy.Hash}, Reason: "Create distinct held CLI output"}}
	requestFile := func(value any) string {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "request.json")
		if err = os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	command := func(name string, extra ...string) ([]byte, error) {
		t.Helper()
		out, err := os.OpenFile(filepath.Join(t.TempDir(), "result.json"), os.O_CREATE|os.O_RDWR, 0600)
		if err != nil {
			t.Fatal(err)
		}
		previous := os.Stdout
		os.Stdout = out
		defer func() { os.Stdout = previous; out.Close() }()
		args := []string{name, "-dsn-file", refs[1], "-token-file", token, "-tenant", scope.Tenant, "-partner", scope.Partner, "-storage", storage, "-max-file-bytes", "1048576"}
		err = run(append(args, extra...))
		if _, e := out.Seek(0, 0); e != nil {
			t.Fatal(e)
		}
		raw, e := io.ReadAll(io.LimitReader(out, (32<<10)+1))
		if e != nil || len(raw) > 32<<10 {
			t.Fatal("CLI result unbounded")
		}
		return raw, err
	}
	raw, err := command("workflow-draft", "-request-file", requestFile(workflow.DraftRequest{Definition: definition}), "-idempotency-key", "cli-processing-draft")
	var drafted workflow.Result
	var cfg store.Configuration
	if err != nil || json.Unmarshal(raw, &drafted) != nil || json.Unmarshal(drafted.Resource, &cfg) != nil {
		t.Fatal("CLI processing draft", err)
	}
	runRequest := requestFile(workflow.RunRequest{Workflow: workflow.Reference{ID: cfg.ID, Version: cfg.Version, Hash: cfg.Hash}, FileID: source.ID})
	if _, err = command("workflow-run", "-request-file", runRequest, "-idempotency-key", "cli-unapproved"); !errors.Is(err, store.ErrState) {
		t.Fatal("CLI execution implied approval", err)
	}
	if _, err = command("workflow-approve", "-workflow-id", cfg.ID, "-version", "1", "-definition-hash", cfg.Hash, "-expected-revision", "1", "-idempotency-key", "cli-processing-approval"); err != nil {
		t.Fatal(err)
	}
	raw, err = command("workflow-run", "-request-file", runRequest, "-idempotency-key", "cli-processing-run")
	var created workflow.Result
	var r store.WorkflowRun
	if err != nil || json.Unmarshal(raw, &created) != nil || json.Unmarshal(created.Resource, &r) != nil {
		t.Fatal("CLI processing run", err)
	}
	raw, err = command("workflow-work", "-run-id", r.ID, "-idempotency-key", "cli-processing-work")
	var work workflow.WorkResult
	if err != nil || json.Unmarshal(raw, &work) != nil || work.Processing == nil || work.Status.ObservedReason != "output_held" || work.Processing.Attempts != 1 {
		t.Fatal("CLI did not create held output", err)
	}
	if _, _, err = service.Download(ctx, scope, work.Processing.FileID); !errors.Is(err, store.ErrState) {
		t.Fatal("CLI processing inherited release", err)
	}
	raw, err = command("workflow-work", "-run-id", r.ID, "-idempotency-key", "cli-processing-work")
	var replay workflow.WorkResult
	if err != nil || json.Unmarshal(raw, &replay) != nil || !replay.Replayed || replay.Processing.ID != work.Processing.ID || replay.Processing.Attempts != 1 {
		t.Fatal("CLI old key advanced the task", err)
	}
	if _, err = control.Run(ctx, scope, work.Processing.FileID, "cli-processing-fresh-output-check"); err != nil {
		t.Fatal(err)
	}
	checked, err := control.Get(ctx, scope, work.Processing.FileID)
	if err != nil {
		t.Fatal(err)
	}
	var binding store.CheckBinding
	if json.Unmarshal(checked.Check.Binding, &binding) != nil {
		t.Fatal("fresh output check binding")
	}
	if _, err = control.Release(ctx, scope, work.Processing.FileID, "cli-processing-separate-release", checks.ReleaseDecision{SHA256: binding.File.SHA256, PolicyHash: checked.Check.PolicyHash, ReportHash: checked.Check.ReportHash, Revision: checked.Check.Revision}); err != nil {
		t.Fatal(err)
	}
	if _, err = command("workflow-refresh", "-run-id", r.ID, "-idempotency-key", "cli-processing-refresh"); err != nil {
		t.Fatal(err)
	}
	raw, err = command("workflow-run-status", "-run-id", r.ID)
	var status workflow.RunView
	if err != nil || json.Unmarshal(raw, &status) != nil || status.ObservedState != "succeeded" || status.ObservedReason != "transformed_output_released" {
		t.Fatal("CLI separate release not observed", err)
	}
	t.Run("independent review controls", func(t *testing.T) {
		reviewerToken := filepath.Join(t.TempDir(), "reviewer.token")
		if err := secure.WriteToken(reviewerToken); err != nil {
			t.Fatal(err)
		}
		secret, err := secure.ReadSecret(reviewerToken, 64)
		if err != nil {
			t.Fatal(err)
		}
		reviewerHash := secure.Digest(secret.Bytes)
		secret.Close()
		account := store.AccountCommand{Operation: "create", ID: secure.NewID(), CredentialHash: reviewerHash, Policy: &store.AccountPolicy{Label: "CLI independent reviewer", Root: "/", Permissions: []string{"inspect", "workflow_approve"}}}
		if _, err = db.ChangeAccount(ctx, scope, "cli-independent-reviewer", account); err != nil {
			t.Fatal(err)
		}
		definition.Name = "CLI independently reviewed processing"
		raw, err := command("workflow-draft", "-request-file", requestFile(workflow.DraftRequest{Definition: definition}), "-idempotency-key", "cli-independent-draft")
		var drafted workflow.Result
		var cfg store.Configuration
		if err != nil || json.Unmarshal(raw, &drafted) != nil || json.Unmarshal(drafted.Resource, &cfg) != nil {
			t.Fatal("independent CLI draft", err)
		}
		raw, err = command("processing-workflow-list", "-processing-workflow-limit", "25")
		var catalog workflow.ProcessingCatalog
		if err != nil || json.Unmarshal(raw, &catalog) != nil || catalog.Profile != "processing-workflow-catalog-v1" {
			t.Fatal("CLI task catalog", err)
		}
		found := false
		for _, task := range catalog.Workflows {
			if task.ID == cfg.ID {
				found = true
				if task.Version != cfg.Version || task.Hash != cfg.Hash || task.State != "draft" || task.ApprovalCurrent {
					t.Fatal("CLI catalog changed draft facts")
				}
			}
		}
		if !found || strings.Contains(string(raw), `"definition":`) {
			t.Fatal("CLI catalog lost own task or exposed complete rules")
		}
		request := workflow.ProcessingReviewRequest{Workflow: workflow.Reference{ID: cfg.ID, Version: cfg.Version, Hash: cfg.Hash}, Revision: 1, Reviewer: account.ID, ExpiresAt: time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond)}
		raw, err = command("processing-review-request", "-request-file", requestFile(request), "-idempotency-key", "cli-independent-request")
		var proposed workflow.Result
		var review store.ProcessingReview
		if err != nil || json.Unmarshal(raw, &proposed) != nil || json.Unmarshal(proposed.Resource, &review) != nil {
			t.Fatal("CLI review request", err)
		}
		decision := requestFile(workflow.Decision{Hash: review.Hash, Revision: 1})
		if _, err = command("processing-review-approve", "-processing-review-id", review.ID, "-request-file", decision, "-idempotency-key", "cli-cannot-self-review"); err == nil {
			t.Fatal("CLI owner approved independent review")
		}
		raw, err = command("processing-review-approve", "-token-file", reviewerToken, "-processing-review-id", review.ID, "-request-file", decision, "-idempotency-key", "cli-independent-approve")
		var approved workflow.Result
		if err != nil || json.Unmarshal(raw, &approved) != nil || json.Unmarshal(approved.Resource, &review) != nil || review.State != "approved" {
			t.Fatal("CLI independent approval", err)
		}
		if _, err = command("processing-review-adopt", "-processing-review-id", review.ID, "-request-file", requestFile(workflow.Decision{Hash: review.Hash, Revision: 2}), "-idempotency-key", "cli-independent-adopt"); err != nil {
			t.Fatal("CLI adoption", err)
		}
		raw, err = command("processing-review-status", "-token-file", reviewerToken, "-processing-review-id", review.ID)
		if err != nil || json.Unmarshal(raw, &review) != nil || review.State != "adopted" || review.AdoptedRevision != 3 {
			t.Fatal("CLI current review state", err)
		}
		if _, err = command("processing-review-withdraw", "-token-file", reviewerToken, "-processing-review-id", review.ID, "-request-file", requestFile(workflow.Decision{Hash: review.Hash, Revision: 3}), "-idempotency-key", "cli-independent-withdraw"); err != nil {
			t.Fatal("CLI withdrawal", err)
		}
	})
}
