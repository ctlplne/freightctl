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
	t.Run("prepared migration calendar uses live schedule preview", func(t *testing.T) {
		qualifyPreparedSFTPGoCalendarPreview(t, ctx, service, scope, cfg, command, requestFile)
	})
	t.Run("portable workflow returns through ordinary draft approval boundary", func(t *testing.T) {
		qualifyPortableWorkflowDraft(t, ctx, service, scope, cfg, command, requestFile)
	})
	var portableSchedule workflow.PortableSchedule
	t.Run("portable schedule retains frozen clock and needs new review", func(t *testing.T) {
		portableSchedule = qualifyPortableScheduleDraft(t, ctx, service, scope, cfg, command, requestFile)
	})
	raw, err = command("workflow-run", "-request-file", runRequest, "-idempotency-key", "cli-processing-run")
	var created workflow.Result
	var r store.WorkflowRun
	if err != nil || json.Unmarshal(raw, &created) != nil || json.Unmarshal(created.Resource, &r) != nil {
		t.Fatal("CLI processing run", err)
	}
	pinnedQueued := workflow.RunHistorySelection{RunID: r.ID, WorkflowHash: r.WorkflowHash, ThroughRevision: r.Revision, Limit: 1}
	_, queuedHistory := readPortableRunHistoryCLI(t, pinnedQueued, command, requestFile)
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
	t.Run("export immutable workflow run history in ordered pages", func(t *testing.T) {
		qualifyPortableRunHistory(t, ctx, service, scope, status, pinnedQueued, queuedHistory, command, requestFile)
	})
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
	t.Run("producer output contract registry", func(t *testing.T) {
		identity, err := db.Identity(ctx, scope)
		if err != nil {
			t.Fatal(err)
		}
		before, err := control.Policy(ctx, scope)
		if err != nil {
			t.Fatal(err)
		}
		request := checks.OutputPolicyRequest{Producer: identity.Actor, Definition: output}
		raw, err := command("processing-output-policy-register", "-request-file", requestFile(request), "-idempotency-key", "cli-register-output-contract")
		var accepted checks.Result
		var record checks.OutputPolicyRecord
		if err != nil || json.Unmarshal(raw, &accepted) != nil || json.Unmarshal(accepted.Resource, &record) != nil || record.Policy.State != "output_active" || record.Binding.Producer.Actor != identity.Actor || record.IngressChanged {
			t.Fatal("CLI output contract registration", err)
		}
		raw, err = command("processing-output-policy-list", "-output-policy-limit", "25")
		var page checks.OutputPolicyPage
		if err != nil || json.Unmarshal(raw, &page) != nil || len(page.Policies) != 1 || page.Policies[0].ID != record.Policy.ID {
			t.Fatal("CLI output registry listing", err)
		}
		raw, err = command("processing-output-policy-status", "-output-policy-id", record.Policy.ID, "-version", "1")
		var view checks.OutputPolicyView
		if err != nil || json.Unmarshal(raw, &view) != nil || !view.ProducerCurrent {
			t.Fatal("CLI output binding inspection", err)
		}
		raw, err = command("check-processing-contracts", "-file-id", source.ID, "-request-file", requestFile(store.OnboardingReference{ID: record.Policy.ID, Version: record.Policy.Version, Hash: record.Policy.Hash}))
		var contracts checks.ProcessingContracts
		if err != nil || json.Unmarshal(raw, &contracts) != nil || contracts.Profile != "record-processing-contracts-v2" || contracts.OutputBinding == nil || contracts.OutputPolicy.Reference.ID != record.Policy.ID || contracts.Source.ID != source.ID {
			t.Fatal("CLI explicit producer output metadata", err)
		}
		if _, err = command("processing-output-policy-revoke", "-output-policy-id", record.Policy.ID, "-version", "1", "-request-file", requestFile(checks.PolicyDecision{Hash: record.Policy.Hash, Version: 1, Revision: 1}), "-idempotency-key", "cli-revoke-output-contract"); err != nil {
			t.Fatal("CLI output revocation", err)
		}
		after, err := control.Policy(ctx, scope)
		if err != nil || after.ID != before.ID || after.Version != before.Version || after.Hash != before.Hash || after.State != before.State {
			t.Fatal("CLI output registry altered ingress", err)
		}
		t.Run("portable output policy enrolls a distinct scoped producer", func(t *testing.T) {
			destination := store.Scope{Tenant: secure.NewID(), Partner: secure.NewID()}
			destinationToken := filepath.Join(t.TempDir(), "destination.token")
			if err := secure.WriteToken(destinationToken); err != nil {
				t.Fatal(err)
			}
			if err := store.Provision(ctx, refs[0], destination.Tenant, destination.Partner, destinationToken); err != nil {
				t.Fatal(err)
			}
			secret, err := secure.ReadSecret(destinationToken, 64)
			if err != nil {
				t.Fatal(err)
			}
			destination.TokenHash = secure.Digest(secret.Bytes)
			secret.Close()
			producer, err := db.Identity(ctx, destination)
			if err != nil || producer.Actor == identity.Actor {
				t.Fatal("destination needs its own producer", err)
			}
			destinationFlags := []string{"-tenant", destination.Tenant, "-partner", destination.Partner, "-token-file", destinationToken}
			reference := []string{"-output-policy-id", record.Policy.ID, "-version", "1", "-definition-hash", record.Policy.Hash}
			exportPath := filepath.Join(privateCLIDirectory(t), "policy.json")
			exportFlags := append(reference, "-output", exportPath)
			if _, err := command("processing-output-policy-export", append(exportFlags, destinationFlags...)...); err == nil {
				t.Fatal("export crossed workspace boundary")
			}
			if _, err := command("processing-output-policy-export", append(exportFlags, "-definition-hash", strings.Repeat("0", 64))...); !errors.Is(err, store.ErrRevision) {
				t.Fatal("export accepted changed definition hash", err)
			}
			if _, err := os.Lstat(exportPath); !os.IsNotExist(err) {
				t.Fatal("failed export published a path", err)
			}
			raw, err := command("processing-output-policy-export", exportFlags...)
			var receipt workflow.PortableExportReceipt
			if err != nil || json.Unmarshal(raw, &receipt) != nil {
				t.Fatal("export refused exact historical revision", err)
			}
			archive, err := os.ReadFile(exportPath)
			var manifest checks.PortableOutputPolicy
			if err != nil || json.Unmarshal(archive, &manifest) != nil || secure.Digest(archive) != receipt.SHA256 ||
				receipt.Size != len(archive) || receipt.Source != manifest.Source || manifest.Profile != checks.PortableOutputPolicyProfile ||
				manifest.ObservedState != "output_revoked" || manifest.SourceBinding == nil || *manifest.SourceBinding != *record.Binding ||
				manifest.Registration.Producer != "" || len(manifest.RequiredBindings) != 1 || manifest.RequiredBindings[0] != "producer_id" {
				t.Fatal("export changed the exact policy, observed state, or binding", err)
			}
			register := func(request checks.OutputPolicyRequest) ([]byte, error) {
				flags := append(destinationFlags, "-request-file", requestFile(request), "-idempotency-key", "cli-recreate-output-policy")
				return command("processing-output-policy-register", flags...)
			}
			if _, err := register(manifest.Registration); !errors.Is(err, checks.ErrInput) {
				t.Fatal("unbound template registered without a destination producer", err)
			}
			manifest.Registration.Producer = producer.Actor
			raw, err = register(manifest.Registration)
			var result checks.Result
			var restored checks.OutputPolicyRecord
			if err != nil || json.Unmarshal(raw, &result) != nil || json.Unmarshal(result.Resource, &restored) != nil ||
				restored.Policy == nil || restored.Binding == nil || restored.Policy.Hash != record.Policy.Hash ||
				restored.Policy.ID == record.Policy.ID || restored.Policy.State != "output_active" ||
				restored.Binding.Producer.Actor != producer.Actor || restored.Binding.Producer.Tenant != destination.Tenant ||
				restored.Binding.Producer.Partner != destination.Partner || restored.IngressChanged {
				t.Fatal("new policy failed to preserve exact checks under the new producer", err)
			}
			intake, err := control.Policy(ctx, destination)
			if err != nil || intake != nil {
				t.Fatal("export or output registration configured destination ingress", err)
			}
			t.Logf("portable output policy definition %s, archive %s", restored.Policy.Hash, receipt.SHA256)
			destinationOutput := workflow.Reference{ID: restored.Policy.ID, Version: restored.Policy.Version, Hash: restored.Policy.Hash}
			t.Run("portable intake restores exact checks after head review", func(t *testing.T) {
				path := filepath.Join(privateCLIDirectory(t), "intake.json")
				sourceRef := workflow.Reference{ID: sourcePolicy.ID, Version: sourcePolicy.Version, Hash: sourcePolicy.Hash}
				flags := []string{"-intake-policy-id", sourceRef.ID, "-version", "1", "-definition-hash", sourceRef.Hash, "-output", path}
				if _, err := command("intake-policy-export", append(flags, destinationFlags...)...); err == nil {
					t.Fatal("source intake policy visible to another workspace")
				}
				if _, err := command("intake-policy-export", append(flags, "-intake-policy-id", record.Policy.ID, "-definition-hash", record.Policy.Hash)...); !errors.Is(err, store.ErrNotFound) {
					t.Fatal("source output policy escaped through intake export", err)
				}
				if _, err := os.Lstat(path); !os.IsNotExist(err) {
					t.Fatal("failed intake export published a path", err)
				}
				raw, err := command("intake-policy-export", flags...)
				var receipt workflow.PortableExportReceipt
				if err != nil || json.Unmarshal(raw, &receipt) != nil {
					t.Fatal("export refused exact retired intake revision", err)
				}
				archive, err := os.ReadFile(path)
				var manifest checks.PortableIntakePolicy
				if err != nil || json.Unmarshal(archive, &manifest) != nil || secure.Digest(archive) != receipt.SHA256 ||
					receipt.Size != len(archive) || receipt.Source != sourceRef || manifest.Source != sourceRef ||
					manifest.Profile != checks.PortableIntakePolicyProfile || manifest.ObservedState != "retired" ||
					manifest.Registration.ExpectedVersion != -1 || len(manifest.RequiredBindings) != 1 || manifest.RequiredBindings[0] != "expected_version" {
					t.Fatal("wrong source history or destination review template", err)
				}
				register := func(request checks.PolicyRequest) ([]byte, error) {
					flags := append(destinationFlags, "-request-file", requestFile(request), "-idempotency-key", "cli-recreate-intake")
					return command("intake-policy-register", flags...)
				}
				if _, err := register(manifest.Registration); !errors.Is(err, checks.ErrInput) {
					t.Fatal("destination registered an unreviewed intake template", err)
				}
				manifest.Registration.ExpectedVersion = 0
				raw, err = register(manifest.Registration)
				var result checks.Result
				var restored store.Configuration
				if err != nil || json.Unmarshal(raw, &result) != nil || json.Unmarshal(result.Resource, &restored) != nil ||
					restored.ID == sourceRef.ID || restored.Version != 1 || restored.Hash != sourceRef.Hash || restored.State != "active" {
					t.Fatal("ordinary registration changed source checks or reused its identity", err)
				}
				file, _, err := service.Accept(ctx, destination, "portable-intake-replay", int64(len(body)), secure.Digest([]byte(body)), strings.NewReader(body))
				if err != nil {
					t.Fatal("ordinary destination intake", err)
				}
				view, err := control.Get(ctx, destination, file.ID)
				if err != nil || view.Check == nil || view.Check.PolicyID != restored.ID || view.Check.PolicyHash != restored.Hash || view.Check.State != "held" {
					t.Fatal("restored policy failed to hold and bind new bytes", err)
				}
				if _, err := control.Run(ctx, destination, file.ID, "cli-restored-intake-run"); err != nil {
					t.Fatal("ordinary check of recovered rules", err)
				}
				view, err = control.Get(ctx, destination, file.ID)
				if err != nil || view.Check == nil || view.Check.State != "passed" || view.Check.ReportHash == "" {
					t.Fatal("ordinary check failed to preserve the accepted original CSV behavior", err)
				}
				t.Logf("portable intake policy definition %s, archive %s", restored.Hash, receipt.SHA256)
				t.Run("rebound workspace repeats approved processing", func(t *testing.T) {
					rebound := qualifyReboundPortableProcessing(t, ctx, service, scope, destination, cfg, destinationOutput,
						restored.Hash, file.ID, work.Processing.FileID, destinationFlags, command, requestFile)
					if portableSchedule.Profile == "" {
						portableSchedule = qualifyPortableScheduleDraft(t, ctx, service, scope, cfg, command, requestFile)
					}
					qualifyReboundPortableSchedule(t, ctx, service, destination, portableSchedule, rebound, destinationFlags, command, requestFile)
				})
			})
		})
	})
}
