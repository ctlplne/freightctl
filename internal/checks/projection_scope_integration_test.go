//go:build integration

package checks

import (
	"errors"
	"strings"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestScopedProjectionActualOwnedInputNamespaceHeldOutputAndNoRelease(t *testing.T) {
	f := setup(t)
	s := &Service{Custody: f.wf.Custody}
	manager := f.scope
	if _, err := s.Register(f.ctx, manager, "input-policy", PolicyRequest{Definition: testPolicy(t)}); err != nil {
		t.Fatal(err)
	}
	mode := uint32(0777)
	if _, err := s.Custody.PathCommand(f.ctx, manager, "scope-directory", store.PathCommand{Operation: "mkdir", Path: "/processor", Mode: &mode}); err != nil {
		t.Fatal(err)
	}
	grants := []string{"read", "write", "check_run", "workflow_manage", "workflow_approve", "workflow_execute"}
	account := store.AccountCommand{Operation: "create", ID: secure.NewID(), CredentialHash: secure.Digest([]byte(secure.NewID())), Policy: &store.AccountPolicy{Label: "Scoped record processor", Root: "/processor", Permissions: grants}}
	if _, err := s.Custody.DB.ChangeAccount(f.ctx, manager, "processor-account", account); err != nil {
		t.Fatal(err)
	}
	actor := store.Scope{Tenant: manager.Tenant, Partner: manager.Partner, TokenHash: account.CredentialHash}
	source, _, err := s.Custody.AcceptAt(f.ctx, actor, "source", int64(len(goodCSV)), secure.Digest([]byte(goodCSV)), strings.NewReader(goodCSV), custody.UploadTarget{Path: "/input.csv"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Run(f.ctx, actor, source.ID, "check-source"); err != nil {
		t.Fatal(err)
	}
	c := getCheck(t, s, &fixture{ctx: f.ctx, scope: actor}, source.ID)
	rules, err := NormalizeRecordProjection(testPolicy(t), RecordProjection{Schema: 1, Kind: "record_projection", SourcePolicyHash: c.PolicyHash, OutputKind: "json_records", MaxBytes: 8192, Columns: []ProjectionColumn{{Source: "amount", Target: "total"}, {Source: "account", Target: "account"}, {Source: "day", Target: "day"}}})
	if err != nil {
		t.Fatal(err)
	}
	output, err := projectionOutputPolicy(testPolicy(t), rules)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Register(f.ctx, manager, "output-policy", PolicyRequest{ExpectedVersion: 1, Definition: output}); err != nil {
		t.Fatal(err)
	}
	options := ProjectionOptions{Profile: ScopedProjectionProfile, TargetPath: "/derived.json", Reason: "Process only this actor's own input in its namespace", Definition: rules}
	if _, err = s.PreviewProjection(f.ctx, actor, f.file.ID, options); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("processing grant revealed another owner", err)
	}
	legacy := options
	legacy.Profile = ProjectionReviewProfile
	if _, err = s.PreviewProjection(f.ctx, actor, source.ID, legacy); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("scoped grant used legacy root profile", err)
	}
	preview, err := s.PreviewProjection(f.ctx, actor, source.ID, options)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Plan.Schema != 2 || preview.Plan.Context.Root != "/processor" || preview.Plan.Context.Target.Command.Path != "/derived.json" {
		t.Fatal("scoped review lost logical target or root")
	}
	saved, err := s.ProposeProjection(f.ctx, actor, "propose", preview.Plan)
	if err != nil {
		t.Fatal(err)
	}
	r := projectionIntentRow(t, saved)
	approved, err := s.DecideProjection(f.ctx, actor, r.ID, "approve", PolicyRecheckDecision{Operation: "approve", Hash: r.Hash, Revision: r.Revision})
	if err != nil {
		t.Fatal(err)
	}
	f.scope = actor
	_, attempt := startProjection(t, f, s, projectionIntentRow(t, approved), "start")
	worked, err := s.WorkProjection(f.ctx, actor, "work", attempt)
	if err != nil {
		t.Fatal(err)
	}
	completed := projectionIntentRow(t, worked)
	if completed.State != "completed" {
		t.Fatal("scoped work did not produce held output")
	}
	check := getCheck(t, s, f, completed.FileID)
	var root, target, parent string
	if err = f.admin.QueryRow(f.ctx, `SELECT binding->>'namespace_root',binding->'target'->>'path',binding->>'parent_id' FROM file_checks WHERE file_id=$1`, completed.FileID).Scan(&root, &target, &parent); err != nil {
		t.Fatal(err)
	}
	var actualParent string
	if err = f.admin.QueryRow(f.ctx, `SELECT entry_id::text FROM namespace_entries WHERE tenant_id=$1 AND partner_id=$2 AND path='/processor' AND NOT deleted`, actor.Tenant, actor.Partner).Scan(&actualParent); err != nil || parent != actualParent || root != "/processor" || target != "/derived.json" {
		t.Fatal("output escaped logical root", err)
	}
	if check.State != "queued" || check.ReportHash != "" {
		t.Fatal("processing supplied a completed check report")
	}
	deniedRelease := releaseDecision(check)
	deniedRelease.ReportHash = secure.Digest([]byte("not a completed check report"))
	if _, err = s.Release(f.ctx, actor, completed.FileID, "not-a-release-grant", deniedRelease); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("processing implied release", err)
	}
	if _, _, err = s.Custody.Download(f.ctx, actor, completed.FileID); !errors.Is(err, store.ErrState) {
		t.Fatal("held output disclosed", err)
	}
	// Removing execution authority also blocks replay of the original work
	// receipt;management/approval alone cannot act as the runtime identity.
	change := store.AccountCommand{Operation: "update", ID: account.ID, ExpectedRevision: 1, Policy: &store.AccountPolicy{Label: "Scoped record processor", Root: "/processor", Permissions: grants[:5]}}
	if _, err = s.Custody.DB.ChangeAccount(f.ctx, manager, "remove-execute", change); err != nil {
		t.Fatal(err)
	}
	if _, err = s.WorkProjection(f.ctx, actor, "work", attempt); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("revoked execution authority replayed work", err)
	}
}
