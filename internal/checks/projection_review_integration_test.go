//go:build integration

package checks

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

// These assertions require the ordinary, real PostgreSQL fixture and immutable
// storage. A compile-only check is not a pass and no substitute store is used.
func TestProjectionPreviewActualRetiredSourceAndNoPayloadOrEffects(t *testing.T) {
	f := setup(t)
	s, sourcePolicy, source := policyAndFile(t, f, goodCSV, true)
	definition := RecordProjection{Schema: 1, Kind: "record_projection", SourcePolicyHash: sourcePolicy.Hash, OutputKind: "csv", Columns: []ProjectionColumn{{Source: "account", Target: "account"}, {Source: "amount", Target: "amount"}, {Source: "day", Target: "day"}}}
	options := ProjectionOptions{TargetPath: "/generated.csv", Reason: "Review separately governed deterministic output", Definition: definition}
	if _, err := s.PreviewProjection(f.ctx, f.scope, source.ID, options); !errors.Is(err, store.ErrState) {
		t.Fatal("held unchecked source reviewed", err)
	}
	if _, err := s.Run(f.ctx, f.scope, source.ID, "source-proof"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PreviewProjection(f.ctx, f.scope, source.ID, options); err != nil {
		t.Fatal("passed held source unavailable to its authorized processor", err)
	}
	if _, err := s.Release(f.ctx, f.scope, source.ID, "source-release", releaseDecision(getCheck(t, s, f, source.ID))); err != nil {
		t.Fatal(err)
	}
	definition.OutputKind = "json_records"
	definition.Columns[1].Target = "total"
	definition, err := NormalizeRecordProjection(testPolicy(t), definition)
	if err != nil {
		t.Fatal(err)
	}
	output, err := projectionOutputPolicy(testPolicy(t), definition)
	if err != nil {
		t.Fatal(err)
	}
	registered, err := s.Register(f.ctx, f.scope, "output-policy", PolicyRequest{ExpectedVersion: sourcePolicy.Version, Definition: output})
	if err != nil {
		t.Fatal(err)
	}
	var current store.Configuration
	if json.Unmarshal(registered.Resource, &current) != nil {
		t.Fatal("output policy result")
	}
	options.TargetPath, options.Definition = "/generated.json", definition
	count := func() [4]int64 {
		t.Helper()
		var counts [4]int64
		if err := f.admin.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM events),(SELECT count(*) FROM files),(SELECT count(*) FROM file_checks),(SELECT count(*) FROM file_rechecks)`).Scan(&counts[0], &counts[1], &counts[2], &counts[3]); err != nil {
			t.Fatal(err)
		}
		return counts
	}
	before := count()
	first, err := s.PreviewProjection(f.ctx, f.scope, source.ID, options)
	if err != nil {
		t.Fatal(err)
	}
	if first.Plan.SourcePolicy.Hash != sourcePolicy.Hash || first.Plan.Context.Policy.Hash != current.Hash || first.Plan.Context.Source.Check.State != "released" || first.Plan.Context.Target.Command.Replace {
		t.Fatal("review lost original source or separate current output")
	}
	// A metadata review must not open even the original payload. Temporarily
	// move only this fixture's exact owned object,then restore it immediately.
	name := filepath.Join(f.diskPath, custody.Name(f.scope.Tenant, f.scope.Partner, source.ID))
	hidden := name + ".projection-preview-held"
	if err = os.Rename(name, hidden); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Rename(hidden, name); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Error(err)
		}
	}()
	second, err := s.PreviewProjection(f.ctx, f.scope, source.ID, options)
	if err != nil {
		t.Fatal("preview tried to consume payload", err)
	}
	_, a, _ := canonical(first.Plan)
	_, b, _ := canonical(second.Plan)
	if a != b || before != count() {
		t.Fatal("preview changed plan or durable state")
	}
	if err = os.Rename(hidden, name); err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.Custody.Download(f.ctx, f.scope, source.ID); err == nil {
		t.Fatal("processing review loosened ordinary retired-policy download")
	}
	options.TargetPath = "/checked.csv"
	if _, err = s.PreviewProjection(f.ctx, f.scope, source.ID, options); !errors.Is(err, ErrInput) {
		t.Fatal("projection allowed overwrite of its source", err)
	}
	if before != count() {
		t.Fatal("refused review persisted effects")
	}
}

func TestProjectionPreviewActualSignatureRequiresFreshOutputAndLiveSourceKey(t *testing.T) {
	f, s, key, source, wire := signedIntake(t, nil)
	c := getCheck(t, s, f, source.ID)
	if _, err := s.AttachSignature(f.ctx, f.scope, source.ID, "signature", source.SHA256, c.PolicyHash, c.Revision, wire); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Run(f.ctx, f.scope, source.ID, "source-proof"); err != nil {
		t.Fatal(err)
	}
	load, _ := pgpBundle(t)
	registered, err := s.RegisterPGPKey(f.ctx, f.scope, "independent-output-key", PGPKeyRequest{Fingerprint: key.Fingerprint, PublicKey: load("good-public.gpg")})
	if err != nil {
		t.Fatal(err)
	}
	var outputKey PGPKeyView
	if json.Unmarshal(registered.Resource, &outputKey) != nil {
		t.Fatal("new output key")
	}
	outputPolicy := testPolicy(t)
	outputPolicy.Signature = &SignaturePolicy{Key: store.PGPReference{ID: outputKey.ID, Version: outputKey.Version, Hash: outputKey.Hash}, MaxAgeSeconds: 3600}
	if _, err = s.Register(f.ctx, f.scope, "independent-output-policy", PolicyRequest{ExpectedVersion: 1, Definition: outputPolicy}); err != nil {
		t.Fatal(err)
	}
	options := ProjectionOptions{Reason: "Changing bytes requires a new detached signature", Definition: RecordProjection{Schema: 1, Kind: "record_projection", SourcePolicyHash: c.PolicyHash, OutputKind: "csv", Columns: []ProjectionColumn{{Source: "account", Target: "account"}, {Source: "amount", Target: "amount"}, {Source: "day", Target: "day"}}}}
	v, err := s.PreviewProjection(f.ctx, f.scope, source.ID, options)
	if err != nil || v.Plan.Context.SignatureMode != "require_new" || v.Plan.ProofValidUntil == nil {
		t.Fatal("source proof or fresh output signature binding lost", err)
	}
	if _, err = s.RevokePGPKey(f.ctx, f.scope, key.ID, key.Version, "revoke-source-key", workflow.Decision{Hash: key.Hash, Revision: key.Revision}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.PreviewProjection(f.ctx, f.scope, source.ID, options); !errors.Is(err, store.ErrState) {
		t.Fatal("revoked original signer accepted", err)
	}
}

func TestProjectionPreviewActualScannerKeepsCurrentProtectedConfiguration(t *testing.T) {
	f, s, profile, source, definition := scanFixture(t, "clean", time.Hour)
	if _, err := s.Run(f.ctx, f.scope, source.ID, "source-proof"); err != nil {
		t.Fatal(err)
	}
	c := getCheck(t, s, f, source.ID)
	registered, err := s.RegisterScanner(f.ctx, f.scope, "independent-output-scanner", ScannerRequest{Definition: definition})
	if err != nil {
		t.Fatal(err)
	}
	var outputScanner ScannerView
	if json.Unmarshal(registered.Resource, &outputScanner) != nil {
		t.Fatal("new output scanner")
	}
	outputPolicy := testPolicy(t)
	outputPolicy.Scanner = &store.ScannerReference{ID: outputScanner.ID, Version: outputScanner.Version, Hash: outputScanner.Hash}
	if _, err = s.Register(f.ctx, f.scope, "independent-output-policy", PolicyRequest{ExpectedVersion: 1, Definition: outputPolicy}); err != nil {
		t.Fatal(err)
	}
	options := ProjectionOptions{Reason: "Validate live scanner proof before processing", Definition: RecordProjection{Schema: 1, Kind: "record_projection", SourcePolicyHash: c.PolicyHash, OutputKind: "csv", Columns: []ProjectionColumn{{Source: "account", Target: "account"}, {Source: "amount", Target: "amount"}, {Source: "day", Target: "day"}}}}
	v, err := s.PreviewProjection(f.ctx, f.scope, source.ID, options)
	if err != nil || v.Plan.ProofValidUntil == nil || v.SourcePolicy.Definition.Scanner == nil || v.OutputPolicy.Definition.Scanner == nil {
		t.Fatal("clean source proof lost its scanner or expiry", err)
	}
	// Change only this fixture's protected file. Metadata may remain active;
	// its exact configured bytes must still match before a processing review.
	original, err := os.ReadFile(definition.Configuration)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(definition.Configuration, append(original, []byte("\n# changed after source proof\n")...), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = s.PreviewProjection(f.ctx, f.scope, source.ID, options); err == nil {
		t.Fatal("changed scanner configuration accepted")
	}
	if err = os.WriteFile(definition.Configuration, original, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = s.RevokeScanner(f.ctx, f.scope, profile.ID, profile.Version, "revoke-source-scanner", workflow.Decision{Hash: profile.Hash, Revision: profile.Revision}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.PreviewProjection(f.ctx, f.scope, source.ID, options); !errors.Is(err, store.ErrState) {
		t.Fatal("revoked source scanner accepted", err)
	}
}

func TestProjectionPreviewActualLiveAuthorityAndOwnership(t *testing.T) {
	f := setup(t)
	s, p, source := policyAndFile(t, f, goodCSV, false)
	if _, err := s.Run(f.ctx, f.scope, source.ID, "checked"); err != nil {
		t.Fatal(err)
	}
	options := ProjectionOptions{Reason: "Review only the explicitly authorized source", Definition: RecordProjection{Schema: 1, Kind: "record_projection", SourcePolicyHash: p.Hash, OutputKind: "csv", Columns: []ProjectionColumn{{Source: "account", Target: "account"}, {Source: "amount", Target: "amount"}, {Source: "day", Target: "day"}}}}
	grants := []string{"admin", "read", "write", "intake_manage", "check_run", "check_release"}
	for _, permissions := range [][]string{grants, grants[:5], {"read", "write"}} {
		command := store.AccountCommand{Operation: "create", ID: secure.NewID(), CredentialHash: secure.Digest([]byte(secure.NewID())), Policy: &store.AccountPolicy{Label: "Projection reviewer", Root: "/", Permissions: permissions}}
		if _, err := s.Custody.DB.ChangeAccount(f.ctx, f.scope, secure.NewID(), command); err != nil {
			t.Fatal(err)
		}
		other := store.Scope{Tenant: f.scope.Tenant, Partner: f.scope.Partner, TokenHash: command.CredentialHash}
		_, err := s.PreviewProjection(f.ctx, other, source.ID, options)
		if len(permissions) == len(grants) {
			if !errors.Is(err, store.ErrNotFound) {
				t.Fatal("different owner learned source proof", err)
			}
		} else if !errors.Is(err, store.ErrForbidden) {
			t.Fatal("review bypassed missing processing authority", err)
		}
	}
	if _, err := s.PreviewProjection(f.ctx, f.scope, source.ID, options); err != nil {
		t.Fatal("original processor lost authority", err)
	}
}
