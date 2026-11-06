package checks

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/scanner"
	"github.com/ctlplne/freightctl/internal/store"
)

func projectionReviewFixture(t *testing.T) (*RecheckPreview, *store.FileCheck, RecordProjection, time.Time) {
	t.Helper()
	source, definition := projectionContract(t)
	definition, err := NormalizeRecordProjection(source, definition)
	if err != nil {
		t.Fatal(err)
	}
	output, err := projectionOutputPolicy(source, definition)
	if err != nil {
		t.Fatal(err)
	}
	_, sourceHash, _ := canonical(source)
	_, outputHash, _ := canonical(output)
	ref := store.OnboardingReference{ID: "11111111-1111-4111-8111-111111111111", Version: 1, Hash: sourceHash}
	file := recordSource([]byte(projectionInput))
	file.Policy = store.JSONRecordsIntakePrefix + sourceHash
	binding := store.CheckBinding{File: file, StorageID: ref.ID, Root: "/", Authority: 7}
	wire, _, _ := canonical(binding)
	report := Report{Engine: policyEngine(source), FileID: file.ID, SHA256: file.SHA256, PolicyHash: sourceHash, Code: policySuccess(source), Rows: 3, Bytes: file.Size}
	raw, hash, _ := canonical(report)
	row := &store.FileCheck{FileID: file.ID, PolicyID: ref.ID, PolicyVersion: 1, PolicyHash: sourceHash, Binding: wire, State: "passed", Revision: 3, Attempts: 1, Code: report.Code, Report: raw, ReportHash: hash}
	view := &RecheckPreview{Plan: RecheckPlan{Source: RecheckSource{File: file, Check: captureProjectionCheck(row, binding)}, Policy: store.OnboardingReference{ID: ref.ID, Version: 2, Hash: outputHash}, Root: "/", Authority: 7, StorageID: ref.ID, SignatureMode: "not_required", Reason: "Map exact approved records"}, PreviousPolicy: &RecheckPolicy{Reference: ref, State: "retired", Definition: source}, CurrentPolicy: RecheckPolicy{Reference: store.OnboardingReference{ID: ref.ID, Version: 2, Hash: outputHash}, State: "active", Definition: output}}
	return view, row, definition, time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
}

func TestProjectionReviewBindsImmutableSourceAndSeparateOutputPolicy(t *testing.T) {
	view, row, definition, now := projectionReviewFixture(t)
	got, err := projectionReview(view, row, definition, now)
	if err != nil {
		t.Fatal(err)
	}
	if got.Plan.Schema != 1 || got.Plan.Profile != ProjectionReviewProfile || got.Plan.SourcePolicy != view.PreviousPolicy.Reference || got.Plan.Context.Policy != view.CurrentPolicy.Reference || got.Plan.Context.SignatureMode != "not_required" || got.Plan.Projection.Engine != ProjectionEngine || got.Plan.ProofValidUntil != nil || got.Plan.OutputContractHash != view.CurrentPolicy.Reference.Hash {
		t.Fatal("review lost source or independent output binding")
	}
	first, hash, _ := canonical(got.Plan)
	again, err := projectionReview(view, row, definition, now.Add(time.Second))
	_, next, _ := canonical(again.Plan)
	if err != nil || hash != next {
		t.Fatal("wall clock changed an otherwise identical review", err)
	}
	definition.Columns[0].Target = "changed_after_review"
	view.Plan.Source.Check.ReportHash = strings.Repeat("a", 64)
	view.PreviousPolicy.Definition.Columns[0].Name = "changed_source"
	last, _, _ := canonical(got.Plan)
	if string(first) != string(last) {
		t.Fatal("caller changed the reviewed immutable plan")
	}
	if strings.Contains(string(first), "12345678901234567890.12") || strings.Contains(string(first), projectionInput) {
		t.Fatal("review includes payload content")
	}
}

func TestProjectionReviewRequiresEachSourceFormatsOwnProofIdentity(t *testing.T) {
	jsonPolicy, _ := projectionContract(t)
	for _, source := range []Policy{testPolicy(t), jsonPolicy, fixedWidthPolicy(t), xmlRecordsPolicy(t), xlsxIntakePolicy(t)} {
		t.Run(source.Kind, func(t *testing.T) {
			v, c, d, n := projectionReviewFixture(t)
			var err error
			source, err = Normalize(source)
			if err != nil {
				t.Fatal(err)
			}
			data, hash, _ := canonical(source)
			v.PreviousPolicy.Definition = source
			v.PreviousPolicy.Reference.Hash = hash
			v.Plan.Source.File.Policy, err = store.IntakeFilePolicy(&store.Configuration{Definition: data, Hash: hash})
			if err != nil {
				t.Fatal(err)
			}
			c.PolicyHash = hash
			v.Plan.Source.Check.PolicyHash = hash
			v.Plan.Source.Check.Binding.File = v.Plan.Source.File
			c.Binding, _, _ = canonical(v.Plan.Source.Check.Binding)
			d.SourcePolicyHash = hash
			d.Columns = nil
			for _, column := range source.Columns {
				d.Columns = append(d.Columns, ProjectionColumn{Source: column.Name, Target: column.Name})
			}
			d, err = NormalizeRecordProjection(source, d)
			if err != nil {
				t.Fatal(err)
			}
			output, err := projectionOutputPolicy(source, d)
			if err != nil {
				t.Fatal(err)
			}
			_, outputHash, _ := canonical(output)
			v.CurrentPolicy.Definition = output
			v.CurrentPolicy.Reference.Hash = outputHash
			v.Plan.Policy.Hash = outputHash
			r := Report{Engine: policyEngine(source), FileID: c.FileID, SHA256: v.Plan.Source.File.SHA256, PolicyHash: hash, Code: policySuccess(source), Rows: 1, Bytes: v.Plan.Source.File.Size}
			c.Code = r.Code
			v.Plan.Source.Check.Code = r.Code
			c.Report, c.ReportHash, _ = canonical(r)
			v.Plan.Source.Check.ReportHash = c.ReportHash
			if _, err = projectionReview(v, c, d, n); err != nil {
				t.Fatal("exact format-specific metadata proof refused", err)
			}
			r.Engine = "unqualified-common-parser"
			c.Report, c.ReportHash, _ = canonical(r)
			v.Plan.Source.Check.ReportHash = c.ReportHash
			if _, err = projectionReview(v, c, d, n); err == nil {
				t.Fatal("invented common proof bypassed format identity")
			}
		})
	}
}

func TestProjectionReviewRefusesUnverifiedStaleOrInventedSource(t *testing.T) {
	mutations := map[string]func(*RecheckPreview, *store.FileCheck){
		"no source check":    func(v *RecheckPreview, c *store.FileCheck) { v.Plan.Source.Check = nil },
		"no source contract": func(v *RecheckPreview, c *store.FileCheck) { v.PreviousPolicy = nil },
		"integrity only":     func(v *RecheckPreview, c *store.FileCheck) { v.Plan.Source.File.Policy = "integrity-only-v1" },
		"held":               func(v *RecheckPreview, c *store.FileCheck) { c.State = "held" },
		"rejected":           func(v *RecheckPreview, c *store.FileCheck) { c.State = "rejected" },
		"live worker":        func(v *RecheckPreview, c *store.FileCheck) { c.WorkerID = v.Plan.StorageID },
		"lease":              func(v *RecheckPreview, c *store.FileCheck) { n := time.Now(); c.LeaseUntil = &n },
		"stale report":       func(v *RecheckPreview, c *store.FileCheck) { c.ReportHash = strings.Repeat("a", 64) },
		"changed source":     func(v *RecheckPreview, c *store.FileCheck) { v.Plan.Source.File.Size++ },
		"changed authority":  func(v *RecheckPreview, c *store.FileCheck) { v.Plan.Authority++ },
		"wrong root":         func(v *RecheckPreview, c *store.FileCheck) { v.Plan.Root = "/other" },
		"wrong storage":      func(v *RecheckPreview, c *store.FileCheck) { v.Plan.StorageID = "22222222-2222-4222-8222-222222222222" },
		"overwrite": func(v *RecheckPreview, c *store.FileCheck) {
			v.Plan.Target = &RecheckTarget{Command: store.PathCommand{Operation: "publish", Path: "/source", Replace: true}}
		},
		"reuse signature":        func(v *RecheckPreview, c *store.FileCheck) { v.Plan.SignatureMode = "reuse_exact" },
		"inactive output":        func(v *RecheckPreview, c *store.FileCheck) { v.CurrentPolicy.State = "retired" },
		"changed output shape":   func(v *RecheckPreview, c *store.FileCheck) { v.CurrentPolicy.Definition.Columns[0].Name = "other" },
		"wrong source reference": func(v *RecheckPreview, c *store.FileCheck) { v.PreviousPolicy.Reference.Version++ },
		"forged engine": func(v *RecheckPreview, c *store.FileCheck) {
			var r Report
			_ = json.Unmarshal(c.Report, &r)
			r.Engine = "pretend"
			c.Report, c.ReportHash, _ = canonical(r)
			v.Plan.Source.Check.ReportHash = c.ReportHash
		},
		"incomplete bytes": func(v *RecheckPreview, c *store.FileCheck) {
			var r Report
			_ = json.Unmarshal(c.Report, &r)
			r.Bytes--
			c.Report, c.ReportHash, _ = canonical(r)
			v.Plan.Source.Check.ReportHash = c.ReportHash
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			v, c, d, n := projectionReviewFixture(t)
			mutate(v, c)
			if _, err := projectionReview(v, c, d, n); err == nil {
				t.Fatal("unqualified source or changed meaning reviewed")
			}
		})
	}
	v, c, d, n := projectionReviewFixture(t)
	c.State, c.Code = "released", "approved_for_publication"
	v.Plan.Source.Check.State, v.Plan.Source.Check.Code = c.State, c.Code
	if _, err := projectionReview(v, c, d, n); err != nil {
		t.Fatal("exact released source refused", err)
	}
}

func TestProjectionReviewProtectedProofRequiresExactFreshBindings(t *testing.T) {
	v, c, d, now := projectionReviewFixture(t)
	key := store.PGPReference{ID: v.Plan.StorageID, Version: 1, Hash: strings.Repeat("b", 64)}
	profile := store.ScannerReference{ID: v.Plan.StorageID, Version: 1, Hash: strings.Repeat("c", 64)}
	v.PreviousPolicy.Definition.Signature = &SignaturePolicy{Key: key, MaxAgeSeconds: 120}
	v.PreviousPolicy.Definition.Scanner = &profile
	v.CurrentPolicy.Definition.Signature = &SignaturePolicy{Key: key, MaxAgeSeconds: 60}
	v.CurrentPolicy.Definition.Scanner = &profile
	v.Plan.SignatureMode = "require_new"
	// Rebind the entire source and output after adding their protected policies.
	_, sourceHash, _ := canonical(v.PreviousPolicy.Definition)
	_, outputHash, _ := canonical(v.CurrentPolicy.Definition)
	v.PreviousPolicy.Reference.Hash = sourceHash
	v.CurrentPolicy.Reference.Hash = outputHash
	v.Plan.Policy.Hash = outputHash
	c.PolicyHash = sourceHash
	v.Plan.Source.Check.PolicyHash = sourceHash
	v.Plan.Source.File.Policy = store.JSONRecordsIntakePrefix + sourceHash
	v.Plan.Source.Check.Binding.File = v.Plan.Source.File
	c.Binding, _, _ = canonical(v.Plan.Source.Check.Binding)
	d.SourcePolicyHash = sourceHash
	until := now.Add(45 * time.Second)
	sig := &store.FileSignature{FileID: c.FileID, ObjectID: "33333333-3333-4333-8333-333333333333", StorageID: v.Plan.StorageID, Size: 10, SHA256: strings.Repeat("d", 64), DataSHA256: v.Plan.Source.File.SHA256, PolicyHash: sourceHash, Key: key}
	v.Plan.Source.Signature = sig
	var r Report
	_ = json.Unmarshal(c.Report, &r)
	r.PolicyHash = sourceHash
	r.Signature = &SignatureProof{Key: key, ObjectID: sig.ObjectID, SHA256: sig.SHA256, Verification: &secure.PGPVerification{Backend: secure.PGPBackend, PrimaryFingerprint: strings.Repeat("1", 40), SignerFingerprint: strings.Repeat("1", 40), SignatureSHA256: sig.SHA256, Hash: "SHA-256", SignatureVersion: 4, Created: now.Add(-time.Second), VerifiedAt: now.Add(-time.Second), ValidUntil: &until}}
	r.Scanner = &ScanProof{Profile: profile, Result: &scanner.Result{Backend: scanner.Backend, Verdict: "clean", SHA256: r.SHA256, Bytes: r.Bytes, VersionSHA256: strings.Repeat("e", 64), ConfigurationSHA256: strings.Repeat("f", 64), ResponseSHA256: strings.Repeat("a", 64)}, StartedAt: now.Add(-2 * time.Second), CompletedAt: now.Add(-time.Second), ValidUntil: now.Add(30 * time.Second)}
	refresh := func() { c.Report, c.ReportHash, _ = canonical(r); v.Plan.Source.Check.ReportHash = c.ReportHash }
	refresh()
	got, err := projectionReview(v, c, d, now)
	if err != nil || got.Plan.ProofValidUntil == nil || !got.Plan.ProofValidUntil.Equal(r.Scanner.ValidUntil) {
		t.Fatal("exact protected source refused or expiry lost", err)
	}
	for _, mutate := range []func(){func() { r.Scanner.Result.Verdict = "unknown" }, func() { r.Scanner.Result.SHA256 = strings.Repeat("a", 64) }, func() { r.Scanner.ValidUntil = now }, func() { r.Signature.Verification.SignatureSHA256 = strings.Repeat("a", 64) }, func() { r.Signature.Verification.ValidUntil = &now }, func() { r.Signature.Verification.Created = now.Add(time.Second) }} {
		copy, _ := json.Marshal(r)
		mutate()
		refresh()
		if _, err := projectionReview(v, c, d, now); !errors.Is(err, store.ErrState) {
			t.Fatal("untrusted proof passed", err)
		}
		_ = json.Unmarshal(copy, &r)
	}
	refresh()
	v.CurrentPolicy.Definition.Scanner = nil
	if _, err = projectionReview(v, c, d, now); err == nil {
		t.Fatal("scanner protection silently removed")
	}
}
