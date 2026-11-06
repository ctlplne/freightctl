package checks

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/scanner"
	"github.com/ctlplne/freightctl/internal/store"
)

const ProjectionReviewProfile = "held-record-projection-v1"

// ProjectionOptions contains only declarative rules and a logical output path.
// It cannot select a host file, executable, recipient, model or scanner socket.
type ProjectionOptions struct {
	TargetPath string           `json:"target_path"`
	Reason     string           `json:"reason"`
	Definition RecordProjection `json:"definition"`
}

// ProjectionPlan is an immutable REVIEW binding, not execution authority. The
// durable intent compares this whole plan again before consequential effects.
type ProjectionPlan struct {
	Schema             int                       `json:"schema_version"`
	Profile            string                    `json:"profile"`
	Context            RecheckPlan               `json:"context"`
	SourcePolicy       store.OnboardingReference `json:"source_policy"`
	Projection         RecordProjection          `json:"projection"`
	OutputContractHash string                    `json:"output_contract_hash"`
	ProofValidUntil    *time.Time                `json:"source_proof_valid_until,omitempty"`
}

type ProjectionPreview struct {
	Plan         ProjectionPlan `json:"plan"`
	SourcePolicy RecheckPolicy  `json:"source_policy"`
	OutputPolicy RecheckPolicy  `json:"output_policy"`
	Effects      string         `json:"effects"`
}

func captureProjectionCheck(c *store.FileCheck, binding store.CheckBinding) *RecheckCheck {
	var lease *time.Time
	if c.LeaseUntil != nil {
		utc := c.LeaseUntil.UTC()
		lease = &utc
	}
	return &RecheckCheck{PolicyID: c.PolicyID, PolicyVersion: c.PolicyVersion, PolicyHash: c.PolicyHash, State: c.State, Revision: c.Revision, Attempts: c.Attempts, Code: c.Code, WorkerID: c.WorkerID, LeaseUntil: lease, ReportHash: c.ReportHash, Binding: binding}
}

// projectionSourceReport validates recorded proof without reading bytes. Live
// keys/scanner configuration are checked separately. Execution must STILL open
// and hash the exact immutable object and run the full source validator.
func projectionSourceReport(view *RecheckPreview, c *store.FileCheck, now time.Time) (Report, *time.Time, error) {
	fail := func() (Report, *time.Time, error) { return Report{}, nil, store.ErrState }
	if view == nil || c == nil || view.PreviousPolicy == nil || view.Plan.Source.Check == nil || now.IsZero() {
		return fail()
	}
	p := view.Plan
	old := view.PreviousPolicy
	if p.Root != "/" || p.Authority < 1 || !store.ValidID(p.StorageID) || !store.ValidID(c.FileID) || !store.ValidID(c.PolicyID) || c.PolicyVersion < 1 || c.FileID != p.Source.File.ID || p.Source.File.Size < 0 || p.Source.File.Size > old.Definition.MaxBytes || !hashPattern.MatchString(p.Source.File.SHA256) || c.Revision < 1 || c.Attempts < 1 || c.WorkerID != "" || c.LeaseUntil != nil || !hashPattern.MatchString(c.ReportHash) {
		return fail()
	}
	if !(c.State == "passed" && c.Code == policySuccess(old.Definition) || c.State == "released" && c.Code == "approved_for_publication") {
		return fail()
	}
	if old.State != "active" && old.State != "retired" || old.Reference != (store.OnboardingReference{ID: c.PolicyID, Version: c.PolicyVersion, Hash: c.PolicyHash}) {
		return fail()
	}
	data, hash, err := canonical(old.Definition)
	if err != nil || hash != c.PolicyHash {
		return fail()
	}
	filePolicy, err := store.IntakeFilePolicy(&store.Configuration{Definition: data, Hash: hash})
	if err != nil || filePolicy != p.Source.File.Policy {
		return fail()
	}
	var binding store.CheckBinding
	if json.Unmarshal(c.Binding, &binding) != nil || binding.File != p.Source.File || binding.Root != p.Root || binding.StorageID != p.StorageID || binding.Authority != p.Authority {
		return fail()
	}
	_, captured, _ := canonical(captureProjectionCheck(c, binding))
	_, approved, _ := canonical(p.Source.Check)
	if captured != approved {
		return fail()
	}
	// Reports are bounded control metadata. Never accept an arbitrary JSON value
	// as proof, or hash a subset that silently discards unknown fields.
	if len(c.Report) == 0 || len(c.Report) > 16<<10 {
		return fail()
	}
	var report Report
	decoder := json.NewDecoder(bytes.NewReader(c.Report))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&report) != nil || decoder.Decode(new(any)) != io.EOF {
		return fail()
	}
	_, reportHash, err := canonical(report)
	if err != nil || reportHash != c.ReportHash || report.Engine != policyEngine(old.Definition) || report.Code != policySuccess(old.Definition) || report.FileID != c.FileID || report.PolicyHash != c.PolicyHash || report.SHA256 != p.Source.File.SHA256 || report.Bytes != p.Source.File.Size || report.Rows < 0 || report.Rows > old.Definition.MaxRows || report.Row != 0 || report.Column != 0 {
		return fail()
	}
	var until *time.Time
	include := func(t time.Time) {
		if until == nil || t.Before(*until) {
			u := t.UTC()
			until = &u
		}
	}
	if (old.Definition.Signature != nil) != (report.Signature != nil) || (old.Definition.Scanner != nil) != (report.Scanner != nil) {
		return fail()
	}
	if policy := old.Definition.Signature; policy != nil {
		proof, attached := report.Signature, p.Source.Signature
		if proof.Verification == nil || attached == nil || attached.FileID != c.FileID || attached.StorageID != p.StorageID || attached.Size < 1 || attached.Size > secure.MaxPGPWire || !store.ValidID(attached.ObjectID) || !hashPattern.MatchString(attached.SHA256) || attached.DataSHA256 != p.Source.File.SHA256 || attached.PolicyHash != c.PolicyHash || attached.Key != policy.Key || proof.Key != attached.Key || proof.ObjectID != attached.ObjectID || proof.SHA256 != attached.SHA256 {
			return fail()
		}
		verified := proof.Verification
		if verified.Backend != secure.PGPBackend || verified.SignatureSHA256 != attached.SHA256 || verified.PrimaryFingerprint == "" || verified.SignerFingerprint == "" || verified.Hash == "" || verified.Created.IsZero() || verified.VerifiedAt.IsZero() || verified.Created.After(verified.VerifiedAt) || verified.VerifiedAt.After(now) || (verified.SignatureVersion != 4 && verified.SignatureVersion != 6) {
			return fail()
		}
		if policy.MaxAgeSeconds > 0 {
			maximum := verified.Created.Add(time.Duration(policy.MaxAgeSeconds) * time.Second)
			if verified.ValidUntil == nil || verified.ValidUntil.After(maximum) {
				return fail()
			}
		}
		if verified.ValidUntil != nil {
			if !now.Before(*verified.ValidUntil) {
				return fail()
			}
			include(*verified.ValidUntil)
		}
	}
	if policy := old.Definition.Scanner; policy != nil {
		proof := report.Scanner
		result := proof.Result
		if result == nil || proof.Profile != *policy || result.Backend != scanner.Backend || result.Verdict != "clean" || result.DetectionSHA256 != "" || result.SHA256 != p.Source.File.SHA256 || result.Bytes != p.Source.File.Size || !hashPattern.MatchString(result.VersionSHA256) || !hashPattern.MatchString(result.ConfigurationSHA256) || !hashPattern.MatchString(result.ResponseSHA256) || proof.StartedAt.IsZero() || proof.CompletedAt.IsZero() || proof.StartedAt.After(proof.CompletedAt) || proof.CompletedAt.After(now) || !proof.CompletedAt.Before(proof.ValidUntil) || !now.Before(proof.ValidUntil) {
			return fail()
		}
		include(proof.ValidUntil)
	}
	return report, until, nil
}

// projectionReview binds an already authorized metadata snapshot. Keeping this
// pure lets the same contract be exercised without opening payloads or runtimes.
func projectionReview(base *RecheckPreview, row *store.FileCheck, definition RecordProjection, now time.Time) (*ProjectionPreview, error) {
	_, until, err := projectionSourceReport(base, row, now)
	if err != nil {
		return nil, err
	}
	// Own every slice/pointer in the returned review; a caller editing an input
	// must not change what was displayed or subsequently signed off.
	wire, _, err := canonical(base)
	if err != nil {
		return nil, err
	}
	var snapshot RecheckPreview
	if json.Unmarshal(wire, &snapshot) != nil {
		return nil, store.ErrState
	}
	source, err := Normalize(snapshot.PreviousPolicy.Definition)
	if err != nil {
		return nil, err
	}
	output, err := Normalize(snapshot.CurrentPolicy.Definition)
	if err != nil {
		return nil, err
	}
	_, outputHash, _ := canonical(output)
	if snapshot.CurrentPolicy.State != "active" || snapshot.Plan.Policy != snapshot.CurrentPolicy.Reference || snapshot.Plan.Policy.Hash != outputHash {
		return nil, store.ErrRevision
	}
	if source.Signature != nil && (output.Signature == nil || source.Signature.MaxAgeSeconds > 0 && (output.Signature.MaxAgeSeconds == 0 || output.Signature.MaxAgeSeconds > source.Signature.MaxAgeSeconds)) || source.Scanner != nil && output.Scanner == nil {
		return nil, ErrInput
	}
	mode := "not_required"
	if output.Signature != nil {
		mode = "require_new"
	}
	if snapshot.Plan.SignatureMode != mode {
		return nil, ErrInput
	}
	if target := snapshot.Plan.Target; target != nil && (target.Command.Operation != "publish" || target.Command.Replace || target.Command.FileID != "" || target.Command.ExpectedRevision != nil || target.EntryID != "" || target.EntryRevision != 0) {
		return nil, ErrInput
	}
	definition, err = NormalizeRecordProjection(source, definition)
	if err != nil {
		return nil, err
	}
	expected, err := projectionOutputPolicy(source, definition)
	if err != nil {
		return nil, err
	}
	_, contractHash, _ := canonical(expected)
	shape := output
	shape.Signature, shape.Scanner = nil, nil
	_, selectedHash, _ := canonical(shape)
	if selectedHash != contractHash {
		return nil, ErrInput
	}
	return &ProjectionPreview{Plan: ProjectionPlan{Schema: 1, Profile: ProjectionReviewProfile, Context: snapshot.Plan, SourcePolicy: snapshot.PreviousPolicy.Reference, Projection: definition, OutputContractHash: contractHash, ProofValidUntil: until}, SourcePolicy: *snapshot.PreviousPolicy, OutputPolicy: snapshot.CurrentPolicy, Effects: "Review only. Execution needs a separately approved durable intent. The transformed output will be a new held artifact with fresh checks, a new signature when required and a separate exact release. No forwarding or execution permission is inherited."}, nil
}

func projectionProtectionCurrent(ctx context.Context, t *store.Transaction, policy Policy, report Report) error {
	if policy.Signature != nil {
		key, _, err := keyCurrent(ctx, t, policy.Signature)
		if err != nil {
			return err
		}
		if report.Signature.Verification.PrimaryFingerprint != key.Fingerprint {
			return store.ErrState
		}
	}
	if policy.Scanner != nil {
		profile, _, err := t.CurrentScanner(ctx, *policy.Scanner)
		if err != nil {
			return err
		}
		proof := report.Scanner
		version, err := scanner.ParseVersion(profile.ExpectedVersion)
		if err != nil || proof.Result.Version != version || proof.Result.VersionSHA256 != secure.Digest([]byte(profile.ExpectedVersion)) || proof.Result.ConfigurationSHA256 != profile.ConfigurationSHA256 || !proof.ValidUntil.Equal(minTime(profile.ValidUntil, proof.StartedAt.Add(time.Duration(profile.MaxResultAgeSeconds)*time.Second))) {
			return store.ErrState
		}
		if err = scanner.ConfigurationCurrent(ctx, *profile); err != nil {
			return err
		}
	}
	return nil
}

// Reject absent/null or structurally unqualified requests before any database
// access. Mapping and budget normalization still require the actual source.
func projectionOptionsInput(options ProjectionOptions) (ProjectionOptions, error) {
	reason, err := recheckReason(options.Reason)
	if err != nil {
		return options, err
	}
	d := options.Definition
	if d.Schema != 1 || d.Kind != "record_projection" || d.Engine != "" && d.Engine != ProjectionEngine || !hashPattern.MatchString(d.SourcePolicyHash) || (d.OutputKind != "csv" && d.OutputKind != "json_records") || len(d.Columns) < 1 || len(d.Columns) > 128 {
		return options, ErrInput
	}
	options.Reason = reason
	return options, nil
}

// projectionPlan is restricted to root administrators with the existing read,
// write, intake, check and release grants. A retired source contract may be used
// only for this explicitly authorized processing review. Ordinary availability
// and downloads keep their current-policy requirement unchanged.
func (s *Service) projectionPlan(ctx context.Context, t *store.Transaction, id string, options ProjectionOptions, lockSource bool) (*ProjectionPreview, error) {
	// Match release/recheck ordering: namespace, source check, then policy/key
	// locks. Holding policy first while waiting for a check can deadlock a
	// concurrent release behind a policy activation.
	if lockSource {
		if _, err := t.FileCheck(ctx, id, true); err != nil {
			return nil, err
		}
	}
	selected, err := t.IntakePolicy(ctx, false)
	if err != nil {
		return nil, err
	}
	if selected == nil || selected.State != "active" {
		return nil, store.ErrState
	}
	output, err := decodePolicy(selected)
	if err != nil {
		return nil, err
	}
	mode := "not_required"
	if output.Signature != nil {
		mode = "require_new"
	}
	base, err := s.recheckPlan(ctx, t, id, RecheckOptions{TargetPath: options.TargetPath, SignatureMode: mode, Reason: options.Reason}, lockSource)
	if err != nil {
		return nil, err
	}
	row, err := t.FileCheck(ctx, id, lockSource)
	if err != nil {
		return nil, err
	}
	now, err := t.DatabaseTime(ctx)
	if err != nil {
		return nil, err
	}
	view, err := projectionReview(base, row, options.Definition, now)
	if err != nil {
		return nil, err
	}
	report, _, err := projectionSourceReport(base, row, now)
	if err != nil {
		return nil, err
	}
	if err = projectionProtectionCurrent(ctx, t, view.SourcePolicy.Definition, report); err != nil {
		return nil, err
	}
	return view, t.Reauthorize(ctx)
}

// PreviewProjection touches control metadata and protected configuration only.
// It creates no intent, custody object, check, release, transfer or model call.
func (s *Service) PreviewProjection(ctx context.Context, scope store.Scope, id string, options ProjectionOptions) (*ProjectionPreview, error) {
	options, err := projectionOptionsInput(options)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.recheckBegin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if err = t.NamespaceLock(ctx); err != nil {
		return nil, err
	}
	view, err := s.projectionPlan(ctx, t, id, options, false)
	if err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return view, t.Tx.Commit(ctx)
}
