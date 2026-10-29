package checks

import (
	"context"
	"encoding/json"
	"io"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/scanner"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

type ScannerRequest struct {
	ID              string             `json:"scanner_id,omitempty"`
	ExpectedVersion int                `json:"expected_version"`
	Definition      scanner.Definition `json:"definition"`
}
type ScannerView struct {
	ID                  string          `json:"id"`
	Version             int             `json:"version"`
	Hash                string          `json:"definition_hash"`
	State               string          `json:"state"`
	Revision            int64           `json:"revision"`
	Kind                string          `json:"kind"`
	Engine              scanner.Version `json:"expected_engine"`
	ConfigurationSHA256 string          `json:"configuration_sha256"`
	ValidUntil          time.Time       `json:"valid_until"`
	MaxBytes            int64           `json:"max_bytes"`
	TimeoutSeconds      int             `json:"timeout_seconds"`
	MaxResultAgeSeconds int             `json:"max_result_age_seconds"`
}
type ScanProof struct {
	Profile     store.ScannerReference `json:"profile"`
	Result      *scanner.Result        `json:"result"`
	StartedAt   time.Time              `json:"started_at"`
	CompletedAt time.Time              `json:"completed_at"`
	ValidUntil  time.Time              `json:"valid_until"`
}

func scannerView(p *store.ScannerProfile) (*ScannerView, error) {
	var d scanner.Definition
	if json.Unmarshal(p.Definition, &d) != nil {
		return nil, store.ErrState
	}
	version, err := scanner.ParseVersion(d.ExpectedVersion)
	if err != nil {
		return nil, store.ErrState
	}
	return &ScannerView{ID: p.ID, Version: p.Version, Hash: p.Hash, State: p.State, Revision: p.Revision, Kind: d.Kind, Engine: version, ConfigurationSHA256: d.ConfigurationSHA256, ValidUntil: p.ValidUntil.UTC(), MaxBytes: d.MaxBytes, TimeoutSeconds: d.TimeoutSeconds, MaxResultAgeSeconds: d.MaxResultAgeSeconds}, nil
}

// RegisterScanner is local configuration enrollment, like SSH connection
// enrollment. HTTP clients select registered references and cannot supply host
// filesystem/socket paths. Enrollment never starts or probes a scanner engine.
func (s *Service) RegisterScanner(ctx context.Context, scope store.Scope, key string, r ScannerRequest) (*Result, error) {
	if !keyPattern.MatchString(key) || r.ExpectedVersion < 0 || (r.ID != "" && (!store.ValidID(r.ID) || r.ExpectedVersion < 1)) || (r.ID == "" && r.ExpectedVersion != 0) {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.begin(ctx, scope, "admin", "scanner_manage")
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if t.Root != "/" {
		return nil, store.ErrForbidden
	}
	now, err := t.DatabaseTime(ctx)
	if err != nil {
		return nil, err
	}
	r.Definition.ValidUntil = r.Definition.ValidUntil.UTC().Truncate(time.Microsecond)
	if scanner.Validate(r.Definition, now) != nil || scanner.ConfigurationCurrent(ctx, r.Definition) != nil {
		return nil, ErrInput
	}
	data, hash, err := canonical(r.Definition)
	if err != nil {
		return nil, err
	}
	_, meaning, _ := canonical(struct {
		Kind    string
		Request ScannerRequest
	}{"register_scanner", r})
	prior, err := t.CheckReplay(ctx, key, meaning)
	if err != nil {
		return nil, err
	}
	if prior != nil {
		return &Result{Resource: prior, Replayed: true}, t.Tx.Commit(ctx)
	}
	id := r.ID
	if id == "" {
		id = secure.NewID()
	}
	version, err := t.ScannerProfileVersion(ctx, id)
	if err != nil {
		return nil, err
	}
	if version != r.ExpectedVersion {
		return nil, store.ErrRevision
	}
	p := &store.ScannerProfile{Configuration: store.Configuration{ID: id, Version: version + 1, Definition: data, Hash: hash, State: "active", Revision: 1}, ValidUntil: r.Definition.ValidUntil}
	if err = t.SaveScannerProfile(ctx, p, 0); err != nil {
		return nil, err
	}
	view, err := scannerView(p)
	if err != nil {
		return nil, err
	}
	return finish(ctx, t, key, meaning, id, view)
}
func (s *Service) Scanner(ctx context.Context, scope store.Scope, id string, version int) (*ScannerView, error) {
	t, err := s.begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if !t.Has("scanner_manage") && !t.Has("intake_manage") && !t.Has("check_run") && !t.Has("check_release") {
		return nil, store.ErrForbidden
	}
	p, err := t.ScannerProfile(ctx, id, version, false)
	if err != nil {
		return nil, err
	}
	view, err := scannerView(p)
	if err != nil {
		return nil, err
	}
	return view, t.Tx.Commit(ctx)
}
func (s *Service) RevokeScanner(ctx context.Context, scope store.Scope, id string, version int, key string, d workflow.Decision) (*Result, error) {
	if !keyPattern.MatchString(key) || !hashPattern.MatchString(d.Hash) || d.Revision < 1 {
		return nil, ErrInput
	}
	t, err := s.begin(ctx, scope, "admin", "scanner_manage")
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if t.Root != "/" {
		return nil, store.ErrForbidden
	}
	_, meaning, _ := canonical(struct {
		Kind, ID string
		Version  int
		Decision workflow.Decision
	}{"revoke_scanner", id, version, d})
	prior, err := t.CheckReplay(ctx, key, meaning)
	if err != nil {
		return nil, err
	}
	p, err := t.ScannerProfile(ctx, id, version, true)
	if err != nil {
		return nil, err
	}
	if prior != nil {
		return &Result{Resource: prior, Replayed: true}, t.Tx.Commit(ctx)
	}
	if p.Hash != d.Hash || p.Revision != d.Revision {
		return nil, store.ErrRevision
	}
	if p.State != "active" {
		return nil, store.ErrState
	}
	previous := p.Revision
	p.Revision++
	p.State = "revoked"
	if err = t.SaveScannerProfile(ctx, p, previous); err != nil {
		return nil, err
	}
	view, err := scannerView(p)
	if err != nil {
		return nil, err
	}
	return finish(ctx, t, key, meaning, id, view)
}

type scanSource struct {
	ctx    context.Context
	source io.Reader
	check  func() error
}

func (r scanSource) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if err := r.check(); err != nil {
		return 0, err
	}
	return r.source.Read(p)
}
func (s *Service) scan(ctx context.Context, scope store.Scope, c *store.FileCheck, b *store.CheckBinding, ref store.ScannerReference, a *Attempt) (*ScanProof, error) {
	t, err := s.begin(ctx, scope, "read", "check_run")
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	profile, now, err := t.CurrentScanner(ctx, ref)
	if err != nil {
		return nil, err
	}
	if err = t.Tx.Commit(ctx); err != nil {
		return nil, err
	}
	slot, release, err := s.Custody.DB.ScanWorkerSlot(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	check := func() error {
		if err := slot(); err != nil {
			return err
		}
		return s.check(ctx, scope, a)
	}
	source, err := s.Custody.Disk.VerifiedContext(ctx, custody.Name(scope.Tenant, scope.Partner, c.FileID), b.File.Size, b.File.SHA256)
	if err != nil {
		return nil, err
	}
	defer source.Close()
	result, err := scanner.Scan(ctx, *profile, now, scanSource{ctx: ctx, source: source, check: check}, b.File.Size, b.File.SHA256, check)
	if err != nil {
		return nil, err
	}
	end, err := s.begin(ctx, scope, "read", "check_run")
	if err != nil {
		return nil, err
	}
	defer end.Tx.Rollback(ctx)
	_, completed, err := end.CurrentScanner(ctx, ref)
	if err != nil {
		return nil, err
	}
	until := minTime(profile.ValidUntil, now.Add(time.Duration(profile.MaxResultAgeSeconds)*time.Second))
	if !completed.Before(until) {
		return nil, scanner.ErrUnavailable
	}
	if err = end.Tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &ScanProof{Profile: ref, Result: result, StartedAt: now, CompletedAt: completed, ValidUntil: until}, nil
}
func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
