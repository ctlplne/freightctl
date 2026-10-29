package checks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/scanner"
	"github.com/ctlplne/freightctl/internal/store"
)

type Service struct{ Custody *custody.Service }
type Result struct {
	Resource json.RawMessage `json:"resource"`
	Replayed bool            `json:"replayed"`
}
type View struct {
	Check        *store.FileCheck     `json:"check"`
	Current      bool                 `json:"current"`
	Signature    *store.FileSignature `json:"signature,omitempty"`
	Requirements *Requirements        `json:"requirements,omitempty"`
}

type Requirements struct {
	Signature bool `json:"signature_required"`
	Scanner   bool `json:"scanner_required"`
}

type Summary struct {
	FileID   string `json:"file_id"`
	State    string `json:"state"`
	Revision int64  `json:"revision"`
	Code     string `json:"code"`
	Path     string `json:"path,omitempty"`
}
type Page struct {
	Checks []Summary `json:"checks"`
	Next   string    `json:"next,omitempty"`
}

func (s *Service) List(ctx context.Context, scope store.Scope, after string, limit int) (*Page, error) {
	if (after != "" && !store.ValidID(after)) || limit < 1 || limit > 100 {
		return nil, ErrInput
	}
	t, err := s.begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if !t.Has("write") && !t.Has("check_run") && !t.Has("check_release") {
		return nil, store.ErrForbidden
	}
	rows, err := t.Tx.Query(ctx, `SELECT file_id::text,state,revision,code,CASE WHEN binding->>'authority_revision'=$1 THEN coalesce(binding->'target'->>'path','') ELSE '' END FROM file_checks WHERE actor_id=$2 AND binding->>'namespace_root'=$3 AND ($4='' OR file_id>nullif($4,'')::uuid) ORDER BY file_id LIMIT $5`, fmt.Sprint(t.AuthorityRevision), t.Actor, t.Root, after, limit+1)
	if err != nil {
		return nil, err
	}
	page := &Page{Checks: make([]Summary, 0)}
	for rows.Next() {
		var item Summary
		if err = rows.Scan(&item.FileID, &item.State, &item.Revision, &item.Code, &item.Path); err != nil {
			rows.Close()
			return nil, err
		}
		page.Checks = append(page.Checks, item)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if len(page.Checks) > limit {
		page.Checks = page.Checks[:limit]
		page.Next = page.Checks[limit-1].FileID
	}
	return page, t.Tx.Commit(ctx)
}

type PolicyDecision struct {
	Hash     string `json:"definition_hash"`
	Version  int    `json:"expected_version"`
	Revision int64  `json:"expected_revision"`
}
type ReleaseDecision struct {
	SHA256     string `json:"sha256"`
	PolicyHash string `json:"policy_hash"`
	ReportHash string `json:"report_hash"`
	Revision   int64  `json:"expected_revision"`
}
type Attempt struct {
	FileID   string `json:"file_id"`
	Number   int    `json:"attempt"`
	WorkerID string `json:"worker_id"`
}

func canonical(v any) (json.RawMessage, string, error) {
	b, e := json.Marshal(v)
	return b, secure.Digest(b), e
}
func (s *Service) begin(ctx context.Context, scope store.Scope, grants ...string) (*store.Transaction, error) {
	t, err := s.Custody.DB.Begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	for _, g := range grants {
		if err = t.Require(g); err != nil {
			_ = t.Tx.Rollback(ctx)
			return nil, err
		}
	}
	return t, nil
}
func finish(ctx context.Context, t *store.Transaction, key, meaning, id string, v any) (*Result, error) {
	data, _, err := canonical(v)
	if err != nil {
		return nil, err
	}
	if err = t.CheckReceipt(ctx, key, meaning, id, v); err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return &Result{Resource: data}, t.Tx.Commit(ctx)
}
func decodePolicy(p *store.Configuration) (Policy, error) {
	var definition Policy
	if json.Unmarshal(p.Definition, &definition) != nil {
		return definition, store.ErrState
	}
	definition, err := Normalize(definition)
	if err != nil {
		return definition, store.ErrState
	}
	_, hash, err := canonical(definition)
	if err != nil || hash != p.Hash {
		return definition, store.ErrState
	}
	return definition, nil
}
func (s *Service) Policy(ctx context.Context, scope store.Scope) (*store.Configuration, error) {
	t, err := s.begin(ctx, scope, "intake_manage")
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if t.Root != "/" {
		return nil, store.ErrForbidden
	}
	p, err := t.IntakePolicy(ctx, false)
	if err != nil {
		return nil, err
	}
	return p, t.Tx.Commit(ctx)
}
func (s *Service) Register(ctx context.Context, scope store.Scope, key string, r PolicyRequest) (*Result, error) {
	if !keyPattern.MatchString(key) || r.ExpectedVersion < 0 {
		return nil, ErrInput
	}
	definition, err := Normalize(r.Definition)
	if err != nil {
		return nil, err
	}
	r.Definition = definition
	t, err := s.begin(ctx, scope, "admin", "intake_manage")
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if t.Root != "/" {
		return nil, store.ErrForbidden
	}
	_, meaning, _ := canonical(struct {
		Kind    string
		Request PolicyRequest
	}{"register_intake", r})
	data, err := t.CheckReplay(ctx, key, meaning)
	if err != nil {
		return nil, err
	}
	p, err := t.IntakePolicy(ctx, true)
	if err != nil {
		return nil, err
	}
	if data != nil {
		return &Result{Resource: data, Replayed: true}, t.Tx.Commit(ctx)
	}
	version := 0
	id := secure.NewID()
	if p != nil {
		version = p.Version
		id = p.ID
	}
	if version != r.ExpectedVersion {
		return nil, store.ErrRevision
	}
	if definition.Signature != nil {
		if _, _, err = keyCurrent(ctx, t, definition.Signature); err != nil {
			return nil, err
		}
	}
	if definition.Scanner != nil {
		if _, _, err = t.CurrentScanner(ctx, *definition.Scanner); err != nil {
			return nil, err
		}
	}
	if p != nil && p.State == "active" {
		previous := p.Revision
		p.Revision++
		p.State = "retired"
		if err = t.SaveIntakePolicy(ctx, p, previous); err != nil {
			return nil, err
		}
	}
	encoded, hash, err := canonical(definition)
	if err != nil {
		return nil, err
	}
	next := &store.Configuration{ID: id, Version: version + 1, Definition: encoded, Hash: hash, State: "active", Revision: 1}
	if err = t.SaveIntakePolicy(ctx, next, 0); err != nil {
		return nil, err
	}
	return finish(ctx, t, key, meaning, id, next)
}
func (s *Service) Revoke(ctx context.Context, scope store.Scope, key string, d PolicyDecision) (*Result, error) {
	if !keyPattern.MatchString(key) || !hashPattern.MatchString(d.Hash) || d.Version < 1 || d.Revision < 1 {
		return nil, ErrInput
	}
	t, err := s.begin(ctx, scope, "admin", "intake_manage")
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if t.Root != "/" {
		return nil, store.ErrForbidden
	}
	_, meaning, _ := canonical(struct {
		Kind     string
		Decision PolicyDecision
	}{"revoke_intake", d})
	data, err := t.CheckReplay(ctx, key, meaning)
	if err != nil {
		return nil, err
	}
	p, err := t.IntakePolicy(ctx, true)
	if err != nil {
		return nil, err
	}
	if data != nil {
		return &Result{Resource: data, Replayed: true}, t.Tx.Commit(ctx)
	}
	if p == nil || p.Version != d.Version || p.Hash != d.Hash || p.Revision != d.Revision {
		return nil, store.ErrRevision
	}
	if p.State != "active" {
		return nil, store.ErrState
	}
	previous := p.Revision
	p.Revision++
	p.State = "revoked"
	if err = t.SaveIntakePolicy(ctx, p, previous); err != nil {
		return nil, err
	}
	return finish(ctx, t, key, meaning, p.ID, p)
}
func (s *Service) current(ctx context.Context, t *store.Transaction, c *store.FileCheck) (*store.CheckBinding, *store.Configuration, error) {
	if s.Custody.Disk == nil {
		return nil, nil, store.ErrState
	}
	b, err := t.CheckBindingCurrent(ctx, c, s.Custody.Disk.Identity())
	if err != nil {
		return nil, nil, err
	}
	p, err := t.IntakePolicy(ctx, false)
	if err != nil {
		return nil, nil, err
	}
	definition, err := decodePolicy(p)
	if err != nil {
		return nil, nil, err
	}
	if definition.Signature != nil {
		if _, _, err = keyCurrent(ctx, t, definition.Signature); err != nil {
			return nil, nil, err
		}
	}
	if definition.Scanner != nil {
		if _, _, err = t.CurrentScanner(ctx, *definition.Scanner); err != nil {
			return nil, nil, err
		}
	}
	return b, p, nil
}
func (s *Service) Get(ctx context.Context, scope store.Scope, id string) (*View, error) {
	t, err := s.begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if !t.Has("write") && !t.Has("check_run") && !t.Has("check_release") {
		return nil, store.ErrForbidden
	}
	c, err := t.FileCheck(ctx, id, false)
	if err != nil {
		return nil, err
	}
	_, policy, currentErr := s.current(ctx, t, c)
	if currentErr != nil && !errors.Is(currentErr, store.ErrRevision) && !errors.Is(currentErr, store.ErrState) {
		return nil, currentErr
	}
	signature, err := t.FileSignature(ctx, id)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	var requirements *Requirements
	if currentErr == nil {
		definition, err := decodePolicy(policy)
		if err != nil {
			return nil, err
		}
		requirements = &Requirements{Signature: definition.Signature != nil, Scanner: definition.Scanner != nil}
	}
	return &View{Check: c, Current: currentErr == nil, Signature: signature, Requirements: requirements}, t.Tx.Commit(ctx)
}
func (s *Service) start(ctx context.Context, scope store.Scope, id, key string) (*store.FileCheck, *store.CheckBinding, Policy, *Attempt, bool, error) {
	var policy Policy
	t, err := s.begin(ctx, scope, "read", "check_run")
	if err != nil {
		return nil, nil, policy, nil, false, err
	}
	defer t.Tx.Rollback(ctx)
	_, meaning, _ := canonical(struct{ Kind, ID string }{"check_attempt", id})
	data, err := t.CheckReplay(ctx, key, meaning)
	if err != nil {
		return nil, nil, policy, nil, false, err
	}
	c, err := t.FileCheck(ctx, id, true)
	if err != nil {
		return nil, nil, policy, nil, false, err
	}
	b, p, err := s.current(ctx, t, c)
	if err != nil {
		return nil, nil, policy, nil, false, err
	}
	policy, err = decodePolicy(p)
	if err != nil {
		return nil, nil, policy, nil, false, err
	}
	if policy.Signature != nil {
		signature, err := t.FileSignature(ctx, id)
		if errors.Is(err, store.ErrNotFound) {
			return nil, nil, policy, nil, false, store.ErrState
		}
		if err != nil {
			return nil, nil, policy, nil, false, err
		}
		if signature.Key != policy.Signature.Key || signature.DataSHA256 != b.File.SHA256 || signature.PolicyHash != c.PolicyHash || signature.StorageID != b.StorageID {
			return nil, nil, policy, nil, false, store.ErrState
		}
	}
	if data != nil {
		var a Attempt
		if json.Unmarshal(data, &a) != nil {
			return nil, nil, policy, nil, false, store.ErrState
		}
		return c, b, policy, &a, true, t.Tx.Commit(ctx)
	}
	now, err := t.DatabaseTime(ctx)
	if err != nil {
		return nil, nil, policy, nil, false, err
	}
	expired := c.State == "running" && c.LeaseUntil != nil && !c.LeaseUntil.After(now)
	if c.State != "held" && c.State != "failed" && !expired {
		return nil, nil, policy, nil, false, store.ErrState
	}
	if c.Attempts >= 3 {
		return nil, nil, policy, nil, false, store.ErrLimit
	}
	previous := c.Revision
	c.Revision++
	c.Attempts++
	c.WorkerID = secure.NewID()
	until := now.Add(70 * time.Second)
	c.LeaseUntil = &until
	c.State = "running"
	c.Code = "checks_started"
	c.Report = json.RawMessage(`{}`)
	c.ReportHash = ""
	if err = t.SaveFileCheck(ctx, c, previous); err != nil {
		return nil, nil, policy, nil, false, err
	}
	a := &Attempt{FileID: id, Number: c.Attempts, WorkerID: c.WorkerID}
	if err = t.CheckReceipt(ctx, key, meaning, id, a); err != nil {
		return nil, nil, policy, nil, false, err
	}
	return c, b, policy, a, false, t.Tx.Commit(ctx)
}
func (s *Service) check(ctx context.Context, scope store.Scope, a *Attempt) error {
	t, err := s.begin(ctx, scope, "read", "check_run")
	if err != nil {
		return err
	}
	defer t.Tx.Rollback(ctx)
	c, err := t.FileCheck(ctx, a.FileID, false)
	if err != nil {
		return err
	}
	now, err := t.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if c.State != "running" || c.WorkerID != a.WorkerID || c.Attempts != a.Number || c.LeaseUntil == nil || !c.LeaseUntil.After(now) {
		return store.ErrRevision
	}
	if _, _, err = s.current(ctx, t, c); err != nil {
		return err
	}
	return t.Tx.Commit(ctx)
}

// Run's durable response selects an attempt, not a clean verdict. Get reports
// its current state. Replaying a key returns that same attempt without parsing.
func (s *Service) Run(ctx context.Context, scope store.Scope, id, key string) (*Result, error) {
	if !keyPattern.MatchString(key) || !store.ValidID(id) {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 65*time.Second)
	defer cancel()
	pre, err := s.begin(ctx, scope, "read", "check_run")
	if err != nil {
		return nil, err
	}
	c, err := pre.FileCheck(ctx, id, false)
	if err == nil {
		_, _, err = s.current(ctx, pre, c)
	}
	_ = pre.Tx.Rollback(ctx)
	if err != nil {
		return nil, err
	}
	slotCheck, release, err := s.Custody.DB.CheckSlot(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	if err = slotCheck(); err != nil {
		return nil, err
	}
	c, b, policy, a, replayed, err := s.start(ctx, scope, id, key)
	if err != nil {
		return nil, err
	}
	attemptData, _, err := canonical(a)
	if err != nil {
		return nil, err
	}
	if replayed {
		return &Result{Resource: attemptData, Replayed: true}, nil
	}
	ctx, parseCancel := context.WithTimeout(ctx, time.Duration(policy.TimeoutSeconds)*time.Second)
	defer parseCancel()
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				if slotCheck() != nil || s.check(ctx, scope, a) != nil {
					parseCancel()
					return
				}
			}
		}
	}()
	var parseErr error
	var scanFailed bool
	report := Report{Engine: Engine, FileID: id, SHA256: b.File.SHA256, PolicyHash: c.PolicyHash, Bytes: b.File.Size, Code: "valid_csv"}
	if policy.Signature != nil {
		report.Signature, parseErr = s.verifySignature(ctx, scope, c, b, policy, "check_run")
		if errors.Is(parseErr, secure.ErrPGPInput) || errors.Is(parseErr, secure.ErrPGPVerification) {
			report.Code = "signature_invalid"
			parseErr = nil
		}
	}
	if parseErr == nil && report.Code == "valid_csv" && policy.Scanner != nil {
		report.Scanner, parseErr = s.scan(ctx, scope, c, b, *policy.Scanner, a)
		scanFailed = parseErr != nil
		if parseErr == nil && report.Scanner.Result.Verdict != "clean" {
			report.Code = "scanner_" + report.Scanner.Result.Verdict
		}
	}
	if parseErr == nil && report.Code == "valid_csv" {
		data, err := s.Custody.Disk.VerifiedContext(ctx, custody.Name(scope.Tenant, scope.Partner, id), b.File.Size, b.File.SHA256)
		if err != nil {
			parseErr = err
		} else {
			parsed, err := Validate(ctx, policy, b.File, c.PolicyHash, data)
			_ = data.Close()
			parsed.Signature = report.Signature
			parsed.Scanner = report.Scanner
			report = parsed
			parseErr = err
		}
	}
	close(stop)
	<-done
	recordCtx, recordCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer recordCancel()
	t, err := s.begin(recordCtx, scope, "read", "check_run")
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(recordCtx)
	current, err := t.FileCheck(recordCtx, id, true)
	if err != nil {
		return nil, err
	}
	now, err := t.DatabaseTime(recordCtx)
	if err != nil {
		return nil, err
	}
	if current.State != "running" || current.WorkerID != a.WorkerID || current.Attempts != a.Number || current.LeaseUntil == nil || !current.LeaseUntil.After(now) {
		return nil, store.ErrRevision
	}
	previous := current.Revision
	current.Revision++
	current.WorkerID = ""
	current.LeaseUntil = nil
	if _, _, err = s.current(recordCtx, t, current); err != nil {
		if !errors.Is(err, store.ErrRevision) && !errors.Is(err, store.ErrState) {
			return nil, err
		}
		current.State = "failed"
		current.Code = "context_changed"
	} else if parseErr != nil {
		current.State = "failed"
		current.Code = "source_or_parser_unavailable"
		if scanFailed {
			current.Code = "scanner_unavailable"
		}
	} else {
		encoded, hash, err := canonical(report)
		if err != nil {
			return nil, err
		}
		current.Report = encoded
		current.Code = report.Code
		if report.Signature != nil && report.Signature.Verification.ValidUntil != nil && !now.Before(*report.Signature.Verification.ValidUntil) {
			current.State = "failed"
			current.Code = "signature_expired"
		} else if report.Scanner != nil && !now.Before(report.Scanner.ValidUntil) {
			current.State = "failed"
			current.Code = "scan_expired"
		} else if report.Code == "valid_csv" {
			current.State = "passed"
			current.ReportHash = hash
		} else {
			current.State = "rejected"
		}
	}
	if err = t.SaveFileCheck(recordCtx, current, previous); err != nil {
		return nil, err
	}
	if err = t.Tx.Commit(recordCtx); err != nil {
		return nil, err
	}
	return &Result{Resource: attemptData}, nil
}
func (s *Service) Release(ctx context.Context, scope store.Scope, id, key string, d ReleaseDecision) (*Result, error) {
	if !keyPattern.MatchString(key) || !hashPattern.MatchString(d.SHA256) || !hashPattern.MatchString(d.PolicyHash) || !hashPattern.MatchString(d.ReportHash) || d.Revision < 1 {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	t, err := s.begin(ctx, scope, "read", "write", "check_release")
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	_, meaning, _ := canonical(struct {
		Kind, ID string
		Decision ReleaseDecision
	}{"release_checked_file", id, d})
	prior, err := t.CheckReplay(ctx, key, meaning)
	if err != nil {
		return nil, err
	}
	if err = t.NamespaceLock(ctx); err != nil {
		return nil, err
	}
	c, err := t.FileCheck(ctx, id, true)
	if err != nil {
		return nil, err
	}
	b, p, err := s.current(ctx, t, c)
	if err != nil {
		return nil, err
	}
	if prior != nil {
		return &Result{Resource: prior, Replayed: true}, t.Tx.Commit(ctx)
	}
	if c.State != "passed" {
		return nil, store.ErrState
	}
	if c.Revision != d.Revision || c.PolicyHash != d.PolicyHash || b.File.SHA256 != d.SHA256 || c.ReportHash != d.ReportHash {
		return nil, store.ErrRevision
	}
	verified, err := s.Custody.Disk.VerifiedContext(ctx, custody.Name(scope.Tenant, scope.Partner, id), b.File.Size, b.File.SHA256)
	if err != nil {
		return nil, err
	}
	_ = verified.Close()
	policy, err := decodePolicy(p)
	if err != nil {
		return nil, err
	}
	if policy.Signature != nil {
		proof, err := s.verifySignature(ctx, scope, c, b, policy, "check_release")
		if err != nil {
			return nil, err
		}
		var approved Report
		if json.Unmarshal(c.Report, &approved) != nil || approved.Signature == nil || approved.Signature.Verification == nil {
			return nil, store.ErrState
		}
		proof.Verification.VerifiedAt = approved.Signature.Verification.VerifiedAt
		_, actualHash, _ := canonical(proof)
		_, approvedHash, _ := canonical(approved.Signature)
		if actualHash != approvedHash {
			return nil, store.ErrRevision
		}
	}
	if policy.Scanner != nil {
		var approved Report
		if json.Unmarshal(c.Report, &approved) != nil || approved.Scanner == nil || approved.Scanner.Result == nil || approved.Scanner.Result.Verdict != "clean" || approved.Scanner.Profile != *policy.Scanner {
			return nil, store.ErrState
		}
		profile, now, err := t.CurrentScanner(ctx, *policy.Scanner)
		if err != nil {
			return nil, err
		}
		if !now.Before(approved.Scanner.ValidUntil) || scanner.ConfigurationCurrent(ctx, *profile) != nil {
			return nil, store.ErrState
		}
	}
	previous := c.Revision
	c.Revision++
	c.State = "released"
	c.Code = "approved_for_publication"
	if err = t.SaveFileCheck(ctx, c, previous); err != nil {
		return nil, err
	}
	if b.Target != nil {
		if _, err = t.ApplyPathCommand(ctx, "check-release-"+id, *b.Target, s.Custody.NamespaceMaxEntries); err != nil {
			return nil, err
		}
	}
	return finish(ctx, t, key, meaning, id, c)
}
