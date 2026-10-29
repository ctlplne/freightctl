package checks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
)

type Service struct{ Custody *custody.Service }
type Result struct {
	Resource json.RawMessage `json:"resource"`
	Replayed bool            `json:"replayed"`
}
type View struct {
	Check   *store.FileCheck `json:"check"`
	Current bool             `json:"current"`
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
	return b, p, err
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
	_, _, currentErr := s.current(ctx, t, c)
	if currentErr != nil && !errors.Is(currentErr, store.ErrRevision) && !errors.Is(currentErr, store.ErrState) {
		return nil, currentErr
	}
	return &View{Check: c, Current: currentErr == nil}, t.Tx.Commit(ctx)
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
	data, parseErr := s.Custody.Disk.VerifiedContext(ctx, custody.Name(scope.Tenant, scope.Partner, id), b.File.Size, b.File.SHA256)
	var report Report
	if parseErr == nil {
		report, parseErr = Validate(ctx, policy, b.File, c.PolicyHash, data)
		_ = data.Close()
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
	} else {
		encoded, hash, err := canonical(report)
		if err != nil {
			return nil, err
		}
		current.Report = encoded
		current.Code = report.Code
		if report.Code == "valid_csv" {
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
	b, _, err := s.current(ctx, t, c)
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
