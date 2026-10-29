package checks

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/scanner"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/vpath"
	"github.com/jackc/pgx/v5"
	"golang.org/x/text/unicode/norm"
)

type RecheckOptions struct {
	TargetPath    string `json:"target_path"`
	SignatureMode string `json:"signature_mode"`
	Reason        string `json:"reason"`
}
type RecheckCheck struct {
	PolicyID      string             `json:"policy_id"`
	PolicyVersion int                `json:"policy_version"`
	PolicyHash    string             `json:"policy_hash"`
	State         string             `json:"state"`
	Revision      int64              `json:"revision"`
	Attempts      int                `json:"attempts"`
	Code          string             `json:"code"`
	WorkerID      string             `json:"worker_id,omitempty"`
	LeaseUntil    *time.Time         `json:"lease_until,omitempty"`
	ReportHash    string             `json:"report_hash"`
	Binding       store.CheckBinding `json:"binding"`
}
type RecheckSource struct {
	File      store.File           `json:"file"`
	Check     *RecheckCheck        `json:"check,omitempty"`
	Signature *store.FileSignature `json:"signature,omitempty"`
}
type RecheckTarget struct {
	Command        store.PathCommand `json:"command"`
	ParentID       string            `json:"parent_id"`
	ParentRevision int64             `json:"parent_revision"`
	EntryID        string            `json:"entry_id"`
	EntryRevision  int64             `json:"entry_revision"`
}
type RecheckPlan struct {
	Source        RecheckSource             `json:"source"`
	Policy        store.OnboardingReference `json:"policy"`
	Root          string                    `json:"namespace_root"`
	Authority     int64                     `json:"authority_revision"`
	StorageID     string                    `json:"storage_id"`
	Target        *RecheckTarget            `json:"target,omitempty"`
	SignatureMode string                    `json:"signature_mode"`
	Reason        string                    `json:"reason"`
}
type RecheckDefinition struct {
	Schema int                 `json:"schema_version"`
	Plan   RecheckPlan         `json:"plan"`
	Slots  []store.RecheckSlot `json:"staging_slots"`
}
type RecheckPolicy struct {
	Reference  store.OnboardingReference `json:"reference"`
	State      string                    `json:"state"`
	Definition Policy                    `json:"definition"`
}
type RecheckPreview struct {
	Plan           RecheckPlan    `json:"plan"`
	PreviousPolicy *RecheckPolicy `json:"previous_policy,omitempty"`
	CurrentPolicy  RecheckPolicy  `json:"current_policy"`
	Effects        string         `json:"effects"`
}
type RecheckView struct {
	Kind           string             `json:"kind"`
	Recheck        *store.FileRecheck `json:"recheck"`
	Current        bool               `json:"current"`
	Code           string             `json:"code"`
	PreviousPolicy *RecheckPolicy     `json:"previous_policy,omitempty"`
	SelectedPolicy *RecheckPolicy     `json:"selected_policy,omitempty"`
}
type RecheckCopyResult struct {
	Kind       string               `json:"kind"`
	File       store.File           `json:"file"`
	Acceptance string               `json:"acceptance"`
	Signature  *store.FileSignature `json:"signature,omitempty"`
}

func recheckReason(text string) (string, error) {
	text = norm.NFC.String(strings.TrimSpace(text))
	if !utf8.ValidString(text) || len(text) < 3 || len(text) > 1024 || utf8.RuneCountInString(text) > 240 {
		return "", ErrInput
	}
	for _, r := range text {
		if unicode.IsControl(r) {
			return "", ErrInput
		}
	}
	return text, nil
}
func (s *Service) recheckBegin(ctx context.Context, scope store.Scope) (*store.Transaction, error) {
	t, err := s.begin(ctx, scope, "admin", "read", "write", "intake_manage", "check_run", "check_release")
	if err != nil {
		return nil, err
	}
	if t.Root != "/" {
		t.Tx.Rollback(ctx)
		return nil, store.ErrForbidden
	}
	return t, nil
}
func (t *Service) recheckPolicy(ctx context.Context, tx *store.Transaction, id string, version int, hash string) (*RecheckPolicy, error) {
	p := &store.Configuration{}
	err := tx.Tx.QueryRow(ctx, `SELECT policy_id::text,version,definition,definition_hash,state,revision FROM intake_policies WHERE policy_id=$1 AND version=$2`, id, version).Scan(&p.ID, &p.Version, &p.Definition, &p.Hash, &p.State, &p.Revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if p.Hash != hash {
		return nil, store.ErrState
	}
	d, err := decodePolicy(p)
	if err != nil {
		return nil, err
	}
	return &RecheckPolicy{Reference: store.OnboardingReference{ID: p.ID, Version: p.Version, Hash: p.Hash}, State: p.State, Definition: d}, nil
}

// recheckPlan runs under the namespace lock. Old proof availability is not
// authority for this operation: current root administration plus exact original
// acceptance ownership authorizes only a held copy, never original downloads.
func (s *Service) recheckPlan(ctx context.Context, t *store.Transaction, id string, options RecheckOptions, lockSource bool) (*RecheckPreview, error) {
	if s.Custody.Disk == nil {
		return nil, store.ErrState
	}
	if err := s.Custody.Disk.CheckIdentity(); err != nil {
		return nil, err
	}
	reason, err := recheckReason(options.Reason)
	if err != nil {
		return nil, err
	}
	if options.SignatureMode != "not_required" && options.SignatureMode != "reuse_exact" && options.SignatureMode != "require_new" {
		return nil, ErrInput
	}
	f, err := t.File(ctx, id)
	if err != nil {
		return nil, err
	}
	var owner string
	if err = t.Tx.QueryRow(ctx, `SELECT actor_id::text FROM events WHERE event_id=$1 AND resource_id=$2 AND kind='FileAccepted'`, f.EventID, id).Scan(&owner); err != nil {
		return nil, err
	}
	if owner != t.Actor {
		return nil, store.ErrNotFound
	}
	plan := RecheckPlan{Source: RecheckSource{File: *f}, Root: t.Root, Authority: t.AuthorityRevision, StorageID: s.Custody.Disk.Identity(), SignatureMode: options.SignatureMode, Reason: reason}
	view := &RecheckPreview{Effects: "Create one held checked revision with identical bytes. Fresh checks and a separate exact release are required; original jobs and reports are unchanged."}
	c, err := t.FileCheck(ctx, id, lockSource)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	if c != nil {
		var b store.CheckBinding
		if json.Unmarshal(c.Binding, &b) != nil || b.File != *f || b.StorageID != plan.StorageID || b.Root != t.Root {
			return nil, store.ErrState
		}
		now, e := t.DatabaseTime(ctx)
		if e != nil {
			return nil, e
		}
		if c.State == "running" && (c.LeaseUntil == nil || c.LeaseUntil.After(now)) {
			return nil, store.ErrState
		}
		plan.Source.Check = &RecheckCheck{PolicyID: c.PolicyID, PolicyVersion: c.PolicyVersion, PolicyHash: c.PolicyHash, State: c.State, Revision: c.Revision, Attempts: c.Attempts, Code: c.Code, WorkerID: c.WorkerID, LeaseUntil: c.LeaseUntil, ReportHash: c.ReportHash, Binding: b}
		if plan.Source.Check.LeaseUntil != nil {
			utc := plan.Source.Check.LeaseUntil.UTC()
			plan.Source.Check.LeaseUntil = &utc
		}
		view.PreviousPolicy, err = s.recheckPolicy(ctx, t, c.PolicyID, c.PolicyVersion, c.PolicyHash)
		if err != nil {
			return nil, err
		}
	} else if f.Policy != "integrity-only-v1" {
		return nil, store.ErrState
	}
	sig, err := t.FileSignature(ctx, id)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	plan.Source.Signature = sig
	p, err := t.IntakePolicy(ctx, false)
	if err != nil {
		return nil, err
	}
	if p == nil || p.State != "active" {
		return nil, store.ErrState
	}
	policy, err := decodePolicy(p)
	if err != nil {
		return nil, err
	}
	plan.Policy = store.OnboardingReference{ID: p.ID, Version: p.Version, Hash: p.Hash}
	if old := view.PreviousPolicy; old != nil {
		if old.Definition.Scanner != nil && policy.Scanner == nil || old.Definition.Signature != nil && policy.Signature == nil {
			return nil, ErrInput
		}
		if old.Definition.Signature != nil && old.Definition.Signature.MaxAgeSeconds > 0 && (policy.Signature.MaxAgeSeconds == 0 || policy.Signature.MaxAgeSeconds > old.Definition.Signature.MaxAgeSeconds) {
			return nil, ErrInput
		}
	}
	if policy.Signature == nil && options.SignatureMode != "not_required" || policy.Signature != nil && options.SignatureMode == "not_required" {
		return nil, ErrInput
	}
	if policy.Signature != nil {
		if _, _, err = keyCurrent(ctx, t, policy.Signature); err != nil {
			return nil, err
		}
	}
	if policy.Scanner != nil {
		d, _, e := t.CurrentScanner(ctx, *policy.Scanner)
		if e != nil {
			return nil, e
		}
		if err = scanner.ConfigurationCurrent(ctx, *d); err != nil {
			return nil, err
		}
	}
	if options.SignatureMode == "reuse_exact" && (sig == nil || sig.Key != policy.Signature.Key || sig.StorageID != plan.StorageID || sig.DataSHA256 != f.SHA256) {
		return nil, ErrInput
	}
	if options.TargetPath != "" {
		path, e := vpath.Canonical(options.TargetPath)
		if e != nil || path == "/" || vpath.ControlPath(path) {
			return nil, ErrInput
		}
		if err = t.ParentWritable(ctx, path); err != nil {
			return nil, err
		}
		parent, e := t.Entry(ctx, vpath.Parent(path))
		if e != nil {
			return nil, e
		}
		target := &RecheckTarget{Command: store.PathCommand{Operation: "publish", Path: path}, ParentID: parent.ID, ParentRevision: parent.Revision}
		entry, e := t.Entry(ctx, path)
		if e != nil && !errors.Is(e, store.ErrNotFound) {
			return nil, e
		}
		if entry != nil {
			if entry.Kind != "file" || entry.FileID != id {
				return nil, store.ErrRevision
			}
			if e = t.EntryMode(entry, 2); e != nil {
				return nil, e
			}
			rev := entry.Revision
			mode := entry.Mode
			target.Command.ExpectedRevision = &rev
			target.Command.Replace = true
			target.Command.Mode = &mode
			target.EntryID = entry.ID
			target.EntryRevision = rev
		}
		plan.Target = target
	}
	view.Plan = plan
	view.CurrentPolicy = RecheckPolicy{Reference: plan.Policy, State: p.State, Definition: policy}
	return view, t.Reauthorize(ctx)
}
func optionsForRecheck(p RecheckPlan) RecheckOptions {
	path := ""
	if p.Target != nil {
		path = p.Target.Command.Path
	}
	return RecheckOptions{TargetPath: path, SignatureMode: p.SignatureMode, Reason: p.Reason}
}
func (s *Service) PreviewRecheck(ctx context.Context, scope store.Scope, id string, options RecheckOptions) (*RecheckPreview, error) {
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
	v, err := s.recheckPlan(ctx, t, id, options, false)
	if err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return v, t.Tx.Commit(ctx)
}
func (s *Service) ProposeRecheck(ctx context.Context, scope store.Scope, key string, plan RecheckPlan) (*Result, error) {
	if !keyPattern.MatchString(key) {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.recheckBegin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	_, meaning, err := canonical(struct {
		Kind string
		Plan RecheckPlan
	}{"propose_file_recheck", plan})
	if err != nil {
		return nil, err
	}
	if prior, e := t.CheckReplay(ctx, key, meaning); e != nil {
		return nil, e
	} else if prior != nil {
		return recheckReplayed(ctx, t, prior)
	}
	if _, err = t.Tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, scope.Tenant+":"+scope.Partner+":"+t.Actor+":file-rechecks"); err != nil {
		return nil, err
	}
	var queued int
	if err = t.Tx.QueryRow(ctx, `SELECT count(*) FROM file_rechecks WHERE actor_id=$1 AND state IN ('proposed','approved')`, t.Actor).Scan(&queued); err != nil {
		return nil, err
	}
	if queued >= 16 {
		return nil, store.ErrLimit
	}
	if err = t.NamespaceLock(ctx); err != nil {
		return nil, err
	}
	fresh, err := s.recheckPlan(ctx, t, plan.Source.File.ID, optionsForRecheck(plan), false)
	if err != nil {
		return nil, err
	}
	_, expected, _ := canonical(fresh.Plan)
	_, actual, _ := canonical(plan)
	if expected != actual {
		return nil, store.ErrRevision
	}
	def := RecheckDefinition{Schema: 1, Plan: fresh.Plan, Slots: make([]store.RecheckSlot, 3)}
	for i := range def.Slots {
		def.Slots[i].FileID = secure.NewID()
		if plan.SignatureMode == "reuse_exact" {
			def.Slots[i].SignatureID = secure.NewID()
		}
	}
	data, hash, err := canonical(def)
	if len(data) > 16384 {
		return nil, ErrInput
	}
	if err != nil {
		return nil, err
	}
	row := &store.FileRecheck{ID: secure.NewID(), SourceID: plan.Source.File.ID, Definition: data, Hash: hash, State: "proposed", Revision: 1, Result: json.RawMessage(`{}`)}
	if err = t.SaveFileRecheck(ctx, row, 0); err != nil {
		return nil, err
	}
	return finishRecheck(ctx, t, key, meaning, row.ID, row)
}
func recheckReceipt(r *store.FileRecheck) any {
	return struct {
		Kind    string             `json:"kind"`
		Recheck *store.FileRecheck `json:"recheck"`
	}{"file_recheck", r}
}
func decodeRecheck(r *store.FileRecheck) (RecheckDefinition, error) {
	var d RecheckDefinition
	if json.Unmarshal(r.Definition, &d) != nil || d.Schema != 1 || len(d.Slots) != 3 {
		return d, store.ErrState
	}
	_, hash, err := canonical(d)
	if err != nil || hash != r.Hash {
		return d, store.ErrState
	}
	return d, nil
}
func (s *Service) recheckCurrent(ctx context.Context, t *store.Transaction, r *store.FileRecheck, d RecheckDefinition, lock bool) error {
	fresh, err := s.recheckPlan(ctx, t, r.SourceID, optionsForRecheck(d.Plan), lock)
	if err != nil {
		return err
	}
	_, expected, _ := canonical(fresh.Plan)
	_, actual, _ := canonical(d.Plan)
	if expected != actual {
		return store.ErrRevision
	}
	return nil
}
func (s *Service) DecideRecheck(ctx context.Context, scope store.Scope, id, key string, decision PolicyRecheckDecision) (*Result, error) {
	if !keyPattern.MatchString(key) || !hashPattern.MatchString(decision.Hash) || decision.Revision < 1 || (decision.Operation != "approve" && decision.Operation != "cancel") {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.recheckBegin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	_, meaning, _ := canonical(struct {
		Kind, ID string
		Decision PolicyRecheckDecision
	}{"decide_file_recheck", id, decision})
	if prior, e := t.CheckReplay(ctx, key, meaning); e != nil {
		return nil, e
	} else if prior != nil {
		return recheckReplayed(ctx, t, prior)
	}
	r, err := t.FileRecheck(ctx, id, true)
	if err != nil {
		return nil, err
	}
	if r.Hash != decision.Hash || r.Revision != decision.Revision {
		return nil, store.ErrRevision
	}
	d, err := decodeRecheck(r)
	if err != nil {
		return nil, err
	}
	if r.State != "proposed" && (r.State != "approved" || decision.Operation != "cancel") {
		return nil, store.ErrState
	}
	if decision.Operation == "approve" {
		if err = t.NamespaceLock(ctx); err != nil {
			return nil, err
		}
		if err = s.recheckCurrent(ctx, t, r, d, true); err != nil {
			return nil, err
		}
		r.State = "approved"
	} else {
		r.State = "cancelled"
	}
	previous := r.Revision
	r.Revision++
	if err = t.SaveFileRecheck(ctx, r, previous); err != nil {
		return nil, err
	}
	return finishRecheck(ctx, t, key, meaning, id, r)
}

type PolicyRecheckDecision struct {
	Operation string `json:"operation"`
	Hash      string `json:"definition_hash"`
	Revision  int64  `json:"expected_revision"`
}

func (s *Service) GetRecheck(ctx context.Context, scope store.Scope, id string) (*RecheckView, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.recheckBegin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	r, err := t.FileRecheck(ctx, id, false)
	if err != nil {
		return nil, err
	}
	d, err := decodeRecheck(r)
	if err != nil {
		return nil, err
	}
	v := &RecheckView{Kind: "file_recheck", Recheck: r, Code: "historical_or_changed"}
	if d.Plan.Root != t.Root {
		return nil, store.ErrNotFound
	}
	if d.Plan.Source.Check != nil {
		c := d.Plan.Source.Check
		v.PreviousPolicy, err = s.recheckPolicy(ctx, t, c.PolicyID, c.PolicyVersion, c.PolicyHash)
		if err != nil {
			return nil, err
		}
	}
	p := d.Plan.Policy
	v.SelectedPolicy, err = s.recheckPolicy(ctx, t, p.ID, p.Version, p.Hash)
	if err != nil {
		return nil, err
	}
	if r.State == "proposed" || r.State == "approved" {
		if err = t.NamespaceLock(ctx); err != nil {
			return nil, err
		}
		if s.recheckCurrent(ctx, t, r, d, false) == nil {
			v.Current = true
			v.Code = "current"
		}
	} else {
		v.Code = r.State
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return v, t.Tx.Commit(ctx)
}

func (s *Service) CopyRecheck(ctx context.Context, scope store.Scope, id, key string) (*Result, error) {
	if !keyPattern.MatchString(key) || !store.ValidID(id) {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	preflight, err := s.recheckBegin(ctx, scope)
	if err != nil {
		return nil, err
	}
	_, preMeaning, _ := canonical(struct{ Kind, ID string }{"copy_rechecked_revision", id})
	prior, preErr := preflight.CheckReplay(ctx, key, preMeaning)
	if preErr != nil {
		preflight.Tx.Rollback(ctx)
		return nil, preErr
	}
	if prior != nil {
		return recheckReplayed(ctx, preflight, prior)
	}
	known, preErr := preflight.FileRecheck(ctx, id, false)
	if preErr != nil {
		preflight.Tx.Rollback(ctx)
		return nil, preErr
	}
	if known.State == "copied" {
		return finishRecheck(ctx, preflight, key, preMeaning, id, known)
	}
	if err := preflight.Tx.Rollback(ctx); err != nil {
		return nil, err
	}
	admission, release, err := s.Custody.DB.RecheckCopySlot(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	t, err := s.recheckBegin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	_, meaning, _ := canonical(struct{ Kind, ID string }{"copy_rechecked_revision", id})
	if prior, e := t.CheckReplay(ctx, key, meaning); e != nil {
		return nil, e
	} else if prior != nil {
		return recheckReplayed(ctx, t, prior)
	}
	r, err := t.FileRecheck(ctx, id, true)
	if err != nil {
		return nil, err
	}
	if r.State == "copied" {
		return finishRecheck(ctx, t, key, meaning, id, r)
	}
	if r.State != "approved" {
		return nil, store.ErrState
	}
	d, err := decodeRecheck(r)
	if err != nil {
		return nil, err
	}
	if err = t.NamespaceLock(ctx); err != nil {
		return nil, err
	}
	// Match upload/reconciliation capacity-before-policy lock ordering. The
	// namespace lock precedes check rows, as it does for ordinary release.
	if _, err = t.Tx.Exec(ctx, `SELECT pg_advisory_xact_lock(721815034)`); err != nil {
		return nil, err
	}
	if err = s.recheckCurrent(ctx, t, r, d, true); err != nil {
		return nil, err
	}
	var target *store.PathCommand
	if d.Plan.Target != nil {
		target = &d.Plan.Target.Command
	}
	var signature *store.FileSignature
	if d.Plan.SignatureMode == "reuse_exact" {
		signature = d.Plan.Source.Signature
	}
	file, attached, err := s.Custody.MaterializeRecheck(ctx, t, r, d.Plan.Source.File, d.Slots, target, signature, admission)
	if err != nil {
		return nil, err
	}
	if file.Policy != "intake-csv-v1:"+d.Plan.Policy.Hash {
		return nil, store.ErrState
	}
	result, _, err := canonical(RecheckCopyResult{Kind: "file_recheck_copy", File: *file, Acceptance: "durable-held-pending-checks-and-release", Signature: attached})
	if err != nil {
		return nil, err
	}
	previous := r.Revision
	r.State = "copied"
	r.Revision++
	r.FileID = file.ID
	r.Result = result
	if err = t.SaveFileRecheck(ctx, r, previous); err != nil {
		return nil, err
	}
	return finishRecheck(ctx, t, key, meaning, id, r)
}

type RecheckPage struct {
	Rechecks []*store.FileRecheck `json:"rechecks"`
	Next     string               `json:"next,omitempty"`
}

func (s *Service) ListRechecks(ctx context.Context, scope store.Scope, source, after string, limit int) (*RecheckPage, error) {
	if !store.ValidID(source) || (after != "" && !store.ValidID(after)) || limit < 1 || limit > 100 {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.recheckBegin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	var owner string
	if err = t.Tx.QueryRow(ctx, `SELECT e.actor_id::text FROM files f JOIN events e ON (e.tenant_id,e.partner_id,e.event_id)=(f.tenant_id,f.partner_id,f.accepted_event_id) WHERE f.file_id=$1`, source).Scan(&owner); err != nil || owner != t.Actor {
		return nil, store.ErrNotFound
	}
	rows, err := t.Tx.Query(ctx, `SELECT recheck_id::text FROM file_rechecks WHERE source_file_id=$1 AND actor_id=$2 AND ($3='' OR recheck_id>nullif($3,'')::uuid) ORDER BY recheck_id LIMIT $4`, source, t.Actor, after, limit+1)
	if err != nil {
		return nil, err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return nil, err
	}
	page := &RecheckPage{Rechecks: []*store.FileRecheck{}}
	if len(ids) > limit {
		ids = ids[:limit]
		page.Next = ids[limit-1]
	}
	for _, id := range ids {
		r, e := t.FileRecheck(ctx, id, false)
		if e != nil {
			return nil, e
		}
		d, e := decodeRecheck(r)
		if e != nil {
			return nil, e
		}
		if d.Plan.Root != t.Root {
			return nil, store.ErrNotFound
		}
		page.Rechecks = append(page.Rechecks, r)
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return page, t.Tx.Commit(ctx)
}

// Return the stored encoding even on the first successful command. PostgreSQL
// JSONB ordering must not change a recovered receipt's exact representation.
func finishRecheck(ctx context.Context, t *store.Transaction, key, meaning, id string, r *store.FileRecheck) (*Result, error) {
	if err := t.CheckReceipt(ctx, key, meaning, id, recheckReceipt(r)); err != nil {
		return nil, err
	}
	data, err := t.CheckReplay(ctx, key, meaning)
	if err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return &Result{Resource: data}, t.Tx.Commit(ctx)
}

func recheckReplayed(ctx context.Context, t *store.Transaction, data json.RawMessage) (*Result, error) {
	if err := t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return &Result{Resource: data, Replayed: true}, t.Tx.Commit(ctx)
}
