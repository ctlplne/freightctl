package assistance

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

type Service struct {
	DB      *store.Store
	Enabled bool
}

func (s *Service) begin(ctx context.Context, scope store.Scope, grants ...string) (*store.Transaction, error) {
	t, err := s.DB.Begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	if t.Root != "/" {
		t.Tx.Rollback(ctx)
		return nil, store.ErrForbidden
	}
	for _, grant := range grants {
		if err = t.Require(grant); err != nil {
			t.Tx.Rollback(ctx)
			return nil, err
		}
	}
	return t, nil
}
func complete(ctx context.Context, t *store.Transaction, key, meaning, id string, value any) (*Result, error) {
	data, _, err := canonical(value)
	if err != nil {
		return nil, err
	}
	if err = t.AIReceipt(ctx, key, meaning, id, value); err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return &Result{Resource: data}, t.Tx.Commit(ctx)
}
func prior(ctx context.Context, t *store.Transaction, key, meaning string) (*Result, error) {
	data, err := t.AIReplay(ctx, key, meaning)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, nil
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return &Result{Resource: data, Replayed: true}, t.Tx.Commit(ctx)
}
func (s *Service) Register(ctx context.Context, scope store.Scope, key string, r ProfileRequest) (*Result, error) {
	if !keyPattern.MatchString(key) || r.ExpectedVersion < 0 || (r.ID != "" && (!store.ValidID(r.ID) || r.ExpectedVersion < 1)) || (r.ID == "" && r.ExpectedVersion != 0) {
		return nil, ErrInput
	}
	p, err := normalizeProfile(r.Definition)
	if err != nil {
		return nil, err
	}
	r.Definition = p
	t, err := s.begin(ctx, scope, "admin", "ai_manage")
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	data, hash, err := canonical(p)
	if err != nil {
		return nil, err
	}
	_, meaning, _ := canonical(struct {
		Kind    string
		Request ProfileRequest
	}{"register_profile", r})
	if replay, err := prior(ctx, t, key, meaning); err != nil || replay != nil {
		return replay, err
	}
	id := r.ID
	if id == "" {
		id = secure.NewID()
	}
	version, err := t.AIProfileVersion(ctx, id)
	if err != nil {
		return nil, err
	}
	if version != r.ExpectedVersion {
		return nil, store.ErrRevision
	}
	row := &store.Configuration{ID: id, Version: version + 1, Definition: data, Hash: hash, State: "active", Revision: 1}
	if err = t.SaveAIProfile(ctx, row, 0); err != nil {
		return nil, err
	}
	return complete(ctx, t, key, meaning, id, row)
}
func (s *Service) Profile(ctx context.Context, scope store.Scope, id string, version int) (*store.Configuration, error) {
	t, err := s.begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if !t.Has("ai_manage") && !t.Has("ai_use") {
		return nil, store.ErrForbidden
	}
	p, err := t.AIProfile(ctx, id, version, false)
	if err != nil {
		return nil, err
	}
	return p, t.Tx.Commit(ctx)
}
func (s *Service) Revoke(ctx context.Context, scope store.Scope, id string, version int, key string, decision workflow.Decision) (*Result, error) {
	if !keyPattern.MatchString(key) || !hashPattern.MatchString(decision.Hash) || decision.Revision < 1 {
		return nil, ErrInput
	}
	t, err := s.begin(ctx, scope, "admin", "ai_manage")
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	_, meaning, _ := canonical(struct {
		Kind, ID string
		Version  int
		Decision workflow.Decision
	}{"revoke_profile", id, version, decision})
	if replay, err := prior(ctx, t, key, meaning); err != nil || replay != nil {
		return replay, err
	}
	p, err := t.AIProfile(ctx, id, version, true)
	if err != nil {
		return nil, err
	}
	if p.Hash != decision.Hash || p.Revision != decision.Revision {
		return nil, store.ErrRevision
	}
	if p.State != "active" {
		return nil, store.ErrState
	}
	previous := p.Revision
	p.Revision++
	p.State = "revoked"
	if err = t.SaveAIProfile(ctx, p, previous); err != nil {
		return nil, err
	}
	return complete(ctx, t, key, meaning, id, p)
}
func (s *Service) Prepare(ctx context.Context, scope store.Scope, key string, r PrepareRequest) (*Result, error) {
	if !keyPattern.MatchString(key) {
		return nil, ErrInput
	}
	t, err := s.begin(ctx, scope, "ai_use")
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	_, p, err := profile(ctx, t, r.Profile, true)
	if err != nil {
		return nil, err
	}
	c, b, err := buildContext(ctx, t, r, p, true)
	if err != nil {
		return nil, err
	}
	_, meaning, _ := canonical(struct {
		Kind             string
		Request          PrepareRequest
		OperatorTextHash string
		Authority        int64
	}{"prepare_context", b.Request, secure.Digest([]byte(r.Requirements)), t.AuthorityRevision})
	if replay, err := prior(ctx, t, key, meaning); err != nil || replay != nil {
		return replay, err
	}
	if _, err = t.Tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, scope.Tenant+":"+scope.Partner+":"+t.Actor+":ai-admission"); err != nil {
		return nil, err
	}
	var count int
	if err = t.Tx.QueryRow(ctx, `SELECT count(*) FROM ai_jobs WHERE actor_id=$1 AND state IN ('prepared','approved','running','failed')`, t.Actor).Scan(&count); err != nil {
		return nil, err
	}
	if count >= 64 {
		return nil, store.ErrLimit
	}
	contextData, hash, err := canonical(c)
	if err != nil {
		return nil, err
	}
	bindingData, _, err := canonical(b)
	if err != nil {
		return nil, err
	}
	j := &store.AIJob{ID: secure.NewID(), ProfileID: r.Profile.ID, ProfileVersion: r.Profile.Version, ProfileHash: r.Profile.Hash, Authority: t.AuthorityRevision, Root: t.Root, Kind: r.Kind, Bindings: bindingData, Context: contextData, ContextHash: hash, State: "prepared", Revision: 1, Result: json.RawMessage(`{}`), Code: "awaiting_disclosure_approval"}
	if err = t.SaveAIJob(ctx, j, 0); err != nil {
		return nil, err
	}
	return complete(ctx, t, key, meaning, j.ID, j)
}
func load(ctx context.Context, t *store.Transaction, id string, lock, active bool) (*store.AIJob, *Profile, error) {
	j, err := t.AIJob(ctx, id, lock)
	if err != nil {
		return nil, nil, err
	}
	if j.Authority != t.AuthorityRevision || j.Root != t.Root {
		return nil, nil, store.ErrUnauthorized
	}
	_, p, err := profile(ctx, t, workflow.Reference{ID: j.ProfileID, Version: j.ProfileVersion, Hash: j.ProfileHash}, active)
	if err != nil {
		return nil, nil, err
	}
	return j, p, nil
}
func current(ctx context.Context, t *store.Transaction, j *store.AIJob, p *Profile) error {
	var b Bindings
	if json.Unmarshal(j.Bindings, &b) != nil {
		return store.ErrState
	}
	c, rebuilt, err := buildContext(ctx, t, b.Request, p, false)
	if err != nil {
		return err
	}
	_, hash, err := canonical(c)
	if err != nil {
		return err
	}
	_, oldHash, err := canonical(b)
	if err != nil {
		return err
	}
	_, newHash, err := canonical(rebuilt)
	if err != nil {
		return err
	}
	if hash != j.ContextHash || oldHash != newHash {
		return store.ErrRevision
	}
	return t.Reauthorize(ctx)
}
func (s *Service) Get(ctx context.Context, scope store.Scope, id string) (*JobView, error) {
	t, err := s.begin(ctx, scope, "ai_use")
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	j, p, err := load(ctx, t, id, false, false)
	if err != nil {
		return nil, err
	}
	err = current(ctx, t, j, p)
	if err != nil && !errors.Is(err, store.ErrState) && !errors.Is(err, store.ErrRevision) {
		return nil, err
	}
	row, readErr := t.AIProfile(ctx, j.ProfileID, j.ProfileVersion, false)
	if readErr != nil {
		return nil, readErr
	}
	return &JobView{Job: j, Current: err == nil && row.State == "active"}, t.Tx.Commit(ctx)
}
func (s *Service) Approve(ctx context.Context, scope store.Scope, id, key string, d Decision) (*Result, error) {
	if !keyPattern.MatchString(key) || !hashPattern.MatchString(d.Hash) || d.Revision < 1 {
		return nil, ErrInput
	}
	t, err := s.begin(ctx, scope, "ai_use", "ai_disclose")
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	_, meaning, _ := canonical(struct {
		Kind, ID string
		Decision Decision
	}{"approve_context", id, d})
	data, err := t.AIReplay(ctx, key, meaning)
	if err != nil {
		return nil, err
	}
	j, p, err := load(ctx, t, id, true, true)
	if err != nil {
		return nil, err
	}
	if err = current(ctx, t, j, p); err != nil {
		return nil, err
	}
	if data != nil {
		return &Result{Resource: data, Replayed: true}, t.Tx.Commit(ctx)
	}
	if j.ContextHash != d.Hash || j.Revision != d.Revision {
		return nil, store.ErrRevision
	}
	if j.State != "prepared" {
		return nil, store.ErrState
	}
	previous := j.Revision
	j.Revision++
	j.State = "approved"
	j.Code = "context_approved"
	if err = t.SaveAIJob(ctx, j, previous); err != nil {
		return nil, err
	}
	return complete(ctx, t, key, meaning, j.ID, j)
}

type attempt struct {
	JobID    string `json:"job_id"`
	WorkerID string `json:"worker_id"`
	Number   int    `json:"attempt"`
}

func (s *Service) start(ctx context.Context, scope store.Scope, id, key string) (*store.AIJob, *Profile, *attempt, bool, error) {
	if !keyPattern.MatchString(key) {
		return nil, nil, nil, false, ErrInput
	}
	t, err := s.begin(ctx, scope, "ai_use")
	if err != nil {
		return nil, nil, nil, false, err
	}
	defer t.Tx.Rollback(ctx)
	_, meaning, _ := canonical(struct{ Kind, ID string }{"generate", id})
	data, err := t.AIReplay(ctx, key, meaning)
	if err != nil {
		return nil, nil, nil, false, err
	}
	j, p, err := load(ctx, t, id, true, true)
	if err != nil {
		return nil, nil, nil, false, err
	}
	if err = current(ctx, t, j, p); err != nil {
		return nil, nil, nil, false, err
	}
	if data != nil {
		var a attempt
		if json.Unmarshal(data, &a) != nil {
			return nil, nil, nil, false, store.ErrState
		}
		return j, p, &a, true, t.Tx.Commit(ctx)
	}
	if !s.Enabled {
		return nil, nil, nil, false, ErrDisabled
	}
	now, err := t.DatabaseTime(ctx)
	if err != nil {
		return nil, nil, nil, false, err
	}
	expired := j.State == "running" && j.LeaseUntil != nil && !j.LeaseUntil.After(now)
	if j.State != "approved" && j.State != "failed" && !expired {
		return nil, nil, nil, false, store.ErrState
	}
	if j.Attempts >= 2 {
		return nil, nil, nil, false, store.ErrLimit
	}
	previous := j.Revision
	j.Revision++
	j.Attempts++
	j.State = "running"
	j.WorkerID = secure.NewID()
	until := now.Add(70 * time.Second)
	j.LeaseUntil = &until
	j.Code = "generation_started"
	j.Result = json.RawMessage(`{}`)
	j.OutputHash = ""
	if err = t.SaveAIJob(ctx, j, previous); err != nil {
		return nil, nil, nil, false, err
	}
	a := &attempt{JobID: id, WorkerID: j.WorkerID, Number: j.Attempts}
	if err = t.AIReceipt(ctx, key, meaning, id, a); err != nil {
		return nil, nil, nil, false, err
	}
	return j, p, a, false, t.Tx.Commit(ctx)
}
func (s *Service) check(ctx context.Context, scope store.Scope, a *attempt) error {
	t, err := s.begin(ctx, scope, "ai_use")
	if err != nil {
		return err
	}
	defer t.Tx.Rollback(ctx)
	j, p, err := load(ctx, t, a.JobID, false, true)
	if err != nil {
		return err
	}
	now, err := t.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if j.State != "running" || j.WorkerID != a.WorkerID || j.Attempts != a.Number || j.LeaseUntil == nil || !j.LeaseUntil.After(now) {
		return store.ErrRevision
	}
	if err = current(ctx, t, j, p); err != nil {
		return err
	}
	return t.Tx.Commit(ctx)
}
func (s *Service) Generate(ctx context.Context, scope store.Scope, id, key string) (*GenerationResult, error) {
	if !keyPattern.MatchString(key) {
		return nil, ErrInput
	}
	// Disabled mode returns before any model endpoint call or capacity reservation.
	if !s.Enabled {
		t, err := s.begin(ctx, scope, "ai_use")
		if err != nil {
			return nil, err
		}
		defer t.Tx.Rollback(ctx)
		if _, _, err = load(ctx, t, id, false, true); err != nil {
			return nil, err
		}
		return nil, ErrDisabled
	}
	ctx, cancel := context.WithTimeout(ctx, 65*time.Second)
	defer cancel()
	// Authentication and resource access precede the database-wide inference slot.
	preflight, err := s.begin(ctx, scope, "ai_use")
	if err != nil {
		return nil, err
	}
	preJob, preProfile, err := load(ctx, preflight, id, false, true)
	if err == nil {
		err = current(ctx, preflight, preJob, preProfile)
	}
	_ = preflight.Tx.Rollback(ctx)
	if err != nil {
		return nil, err
	}
	slotCheck, release, err := s.DB.AISlot(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	if err = slotCheck(); err != nil {
		return nil, err
	}
	j, p, a, replayed, err := s.start(ctx, scope, id, key)
	if err != nil {
		return nil, err
	}
	if replayed {
		if j.State == "running" {
			return nil, store.ErrState
		}
		return &GenerationResult{Job: j, Replayed: true}, nil
	}
	if err = s.check(ctx, scope, a); err != nil {
		return nil, err
	}
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
					cancel()
					return
				}
			}
		}
	}()
	response, backendErr := generate(ctx, *p, j.Context)
	close(stop)
	<-done
	// Use a fresh bounded recording context after a timeout/cancellation. Lost
	// authority still denies output; a retained running record needs later recovery.
	recordCtx, recordCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer recordCancel()
	t, err := s.begin(recordCtx, scope, "ai_use")
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(recordCtx)
	currentJob, currentProfile, err := load(recordCtx, t, id, true, true)
	if err != nil {
		return nil, err
	}
	now, err := t.DatabaseTime(recordCtx)
	if err != nil {
		return nil, err
	}
	if currentJob.WorkerID != a.WorkerID || currentJob.Attempts != a.Number || currentJob.State != "running" || currentJob.LeaseUntil == nil || !currentJob.LeaseUntil.After(now) {
		return nil, store.ErrRevision
	}
	previous := currentJob.Revision
	currentJob.Revision++
	currentJob.WorkerID = ""
	currentJob.LeaseUntil = nil
	if err = current(recordCtx, t, currentJob, currentProfile); err != nil {
		if !errors.Is(err, store.ErrRevision) && !errors.Is(err, store.ErrState) {
			return nil, err
		}
		currentJob.State = "superseded"
		currentJob.Code = "context_changed"
	} else if backendErr != nil {
		currentJob.State = "failed"
		currentJob.Code = "backend_failed"
	} else {
		currentJob.OutputHash = secure.Digest([]byte(response.Output))
		validated, validationErr := validateOutput(currentJob, response.Output)
		if validationErr != nil {
			currentJob.State = "rejected"
			currentJob.Code = "model_output_rejected"
		} else {
			validated.Usage = &response.Usage
			data, _, err := canonical(validated)
			if err != nil {
				return nil, err
			}
			currentJob.Result = data
			currentJob.State = "succeeded"
			currentJob.Code = "result_validated"
		}
	}
	if err = t.SaveAIJob(recordCtx, currentJob, previous); err != nil {
		return nil, err
	}
	if err = t.Tx.Commit(recordCtx); err != nil {
		return nil, err
	}
	return &GenerationResult{Job: currentJob}, nil
}
func (s *Service) Adopt(ctx context.Context, scope store.Scope, id, key string, decision Decision) (*Result, error) {
	if !keyPattern.MatchString(key) || !hashPattern.MatchString(decision.Hash) || decision.Revision < 1 {
		return nil, ErrInput
	}
	t, err := s.begin(ctx, scope, "ai_use", "workflow_manage")
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	_, meaning, _ := canonical(struct {
		Kind, ID string
		Decision Decision
	}{"adopt_proposal", id, decision})
	data, err := t.AIReplay(ctx, key, meaning)
	if err != nil {
		return nil, err
	}
	j, p, err := load(ctx, t, id, true, true)
	if err != nil {
		return nil, err
	}
	if err = current(ctx, t, j, p); err != nil {
		return nil, err
	}
	if data != nil {
		return &Result{Resource: data, Replayed: true}, t.Tx.Commit(ctx)
	}
	if j.Kind != "propose" || j.State != "succeeded" {
		return nil, store.ErrState
	}
	if decision.Hash != j.ContextHash || decision.Revision != j.Revision {
		return nil, store.ErrRevision
	}
	definition, err := proposedDefinition(j)
	if err != nil {
		return nil, err
	}
	draft, err := workflow.StageDraft(ctx, t, workflow.DraftRequest{Definition: definition})
	if err != nil {
		return nil, err
	}
	if _, err = t.Append(ctx, "AIProposalAdopted", draft.ID, map[string]any{"job_id": j.ID, "context_hash": j.ContextHash, "output_hash": j.OutputHash, "workflow_id": draft.ID, "workflow_hash": draft.Hash, "workflow_version": draft.Version}); err != nil {
		return nil, err
	}
	return complete(ctx, t, key, meaning, draft.ID, draft)
}

// Evidence resolves only citations held by this actor's authorized context; it
// never returns arbitrary journal payloads, secrets, transport paths or prompts.
func (s *Service) Evidence(ctx context.Context, scope store.Scope, id, eventID string) (*Citation, error) {
	t, err := s.begin(ctx, scope, "ai_use")
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	j, p, err := load(ctx, t, id, false, false)
	if err != nil {
		return nil, err
	}
	if err = current(ctx, t, j, p); err != nil {
		return nil, err
	}
	var b Bindings
	if json.Unmarshal(j.Bindings, &b) != nil {
		return nil, store.ErrState
	}
	for _, citations := range b.Evidence {
		for _, cite := range citations {
			if cite.EventID == eventID {
				var actual Citation
				err = t.Tx.QueryRow(ctx, `SELECT event_id::text,kind,resource_id::text FROM events WHERE event_id=$1 AND actor_id=$2`, eventID, t.Actor).Scan(&actual.EventID, &actual.Kind, &actual.ResourceID)
				if err != nil {
					return nil, err
				}
				if actual != cite {
					return nil, store.ErrState
				}
				return &actual, t.Tx.Commit(ctx)
			}
		}
	}
	return nil, store.ErrNotFound
}
