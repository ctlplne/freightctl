package checks

import (
	"context"
	"encoding/json"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

type ProjectionDefinition struct {
	Schema int            `json:"schema_version"`
	Plan   ProjectionPlan `json:"plan"`
	Slots  []string       `json:"staging_slots"`
}
type ProjectionAttempt struct {
	ID       string `json:"projection_id"`
	Number   int    `json:"attempt"`
	WorkerID string `json:"worker_id"`
}
type ProjectionStartDecision struct {
	Hash     string `json:"definition_hash"`
	Revision int64  `json:"expected_revision"`
}
type ProjectionView struct {
	Kind       string                  `json:"kind"`
	Projection *store.RecordProjection `json:"projection"`
	Current    bool                    `json:"current"`
	Code       string                  `json:"code"`
}
type ProjectionOutput struct {
	Kind       string            `json:"kind"`
	Attempt    ProjectionAttempt `json:"attempt"`
	File       store.File        `json:"file"`
	Acceptance string            `json:"acceptance"`
	Report     ProjectionReport  `json:"report"`
}

func decodeProjection(r *store.RecordProjection) (ProjectionDefinition, error) {
	var d ProjectionDefinition
	if r == nil || len(r.Definition) > 32768 || workflow.Decode(r.Definition, &d) != nil || d.Schema != 1 || !validProjectionProfile(d.Plan) || len(d.Slots) != 3 || d.Plan.Context.Source.File.ID != r.SourceID {
		return d, store.ErrState
	}
	_, hash, err := canonical(d)
	if err != nil || hash != r.Hash {
		return d, store.ErrState
	}
	seen := make(map[string]bool)
	for _, id := range d.Slots {
		if !store.ValidID(id) || id == r.SourceID || seen[id] {
			return d, store.ErrState
		}
		seen[id] = true
	}
	return d, nil
}
func projectionLeaseCurrent(r *store.RecordProjection, a ProjectionAttempt, now time.Time) error {
	if r == nil || r.ID != a.ID || r.State != "running" || a.Number < 1 || a.Number > 3 || r.Attempts != a.Number || !store.ValidID(a.WorkerID) || r.WorkerID != a.WorkerID || r.LeaseUntil == nil || !now.Before(*r.LeaseUntil) {
		return store.ErrState
	}
	return nil
}
func projectionOptionsFor(plan ProjectionPlan) ProjectionOptions {
	path := ""
	if plan.Context.Target != nil {
		path = plan.Context.Target.Command.Path
	}
	return ProjectionOptions{Profile: plan.Profile, TargetPath: path, Reason: plan.Context.Reason, Definition: plan.Projection}
}
func (s *Service) projectionCurrent(ctx context.Context, t *store.Transaction, d ProjectionDefinition, lock bool) (*ProjectionPreview, error) {
	fresh, err := s.projectionPlan(ctx, t, d.Plan.Context.Source.File.ID, projectionOptionsFor(d.Plan), lock)
	if err != nil {
		return nil, err
	}
	_, expected, _ := canonical(fresh.Plan)
	_, actual, _ := canonical(d.Plan)
	if actual != expected {
		return nil, store.ErrRevision
	}
	return fresh, nil
}
func projectionReceipt(r *store.RecordProjection) any {
	return struct {
		Kind       string                  `json:"kind"`
		Projection *store.RecordProjection `json:"projection"`
	}{"record_projection", r}
}
func finishProjection(ctx context.Context, t *store.Transaction, key, meaning string, r *store.RecordProjection) (*Result, error) {
	return finish(ctx, t, key, meaning, r.ID, projectionReceipt(r))
}

func (s *Service) ProposeProjection(ctx context.Context, scope store.Scope, key string, plan ProjectionPlan) (*Result, error) {
	if !keyPattern.MatchString(key) || !validProjectionProfile(plan) {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.projectionBegin(ctx, scope, plan.Profile)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	_, meaning, err := canonical(struct {
		Kind string
		Plan ProjectionPlan
	}{"propose_record_projection", plan})
	if err != nil {
		return nil, err
	}
	if prior, e := t.CheckReplay(ctx, key, meaning); e != nil {
		return nil, e
	} else if prior != nil {
		return projectionReplayed(ctx, t, prior)
	}
	return s.stageProjectionProposal(ctx, t, key, meaning, plan)
}

func (s *Service) projectionProposalAdmission(ctx context.Context, t *store.Transaction) error {
	scope := t.Scope
	var err error
	if _, err = t.Tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, scope.Tenant+":"+scope.Partner+":"+t.Actor+":record-projections"); err != nil {
		return err
	}
	var count int
	if err = t.Tx.QueryRow(ctx, `SELECT count(*) FROM record_projections WHERE actor_id=$1 AND state IN ('proposed','approved','running','failed')`, t.Actor).Scan(&count); err != nil {
		return err
	}
	if count >= 16 {
		return store.ErrLimit
	}
	return nil
}
func (s *Service) stageProjectionProposal(ctx context.Context, t *store.Transaction, key, meaning string, plan ProjectionPlan) (*Result, error) {
	var err error
	if err = s.projectionProposalAdmission(ctx, t); err != nil {
		return nil, err
	}
	if err = t.NamespaceLock(ctx); err != nil {
		return nil, err
	}
	d := ProjectionDefinition{Schema: 1, Plan: plan, Slots: make([]string, 3)}
	fresh, err := s.projectionCurrent(ctx, t, d, true)
	if err != nil {
		return nil, err
	}
	d.Plan = fresh.Plan
	for i := range d.Slots {
		d.Slots[i] = secure.NewID()
	}
	data, hash, err := canonical(d)
	if err != nil {
		return nil, err
	}
	if len(data) > 32768 {
		return nil, ErrInput
	}
	r := &store.RecordProjection{ID: secure.NewID(), SourceID: plan.Context.Source.File.ID, Definition: data, Hash: hash, State: "proposed", Revision: 1, Result: json.RawMessage(`{}`)}
	if err = t.SaveRecordProjection(ctx, r, 0); err != nil {
		return nil, err
	}
	return finishProjection(ctx, t, key, meaning, r)
}

// ProposeReviewedProjection lets a metadata-only client pin the complete private
// review by hash without disclosing source paths or full bindings to a model.
// Original-key replay precedes source revalidation and preserves its receipt.
func (s *Service) ProposeReviewedProjection(ctx context.Context, scope store.Scope, key, source, reviewHash string, options ProjectionOptions) (*Result, error) {
	if !keyPattern.MatchString(key) || !store.ValidID(source) || !hashPattern.MatchString(reviewHash) {
		return nil, ErrInput
	}
	options, err := projectionOptionsInput(options)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.projectionBegin(ctx, scope, options.Profile)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	_, meaning, err := canonical(struct {
		Kind, Source, Review string
		Options              ProjectionOptions
	}{"propose_reviewed_record_projection", source, reviewHash, options})
	if err != nil {
		return nil, err
	}
	if prior, e := t.CheckReplay(ctx, key, meaning); e != nil {
		return nil, e
	} else if prior != nil {
		return projectionReplayed(ctx, t, prior)
	}
	if err = s.projectionProposalAdmission(ctx, t); err != nil {
		return nil, err
	}
	if err = t.NamespaceLock(ctx); err != nil {
		return nil, err
	}
	view, err := s.projectionPlan(ctx, t, source, options, true)
	if err != nil {
		return nil, err
	}
	_, hash, err := canonical(view.Plan)
	if err != nil {
		return nil, err
	}
	if hash != reviewHash {
		return nil, store.ErrRevision
	}
	return s.stageProjectionProposal(ctx, t, key, meaning, view.Plan)
}
func (s *Service) DecideProjection(ctx context.Context, scope store.Scope, id, key string, decision PolicyRecheckDecision) (*Result, error) {
	if !keyPattern.MatchString(key) || !hashPattern.MatchString(decision.Hash) || decision.Revision < 1 || (decision.Operation != "approve" && decision.Operation != "cancel") {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	action := "workflow_manage"
	if decision.Operation == "approve" {
		action = "workflow_approve"
	}
	t, err := s.projectionExistingBegin(ctx, scope, id, action)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	_, meaning, _ := canonical(struct {
		Kind, ID string
		Decision PolicyRecheckDecision
	}{"decide_record_projection", id, decision})
	if prior, e := t.CheckReplay(ctx, key, meaning); e != nil {
		return nil, e
	} else if prior != nil {
		return projectionReplayed(ctx, t, prior)
	}
	r, err := t.RecordProjection(ctx, id, true)
	if err != nil {
		return nil, err
	}
	if r.Hash != decision.Hash || r.Revision != decision.Revision {
		return nil, store.ErrRevision
	}
	d, err := decodeProjection(r)
	if err != nil {
		return nil, err
	}
	if decision.Operation == "approve" {
		if r.State != "proposed" {
			return nil, store.ErrState
		}
		if err = t.NamespaceLock(ctx); err != nil {
			return nil, err
		}
		if _, err = s.projectionCurrent(ctx, t, d, true); err != nil {
			return nil, err
		}
		r.State = "approved"
	} else {
		now, e := t.DatabaseTime(ctx)
		if e != nil {
			return nil, e
		}
		if r.State != "proposed" && r.State != "approved" && r.State != "failed" && (r.State != "running" || r.LeaseUntil == nil || now.Before(*r.LeaseUntil)) {
			return nil, store.ErrState
		}
		r.State = "cancelled"
		r.WorkerID = ""
		r.LeaseUntil = nil
		r.Result = json.RawMessage(`{}`)
	}
	previous := r.Revision
	r.Revision++
	if err = t.SaveRecordProjection(ctx, r, previous); err != nil {
		return nil, err
	}
	return finishProjection(ctx, t, key, meaning, r)
}
func (s *Service) StartProjection(ctx context.Context, scope store.Scope, id, key string, decision ProjectionStartDecision) (*Result, error) {
	if !keyPattern.MatchString(key) || !hashPattern.MatchString(decision.Hash) || decision.Revision < 1 {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.projectionExistingBegin(ctx, scope, id, "workflow_execute")
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	_, meaning, _ := canonical(struct {
		Kind, ID string
		Decision ProjectionStartDecision
	}{"start_record_projection", id, decision})
	if prior, e := t.CheckReplay(ctx, key, meaning); e != nil {
		return nil, e
	} else if prior != nil {
		return projectionReplayed(ctx, t, prior)
	}
	r, err := t.RecordProjection(ctx, id, true)
	if err != nil {
		return nil, err
	}
	if r.Hash != decision.Hash || r.Revision != decision.Revision {
		return nil, store.ErrRevision
	}
	now, err := t.DatabaseTime(ctx)
	if err != nil {
		return nil, err
	}
	if r.Attempts >= 3 || (r.State != "approved" && r.State != "failed" && (r.State != "running" || r.LeaseUntil == nil || now.Before(*r.LeaseUntil))) {
		return nil, store.ErrState
	}
	d, err := decodeProjection(r)
	if err != nil {
		return nil, err
	}
	if err = t.NamespaceLock(ctx); err != nil {
		return nil, err
	}
	if _, err = s.projectionCurrent(ctx, t, d, true); err != nil {
		return nil, err
	}
	// Obtain the database clock after waiting for all current-state locks.
	now, err = t.DatabaseTime(ctx)
	if err != nil {
		return nil, err
	}
	until := now.Add(71 * time.Second)
	previous := r.Revision
	r.Revision++
	r.Attempts++
	r.State = "running"
	r.WorkerID = secure.NewID()
	r.LeaseUntil = &until
	r.Result = json.RawMessage(`{}`)
	if err = t.SaveRecordProjection(ctx, r, previous); err != nil {
		return nil, err
	}
	return finishProjection(ctx, t, key, meaning, r)
}
func (s *Service) GetProjection(ctx context.Context, scope store.Scope, id string) (*ProjectionView, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.projectionExistingBegin(ctx, scope, id, "")
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	r, err := t.RecordProjection(ctx, id, false)
	if err != nil {
		return nil, err
	}
	d, err := decodeProjection(r)
	if err != nil {
		return nil, err
	}
	if err = t.NamespaceLock(ctx); err != nil {
		return nil, err
	}
	v := &ProjectionView{Kind: "record_projection", Projection: r, Code: "review_current"}
	if _, err = s.projectionCurrent(ctx, t, d, false); err == nil {
		v.Current = true
	} else {
		v.Code = "review_unavailable"
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return v, t.Tx.Commit(ctx)
}
