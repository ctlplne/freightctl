package workflow

import (
	"context"
	"reflect"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

type CollectionRoutingSelection struct {
	Collection Decision  `json:"collection"`
	Workflow   Reference `json:"workflow"`
	Authority  int64     `json:"expected_authority_revision"`
}
type CollectionRoutingProposal struct {
	Selection CollectionRoutingSelection `json:"selection"`
	Hash      string                     `json:"definition_hash"`
}
type CollectionRoutingJob struct {
	ID       string `json:"id"`
	Revision int64  `json:"revision"`
	Hash     string `json:"definition_hash"`
}
type CollectionRoutingBinding struct {
	InputID  string `json:"input_id"`
	FileID   string `json:"file_id"`
	PlanHash string `json:"plan_hash"`
}
type CollectionRoutingReference struct {
	ID       string `json:"id"`
	Version  int    `json:"version"`
	Hash     string `json:"definition_hash"`
	Revision int64  `json:"revision"`
}
type CollectionRoutingDefinition struct {
	Schema           int                         `json:"schema_version"`
	Collection       CollectionRoutingJob        `json:"collection"`
	OriginalWorkflow Reference                   `json:"original_workflow"`
	Workflow         Reference                   `json:"workflow"`
	ManifestHash     string                      `json:"manifest_hash"`
	Authority        int64                       `json:"authority_revision"`
	StorageID        string                      `json:"storage_id"`
	Root             string                      `json:"namespace_root"`
	Inputs           []CollectionRoutingBinding  `json:"inputs"`
	Previous         *CollectionRoutingReference `json:"previous,omitempty"`
}
type CollectionRoutingPreview struct {
	Definition       CollectionRoutingDefinition `json:"definition"`
	Hash             string                      `json:"definition_hash"`
	ExternalContact  bool                        `json:"external_contact"`
	ApprovalRequired bool                        `json:"approval_required"`
}
type CollectionRoutingAction struct {
	Kind     string `json:"kind"`
	ID       string `json:"id"`
	JobID    string `json:"job_id"`
	Version  int    `json:"version"`
	Hash     string `json:"definition_hash"`
	State    string `json:"state"`
	Revision int64  `json:"revision"`
}

func routingReference(r *store.CollectionRouting) *CollectionRoutingReference {
	if r == nil {
		return nil
	}
	return &CollectionRoutingReference{ID: r.ID, Version: r.Version, Hash: r.Hash, Revision: r.Revision}
}

func validateCollectionRoutingDefinition(d CollectionRoutingDefinition) error {
	validRef := func(r Reference) bool {
		return store.ValidID(r.ID) && r.Version > 0 && r.Version <= 2147483647 && hashPattern.MatchString(r.Hash)
	}
	if d.Schema != 1 || !store.ValidID(d.Collection.ID) || d.Collection.Revision < 1 || !hashPattern.MatchString(d.Collection.Hash) || !validRef(d.OriginalWorkflow) || !validRef(d.Workflow) || d.Workflow.ID != d.OriginalWorkflow.ID || !hashPattern.MatchString(d.ManifestHash) || d.Authority < 1 || !store.ValidID(d.StorageID) || d.Root != "/" || len(d.Inputs) < 1 || len(d.Inputs) > 64 {
		return ErrInput
	}
	if p := d.Previous; p != nil && (!store.ValidID(p.ID) || p.Version < 1 || p.Version > 2147483647 || !hashPattern.MatchString(p.Hash) || p.Revision < 1) {
		return ErrInput
	}
	inputs, files := map[string]bool{}, map[string]bool{}
	for _, b := range d.Inputs {
		if !store.ValidID(b.InputID) || !store.ValidID(b.FileID) || !hashPattern.MatchString(b.PlanHash) || inputs[b.InputID] || files[b.FileID] {
			return ErrInput
		}
		inputs[b.InputID], files[b.FileID] = true, true
	}
	encoded, _, err := digest(d)
	if err != nil {
		return err
	}
	if len(encoded) > 24<<10 {
		return store.ErrLimit
	}
	return nil
}

func collectionRoutingDefinition(r *store.CollectionRouting) (*CollectionRoutingDefinition, error) {
	var d CollectionRoutingDefinition
	if Decode(r.Definition, &d) != nil || validateCollectionRoutingDefinition(d) != nil || d.Collection.ID != r.JobID {
		return nil, store.ErrState
	}
	_, hash, err := digest(d)
	if err != nil || hash != r.Hash {
		return nil, store.ErrState
	}
	return &d, nil
}

type collectionRoutingExecution struct {
	Workflow      Reference
	Definition    *Definition
	Authorization *store.CollectionRouting
	Binding       *CollectionRoutingDefinition
}

// The effective choice comes from an approved decision, never the latest draft
// or the latest workflow. Original capture checks remain the caller's duty.
func (s *Service) effectiveCollectionRouting(ctx context.Context, t *store.Transaction, j *store.CollectionJob, original *CollectionDefinition) (*collectionRoutingExecution, error) {
	r, err := t.CurrentCollectionRouting(ctx, j.ID)
	if err != nil {
		return nil, err
	}
	x := &collectionRoutingExecution{Workflow: original.Workflow, Authorization: r}
	if r != nil {
		if r.State != "approved" || r.ApprovalAuthority != t.AuthorityRevision {
			return nil, store.ErrCollection
		}
		d, err := collectionRoutingDefinition(r)
		if err != nil {
			return nil, err
		}
		if d.Collection.ID != j.ID || d.Collection.Revision != j.Revision || d.Collection.Hash != j.Hash || d.OriginalWorkflow != original.Workflow || j.ManifestHash == nil || d.ManifestHash != *j.ManifestHash || d.Authority != t.AuthorityRevision || d.StorageID != original.StorageID || d.Root != t.Root {
			return nil, store.ErrRevision
		}
		x.Workflow, x.Binding = d.Workflow, d
	}
	_, x.Definition, err = approved(ctx, t, x.Workflow)
	if err != nil {
		return nil, err
	}
	if r != nil && (x.Definition.Schema != 2 || x.Definition.Source == nil || !reflect.DeepEqual(*x.Definition.Source, original.Source)) {
		return nil, store.ErrState
	}
	return x, nil
}

func (s *Service) originalCollectionPlan(ctx context.Context, t *store.Transaction, j *store.CollectionJob, w *Definition, input store.CollectionInput) (*ExecutionPlan, error) {
	if input.JobID != j.ID || input.State != "accepted" || input.RunID != nil || input.FileID == nil {
		return nil, store.ErrState
	}
	if err := t.FileAvailable(ctx, *input.FileID); err != nil {
		return nil, err
	}
	if err := t.FileAccessible(ctx, *input.FileID); err != nil {
		return nil, err
	}
	entry, err := t.Entry(ctx, input.Target)
	if err != nil {
		return nil, err
	}
	if entry.Kind != "file" || entry.FileID != *input.FileID {
		return nil, store.ErrState
	}
	file, err := t.File(ctx, *input.FileID)
	if err != nil {
		return nil, err
	}
	raw, err := t.CollectionOriginalRoutingFacts(ctx, j.ID, file.ID)
	if err != nil {
		return nil, err
	}
	var facts RoutingFacts
	if Decode(raw, &facts) != nil || facts.File != *file || facts.Source == nil || facts.Source.CollectionID != j.ID || facts.Source.Name != input.Name || j.ManifestHash == nil || facts.Source.ManifestHash != *j.ManifestHash {
		return nil, store.ErrState
	}
	return CompileProgram(*w, facts)
}

func (s *Service) collectionRoutingPreview(ctx context.Context, t *store.Transaction, job string, x CollectionRoutingSelection) (*CollectionRoutingPreview, error) {
	if !store.ValidID(job) || x.Authority < 1 || x.Collection.Revision < 1 || !hashPattern.MatchString(x.Collection.Hash) || !store.ValidID(x.Workflow.ID) || x.Workflow.Version < 1 || x.Workflow.Version > 2147483647 || !hashPattern.MatchString(x.Workflow.Hash) {
		return nil, ErrInput
	}
	if x.Authority != t.AuthorityRevision {
		return nil, store.ErrRevision
	}
	j, err := t.Collection(ctx, job, false)
	if err != nil {
		return nil, err
	}
	if j.Hash != x.Collection.Hash || j.Revision != x.Collection.Revision {
		return nil, store.ErrRevision
	}
	d, err := collectionDefinition(j)
	if err != nil {
		return nil, err
	}
	now, err := t.DatabaseTime(ctx)
	if err != nil {
		return nil, err
	}
	if !j.Captured || j.State != "captured" || j.ManifestHash == nil || !j.Deadline.After(now) {
		return nil, store.ErrCollection
	}
	if err = t.CollectionDefinitionCurrent(ctx, j.Definition); err != nil {
		return nil, err
	}
	if err = s.checkStorage(d.StorageID); err != nil {
		return nil, err
	}
	_, w, err := approved(ctx, t, x.Workflow)
	if err != nil {
		return nil, err
	}
	if x.Workflow.ID != j.WorkflowID || w.Schema != 2 || w.Source == nil || !reflect.DeepEqual(*w.Source, d.Source) {
		return nil, ErrInput
	}
	if len(w.Steps) > 0 {
		if err = t.Require("deliver"); err != nil {
			return nil, err
		}
	}
	prior, err := t.CurrentCollectionRouting(ctx, job)
	if err != nil {
		return nil, err
	}
	inputs, err := t.CollectionInputs(ctx, j)
	if err != nil {
		return nil, err
	}
	definition := CollectionRoutingDefinition{Schema: 1, Collection: CollectionRoutingJob{ID: job, Revision: j.Revision, Hash: j.Hash}, OriginalWorkflow: d.Workflow, Workflow: x.Workflow, ManifestHash: *j.ManifestHash, Authority: t.AuthorityRevision, StorageID: d.StorageID, Root: t.Root, Inputs: []CollectionRoutingBinding{}, Previous: routingReference(prior)}
	for _, input := range inputs {
		if input.JobID != job {
			continue
		}
		plan, err := s.originalCollectionPlan(ctx, t, j, w, input)
		if err != nil {
			return nil, err
		}
		_, hash, err := digest(plan)
		if err != nil {
			return nil, err
		}
		definition.Inputs = append(definition.Inputs, CollectionRoutingBinding{InputID: input.ID, FileID: *input.FileID, PlanHash: hash})
	}
	if err = validateCollectionRoutingDefinition(definition); err != nil {
		return nil, err
	}
	_, hash, err := digest(definition)
	if err != nil {
		return nil, err
	}
	return &CollectionRoutingPreview{Definition: definition, Hash: hash, ApprovalRequired: true}, nil
}

func (s *Service) PreviewCollectionRouting(ctx context.Context, scope store.Scope, job string, x CollectionRoutingSelection) (*CollectionRoutingPreview, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.collectionBegin(ctx, scope, "workflow_execute", "read", "write", "list")
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	p, err := s.collectionRoutingPreview(ctx, t, job, x)
	if err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return p, t.Tx.Commit(ctx)
}

// Review one full plan at a time. The batch authorization carries bounded
// fingerprints, so reviewing 64 large plans cannot create a giant response.
func (s *Service) PreviewCollectionRoutingInput(ctx context.Context, scope store.Scope, job, inputID string, x CollectionRoutingSelection) (*RunPreview, error) {
	if !store.ValidID(inputID) {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.collectionBegin(ctx, scope, "workflow_execute", "read", "write", "list")
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	p, err := s.collectionRoutingPreview(ctx, t, job, x)
	if err != nil {
		return nil, err
	}
	var binding *CollectionRoutingBinding
	for index := range p.Definition.Inputs {
		if p.Definition.Inputs[index].InputID == inputID {
			binding = &p.Definition.Inputs[index]
			break
		}
	}
	if binding == nil {
		return nil, store.ErrNotFound
	}
	j, err := t.Collection(ctx, job, false)
	if err != nil {
		return nil, err
	}
	_, w, err := approved(ctx, t, x.Workflow)
	if err != nil {
		return nil, err
	}
	inputs, err := t.CollectionInputs(ctx, j)
	if err != nil {
		return nil, err
	}
	var plan *ExecutionPlan
	for _, input := range inputs {
		if input.ID == inputID && input.JobID == job {
			plan, err = s.originalCollectionPlan(ctx, t, j, w, input)
			break
		}
	}
	if err != nil {
		return nil, err
	}
	if plan == nil {
		return nil, store.ErrNotFound
	}
	_, hash, err := digest(plan)
	if err != nil {
		return nil, err
	}
	if hash != binding.PlanHash || plan.Facts.File.ID != binding.FileID {
		return nil, store.ErrRevision
	}
	effects, err := workflowEffects(ctx, t, w)
	if err != nil {
		return nil, err
	}
	preview := &RunPreview{Workflow: x.Workflow, Source: plan.Facts.File, Potential: effects, Selected: []Effect{}, Plan: plan, PlanHash: hash}
	byID := map[string]Effect{}
	for _, effect := range effects {
		byID[effect.StepID] = effect
	}
	for _, id := range plan.Steps {
		effect, ok := byID[id]
		if !ok {
			return nil, store.ErrState
		}
		preview.Selected = append(preview.Selected, effect)
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return preview, t.Tx.Commit(ctx)
}

func (s *Service) CollectionRoutingStatus(ctx context.Context, scope store.Scope, job, id string) (*store.CollectionRouting, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.collectionRead(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	r, err := t.CollectionRouting(ctx, job, id, false)
	if err != nil {
		return nil, err
	}
	if _, err = collectionRoutingDefinition(r); err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return r, t.Tx.Commit(ctx)
}

func (s *Service) CollectionRoutingHistory(ctx context.Context, scope store.Scope, job string, after, limit int) (*store.CollectionRoutingPage, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.collectionRead(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if _, err = t.Collection(ctx, job, false); err != nil {
		return nil, err
	}
	p, err := t.CollectionRoutingHistory(ctx, job, after, limit)
	if err != nil {
		return nil, err
	}
	for _, r := range p.Authorizations {
		if _, err = collectionRoutingDefinition(&r); err != nil {
			return nil, err
		}
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return p, t.Tx.Commit(ctx)
}

func collectionRoutingResult(ctx context.Context, t *store.Transaction, key, meaning string, r *store.CollectionRouting) (*Result, error) {
	return scheduleResult(t, ctx, key, meaning, r.ID, CollectionRoutingAction{Kind: "workflow_collection_routing", ID: r.ID, JobID: r.JobID, Version: r.Version, Hash: r.Hash, State: r.State, Revision: r.Revision})
}

func (s *Service) ProposeCollectionRouting(ctx context.Context, scope store.Scope, job, key string, x CollectionRoutingProposal) (*Result, error) {
	if !store.ValidID(job) || !keyPattern.MatchString(key) || !hashPattern.MatchString(x.Hash) {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.collectionBegin(ctx, scope, "workflow_execute", "read", "write", "list")
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	_, meaning, err := digest(struct {
		Kind, Job string
		Request   CollectionRoutingProposal
	}{"propose_collection_routing", job, x})
	if err != nil {
		return nil, err
	}
	if prior, err := replay(t, ctx, key, meaning); err != nil || prior != nil {
		return prior, err
	}
	p, err := s.collectionRoutingPreview(ctx, t, job, x.Selection)
	if err != nil {
		return nil, err
	}
	if p.Hash != x.Hash {
		return nil, store.ErrRevision
	}
	version, err := t.CollectionRoutingVersion(ctx, job)
	if err != nil {
		return nil, err
	}
	if version >= 2147483647 {
		return nil, store.ErrLimit
	}
	raw, _, err := digest(p.Definition)
	if err != nil {
		return nil, err
	}
	r := &store.CollectionRouting{ID: secure.NewID(), JobID: job, Version: version + 1, Definition: raw, Hash: p.Hash, State: "proposed", Revision: 1}
	if err = t.SaveCollectionRouting(ctx, r, 0); err != nil {
		return nil, err
	}
	return collectionRoutingResult(ctx, t, key, meaning, r)
}

func (s *Service) DecideCollectionRouting(ctx context.Context, scope store.Scope, job, id, key, action string, x Decision) (*Result, error) {
	if !store.ValidID(job) || !store.ValidID(id) || !keyPattern.MatchString(key) || !hashPattern.MatchString(x.Hash) || x.Revision < 1 || (action != "approve" && action != "revoke" && action != "withdraw") {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	grant := "workflow_approve"
	if action == "withdraw" {
		grant = "workflow_execute"
	}
	t, err := s.collectionBegin(ctx, scope, grant, "read")
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	_, meaning, err := digest(struct {
		Kind, Job, ID, Action string
		Decision              Decision
	}{"decide_collection_routing", job, id, action, x})
	if err != nil {
		return nil, err
	}
	if prior, err := replay(t, ctx, key, meaning); err != nil || prior != nil {
		return prior, err
	}
	r, err := t.CollectionRouting(ctx, job, id, true)
	if err != nil {
		return nil, err
	}
	if r.Hash != x.Hash || r.Revision != x.Revision {
		return nil, store.ErrRevision
	}
	d, err := collectionRoutingDefinition(r)
	if err != nil {
		return nil, err
	}
	switch action {
	case "approve":
		if r.State != "proposed" {
			return nil, store.ErrState
		}
		for _, grant := range []string{"workflow_execute", "write", "list"} {
			if err = t.Require(grant); err != nil {
				return nil, err
			}
		}
		p, err := s.collectionRoutingPreview(ctx, t, job, CollectionRoutingSelection{Collection: Decision{Hash: d.Collection.Hash, Revision: d.Collection.Revision}, Workflow: d.Workflow, Authority: d.Authority})
		if err != nil {
			return nil, err
		}
		if p.Hash != r.Hash {
			return nil, store.ErrRevision
		}
		r.State, r.ApprovalAuthority = "approved", t.AuthorityRevision
	case "revoke":
		if r.State != "approved" {
			return nil, store.ErrState
		}
		r.State = "revoked"
	case "withdraw":
		if r.State != "proposed" {
			return nil, store.ErrState
		}
		r.State = "withdrawn"
	}
	previous := r.Revision
	r.Revision++
	if err = t.SaveCollectionRouting(ctx, r, previous); err != nil {
		return nil, err
	}
	return collectionRoutingResult(ctx, t, key, meaning, r)
}
