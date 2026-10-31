package workflow

import (
	"context"
	"errors"
	"path"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

type CollectionSelection struct {
	Workflow  Reference `json:"workflow"`
	Timeout   int       `json:"timeout_seconds"`
	Authority int64     `json:"expected_authority_revision"`
}
type CollectionDefinition struct {
	Schema         int              `json:"schema_version"`
	Workflow       Reference        `json:"workflow"`
	Source         CollectionSource `json:"source"`
	Connection     ConnectionView   `json:"source_connection"`
	SourceIdentity string           `json:"source_identity"`
	Authority      int64            `json:"authority_revision"`
	StorageID      string           `json:"storage_id"`
	Root           string           `json:"namespace_root"`
	Timeout        int              `json:"timeout_seconds"`
	Effects        []Effect         `json:"effects"`
}
type CollectionPreview struct {
	Definition       CollectionDefinition `json:"definition"`
	Hash             string               `json:"definition_hash"`
	ExternalContact  bool                 `json:"external_contact"`
	ApprovalRequired bool                 `json:"approval_required"`
}
type CollectionStartRequest struct {
	Selection CollectionSelection `json:"selection"`
	Hash      string              `json:"definition_hash"`
}
type CollectionWorkRequest struct {
	Hash string `json:"definition_hash"`
}
type CollectionAction struct {
	Kind     string `json:"kind"`
	ID       string `json:"id"`
	Hash     string `json:"definition_hash"`
	State    string `json:"state"`
	Revision int64  `json:"revision"`
}
type CollectionView struct {
	Job                *store.CollectionJob    `json:"job"`
	Inputs             []store.CollectionInput `json:"inputs"`
	Current            bool                    `json:"current_authority"`
	Observed           string                  `json:"observed_state"`
	BusinessAcceptance string                  `json:"business_acceptance"`
	LocalStates        []CollectionLocalState  `json:"local_states"`
}
type CollectionLocalState struct {
	InputID string `json:"input_id"`
	State   string `json:"state"`
}

func (s *Service) collectionBegin(ctx context.Context, scope store.Scope, grants ...string) (*store.Transaction, error) {
	t, e := s.Custody.DB.BeginApproval(ctx, scope)
	if e != nil {
		return nil, e
	}
	fail := func(e error) (*store.Transaction, error) { t.Tx.Rollback(ctx); return nil, e }
	if t.Root != "/" {
		return fail(store.ErrForbidden)
	}
	for _, g := range grants {
		if e = t.Require(g); e != nil {
			return fail(e)
		}
	}
	if e = t.ScheduleLock(ctx, false); e != nil {
		return fail(e)
	}
	if e = t.CollectionLock(ctx, true); e != nil {
		return fail(e)
	}
	return t, nil
}
func collectionDefinition(j *store.CollectionJob) (*CollectionDefinition, error) {
	var d CollectionDefinition
	if Decode(j.Definition, &d) != nil || d.Schema != 1 || normalizeCollectionSource(d.Source) != nil || d.Workflow.ID != j.WorkflowID || d.Workflow.Version != j.WorkflowVersion || d.Workflow.Hash != j.WorkflowHash || d.Authority < 1 || d.Root != "/" || !store.ValidID(d.StorageID) || d.Timeout < 1 || d.Timeout > 3600 {
		return nil, store.ErrState
	}
	_, hash, e := digest(d)
	if e != nil || hash != j.Hash {
		return nil, store.ErrState
	}
	return &d, nil
}
func (s *Service) collectionPreview(ctx context.Context, t *store.Transaction, x CollectionSelection) (*CollectionPreview, error) {
	if x.Timeout < 1 || x.Timeout > 3600 || x.Authority < 1 || !store.ValidID(x.Workflow.ID) || x.Workflow.Version < 1 || !hashPattern.MatchString(x.Workflow.Hash) {
		return nil, ErrInput
	}
	if x.Authority != t.AuthorityRevision {
		return nil, store.ErrRevision
	}
	_, w, e := approved(ctx, t, x.Workflow)
	if e != nil {
		return nil, e
	}
	if w.Source == nil {
		return nil, ErrInput
	}
	if len(w.Steps) > 0 {
		if e = t.Require("deliver"); e != nil {
			return nil, e
		}
	}
	if w.Source.MaxFile > s.Custody.MaxFile || w.Source.MaxTotal > s.Custody.MaxStored {
		return nil, store.ErrLimit
	}
	_, connection, e := collectionConnection(ctx, t, w.Source)
	if e != nil {
		return nil, e
	}
	if s.Custody.Disk == nil {
		return nil, store.ErrState
	}
	if e = s.Custody.Disk.CheckIdentity(); e != nil {
		return nil, e
	}
	effects, e := workflowEffects(ctx, t, w)
	if e != nil {
		return nil, e
	}
	d := CollectionDefinition{Schema: 1, Workflow: x.Workflow, Source: *w.Source, Connection: *connection, SourceIdentity: secure.Digest([]byte(connection.ID + ":" + connection.Directory)), Authority: t.AuthorityRevision, StorageID: s.Custody.Disk.Identity(), Root: t.Root, Timeout: x.Timeout, Effects: effects}
	encoded, hash, e := digest(d)
	if e != nil {
		return nil, e
	}
	if len(encoded) > 24<<10 {
		return nil, store.ErrLimit
	}
	return &CollectionPreview{Definition: d, Hash: hash, ApprovalRequired: true}, nil
}
func (s *Service) PreviewCollection(ctx context.Context, scope store.Scope, x CollectionSelection) (*CollectionPreview, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, e := s.collectionBegin(ctx, scope, "workflow_execute", "write", "list", "read")
	if e != nil {
		return nil, e
	}
	defer t.Tx.Rollback(ctx)
	p, e := s.collectionPreview(ctx, t, x)
	if e != nil {
		return nil, e
	}
	if e = t.Reauthorize(ctx); e != nil {
		return nil, e
	}
	return p, t.Tx.Commit(ctx)
}
func collectionResult(ctx context.Context, t *store.Transaction, key, meaning string, j *store.CollectionJob) (*Result, error) {
	return scheduleResult(t, ctx, key, meaning, j.ID, CollectionAction{Kind: "workflow_collection", ID: j.ID, Hash: j.Hash, State: j.State, Revision: j.Revision})
}
func (s *Service) StartCollection(ctx context.Context, scope store.Scope, key string, x CollectionStartRequest) (*Result, error) {
	if !keyPattern.MatchString(key) || !hashPattern.MatchString(x.Hash) {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, e := s.collectionBegin(ctx, scope, "workflow_execute", "write", "list", "read")
	if e != nil {
		return nil, e
	}
	defer t.Tx.Rollback(ctx)
	_, meaning, e := digest(struct {
		Kind    string
		Request CollectionStartRequest
	}{"start_collection", x})
	if e != nil {
		return nil, e
	}
	if prior, e := replay(t, ctx, key, meaning); e != nil || prior != nil {
		return prior, e
	}
	p, e := s.collectionPreview(ctx, t, x.Selection)
	if e != nil {
		return nil, e
	}
	if p.Hash != x.Hash {
		return nil, store.ErrRevision
	}
	if e = t.CollectionAdmission(ctx, p.Definition.Workflow.ID); e != nil {
		return nil, e
	}
	now, e := t.DatabaseTime(ctx)
	if e != nil {
		return nil, e
	}
	encoded, _, e := digest(p.Definition)
	if e != nil {
		return nil, e
	}
	j := &store.CollectionJob{ID: secure.NewID(), WorkflowID: p.Definition.Workflow.ID, WorkflowVersion: p.Definition.Workflow.Version, WorkflowHash: p.Definition.Workflow.Hash, Definition: encoded, Hash: p.Hash, State: "queued", Revision: 1, Next: now, Created: now, Deadline: now.Add(time.Duration(p.Definition.Timeout) * time.Second), Reason: "awaiting_collection_worker"}
	if e = t.SaveCollection(ctx, j, 0); e != nil {
		return nil, e
	}
	return collectionResult(ctx, t, key, meaning, j)
}
func (s *Service) collectionRead(ctx context.Context, scope store.Scope) (*store.Transaction, error) {
	return s.scheduleRead(ctx, scope)
}
func collectionView(ctx context.Context, t *store.Transaction, j *store.CollectionJob) (*CollectionView, error) {
	if _, e := collectionDefinition(j); e != nil {
		return nil, e
	}
	inputs, e := t.CollectionInputs(ctx, j)
	if e != nil {
		return nil, e
	}
	current := t.CollectionDefinitionCurrent(ctx, j.Definition)
	if current != nil && !errors.Is(current, store.ErrCollection) {
		return nil, current
	}
	now, e := t.DatabaseTime(ctx)
	if e != nil {
		return nil, e
	}
	v := &CollectionView{Job: j, Inputs: inputs, Current: current == nil && j.Deadline.After(now) && j.State != "cancelled" && j.State != "expired", Observed: j.State, BusinessAcceptance: "unknown"}
	v.LocalStates = []CollectionLocalState{}
	for _, input := range inputs {
		state := "pending"
		if input.FileID != nil {
			state = "held_or_unavailable"
			if input.JobID == j.ID && !j.Captured {
				state = "awaiting_batch_capture"
			} else {
				if e = t.FileAvailable(ctx, *input.FileID); e == nil {
					entry, lookup := t.Entry(ctx, input.Target)
					if lookup != nil && !errors.Is(lookup, store.ErrNotFound) {
						return nil, lookup
					}
					state = "unpublished_or_removed"
					if lookup == nil && entry.Kind == "file" && entry.FileID == *input.FileID {
						state = "published"
					}
				} else if !errors.Is(e, store.ErrState) && !errors.Is(e, store.ErrNotFound) {
					return nil, e
				}
			}
		}
		v.LocalStates = append(v.LocalStates, CollectionLocalState{InputID: input.ID, State: state})
	}
	if j.State != "cancelled" && j.State != "expired" && !v.Current {
		v.Observed = "attention"
	}
	return v, nil
}
func (s *Service) CollectionStatus(ctx context.Context, scope store.Scope, id string) (*CollectionView, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, e := s.collectionRead(ctx, scope)
	if e != nil {
		return nil, e
	}
	defer t.Tx.Rollback(ctx)
	// Read without a writer lock, then confirm that the job revision did not
	// move while its input snapshot was assembled. Busy control writers cannot
	// block this metadata read behind a worker's effect guard.
	for attempt := 0; attempt < 3; attempt++ {
		j, e := t.Collection(ctx, id, false)
		if e != nil {
			return nil, e
		}
		v, e := collectionView(ctx, t, j)
		if e != nil {
			return nil, e
		}
		after, e := t.Collection(ctx, id, false)
		if e != nil {
			return nil, e
		}
		if after.Revision == j.Revision {
			return v, t.Tx.Commit(ctx)
		}
	}
	return nil, store.ErrRevision
}
func (s *Service) Collections(ctx context.Context, scope store.Scope, after string, limit int) (*store.CollectionPage, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, e := s.collectionRead(ctx, scope)
	if e != nil {
		return nil, e
	}
	defer t.Tx.Rollback(ctx)
	p, e := t.Collections(ctx, after, limit)
	if e != nil {
		return nil, e
	}
	return p, t.Tx.Commit(ctx)
}
func (s *Service) CancelCollection(ctx context.Context, scope store.Scope, id, key string, x Decision) (*Result, error) {
	if !store.ValidID(id) || !keyPattern.MatchString(key) || !hashPattern.MatchString(x.Hash) || x.Revision < 1 {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, e := s.collectionBegin(ctx, scope, "workflow_execute")
	if e != nil {
		return nil, e
	}
	defer t.Tx.Rollback(ctx)
	_, meaning, _ := digest(struct {
		Kind, ID string
		Decision Decision
	}{"cancel_collection", id, x})
	if prior, e := replay(t, ctx, key, meaning); e != nil || prior != nil {
		return prior, e
	}
	j, e := t.Collection(ctx, id, true)
	if e != nil {
		return nil, e
	}
	if j.Hash != x.Hash || j.Revision != x.Revision {
		return nil, store.ErrRevision
	}
	if j.State == "cancelled" || j.State == "expired" {
		return nil, store.ErrState
	}
	previous := j.Revision
	j.Revision++
	j.State = "cancelled"
	j.Owner = ""
	j.Until = nil
	j.Reason = "operator_cancelled"
	if e = t.SaveCollection(ctx, j, previous); e != nil {
		return nil, e
	}
	return collectionResult(ctx, t, key, meaning, j)
}
func (s *Service) RefreshCollection(ctx context.Context, scope store.Scope, id, key string, x Decision) (*Result, error) {
	if !store.ValidID(id) || !keyPattern.MatchString(key) || !hashPattern.MatchString(x.Hash) || x.Revision < 1 {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, e := s.collectionBegin(ctx, scope, "workflow_execute", "write", "list", "read")
	if e != nil {
		return nil, e
	}
	defer t.Tx.Rollback(ctx)
	_, meaning, _ := digest(struct {
		Kind, ID string
		Decision Decision
	}{"refresh_collection", id, x})
	if prior, e := replay(t, ctx, key, meaning); e != nil || prior != nil {
		return prior, e
	}
	j, e := t.Collection(ctx, id, true)
	if e != nil {
		return nil, e
	}
	if j.Hash != x.Hash || j.Revision != x.Revision {
		return nil, store.ErrRevision
	}
	if e = s.advanceCollection(ctx, t, j); e != nil {
		return nil, e
	}
	return collectionResult(ctx, t, key, meaning, j)
}
func (s *Service) advanceCollection(ctx context.Context, t *store.Transaction, j *store.CollectionJob) error {
	d, e := collectionDefinition(j)
	if e != nil {
		return e
	}
	if j.State != "captured" {
		return store.ErrState
	}
	now, e := t.DatabaseTime(ctx)
	if e != nil {
		return e
	}
	if !j.Deadline.After(now) {
		return store.ErrCollection
	}
	if e = t.CollectionDefinitionCurrent(ctx, j.Definition); e != nil {
		return e
	}
	if e = s.checkStorage(d.StorageID); e != nil {
		return e
	}
	_, w, e := approved(ctx, t, d.Workflow)
	if e != nil {
		return e
	}
	if len(w.Steps) == 0 {
		return nil
	}
	if e = t.Require("deliver"); e != nil {
		return e
	}
	inputs, e := t.CollectionInputs(ctx, j)
	if e != nil {
		return e
	}
	// A batch is routed only after every newly collected sibling has passed
	// its ordinary intake policy. Already claimed inputs belong to their
	// original job and are neither republished nor sent again by this job.
	for _, input := range inputs {
		if input.JobID != j.ID || input.FileID == nil {
			continue
		}
		if e = t.FileAvailable(ctx, *input.FileID); errors.Is(e, store.ErrState) {
			return nil
		} else if e != nil {
			return e
		}
	}
	for index := range inputs {
		i := &inputs[index]
		if i.State != "accepted" || i.JobID != j.ID || i.FileID == nil {
			continue
		}
		if e = t.FileAvailable(ctx, *i.FileID); errors.Is(e, store.ErrState) {
			continue
		} else if e != nil {
			return e
		}
		if e = t.FileAccessible(ctx, *i.FileID); e != nil {
			return e
		}
		entry, e := t.Entry(ctx, i.Target)
		if e != nil {
			return e
		}
		if entry.Kind != "file" || entry.FileID != *i.FileID {
			return store.ErrState
		}
		if e = t.CheckAncestors(ctx, path.Join(d.Source.Directory, "collection-target")); e != nil {
			return e
		}
		if e = t.DeliveryAdmission(ctx, len(w.Steps)); errors.Is(e, store.ErrLimit) {
			break
		} else if e != nil {
			return e
		}
		file, e := t.File(ctx, *i.FileID)
		if e != nil {
			return e
		}
		run, e := s.stageRun(ctx, t, RunRequest{Workflow: d.Workflow, FileID: file.ID}, w, file, d.StorageID)
		if e != nil {
			return e
		}
		previous := i.Revision
		i.Revision++
		i.State = "queued"
		i.RunID = &run.ID
		if e = t.SaveCollectionInput(ctx, i, previous); e != nil {
			return e
		}
	}
	return nil
}
