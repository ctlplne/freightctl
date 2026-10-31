package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"path"
	"reflect"
	"strconv"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/delivery"
	"github.com/ctlplne/freightctl/internal/store"
)

// collectionWorkerBegin deliberately avoids the broad account-writer lock.
// Short shared effect guards allow current metadata to stay readable while a
// credential/configuration change waits for an already admitted check to finish.
func (s *Service) collectionWorkerBegin(ctx context.Context, scope store.Scope) (*store.Transaction, error) {
	t, e := s.begin(ctx, scope, "workflow_execute", "write", "list", "read")
	if e != nil {
		return nil, e
	}
	if e = t.CollectionLock(ctx, false); e != nil {
		t.Tx.Rollback(ctx)
		return nil, e
	}
	return t, nil
}
func (s *Service) currentCollection(ctx context.Context, t *store.Transaction, j *store.CollectionJob) (*CollectionDefinition, *ConnectionDefinition, error) {
	d, e := collectionDefinition(j)
	if e != nil {
		return nil, nil, e
	}
	if d.Authority != t.AuthorityRevision || d.Root != t.Root {
		return nil, nil, store.ErrCollection
	}
	if e = t.CollectionDefinitionCurrent(ctx, j.Definition); e != nil {
		return nil, nil, e
	}
	if e = s.checkStorage(d.StorageID); e != nil {
		return nil, nil, e
	}
	if d.Source.MaxFile > s.Custody.MaxFile || d.Source.MaxTotal > s.Custody.MaxStored {
		return nil, nil, store.ErrLimit
	}
	_, w, e := approved(ctx, t, d.Workflow)
	if e != nil {
		return nil, nil, e
	}
	if w.Source == nil || !reflect.DeepEqual(*w.Source, d.Source) {
		return nil, nil, store.ErrCollection
	}
	if len(w.Steps) > 0 {
		if e = t.Require("deliver"); e != nil {
			return nil, nil, e
		}
	}
	c, v, e := collectionConnection(ctx, t, &d.Source)
	if e != nil {
		return nil, nil, e
	}
	effects, e := workflowEffects(ctx, t, w)
	if e != nil {
		return nil, nil, e
	}
	if !reflect.DeepEqual(*v, d.Connection) || !reflect.DeepEqual(effects, d.Effects) {
		return nil, nil, store.ErrCollection
	}
	return d, c, nil
}
func (s *Service) collectionLease(ctx context.Context, t *store.Transaction, j *store.CollectionJob, owner string, fence int64) (*CollectionDefinition, *ConnectionDefinition, error) {
	now, e := t.DatabaseTime(ctx)
	if e != nil {
		return nil, nil, e
	}
	if j.State != "reading" || j.Owner != owner || j.Fence != fence || j.Until == nil || !j.Until.After(now) || !j.Deadline.After(now) {
		return nil, nil, store.ErrCollection
	}
	return s.currentCollection(ctx, t, j)
}
func (s *Service) checkCollectionLease(ctx context.Context, scope store.Scope, id, owner string, fence int64, renew bool) error {
	t, e := s.collectionWorkerBegin(ctx, scope)
	if e != nil {
		return e
	}
	defer t.Tx.Rollback(ctx)
	j, e := t.Collection(ctx, id, renew)
	if e != nil {
		return e
	}
	if renew && j.State == "captured" && j.Fence == fence {
		return t.Tx.Commit(ctx)
	}
	if _, _, e = s.collectionLease(ctx, t, j, owner, fence); e != nil {
		return e
	}
	if renew {
		now, e := t.DatabaseTime(ctx)
		if e != nil {
			return e
		}
		until := now.Add(30 * time.Second)
		if until.After(j.Deadline) {
			until = j.Deadline
		}
		previous := j.Revision
		j.Revision++
		j.Until = &until
		if e = t.SaveCollection(ctx, j, previous); e != nil {
			return e
		}
	}
	return t.Tx.Commit(ctx)
}
func (s *Service) claimCollection(ctx context.Context, scope store.Scope, id, hash, owner string) (*store.CollectionJob, *CollectionDefinition, *ConnectionDefinition, error) {
	t, e := s.collectionWorkerBegin(ctx, scope)
	if e != nil {
		return nil, nil, nil, e
	}
	defer t.Tx.Rollback(ctx)
	j, e := t.Collection(ctx, id, true)
	if e != nil {
		return nil, nil, nil, e
	}
	if j.Hash != hash {
		return nil, nil, nil, store.ErrRevision
	}
	d, c, e := s.currentCollection(ctx, t, j)
	if e != nil {
		return nil, nil, nil, e
	}
	now, e := t.DatabaseTime(ctx)
	if e != nil {
		return nil, nil, nil, e
	}
	if !j.Deadline.After(now) || j.Attempts >= 8 || j.Next.After(now) || (j.State != "queued" && j.State != "retry" && j.State != "attention" && !(j.State == "reading" && j.Until != nil && !j.Until.After(now))) {
		return nil, nil, nil, store.ErrCollection
	}
	if j.State == "attention" {
		if e = t.CollectionAdmission(ctx, j.WorkflowID); e != nil {
			return nil, nil, nil, e
		}
	}
	previous := j.Revision
	j.Revision++
	j.Fence++
	j.Attempts++
	j.Owner = owner
	until := now.Add(30 * time.Second)
	if until.After(j.Deadline) {
		until = j.Deadline
	}
	j.Until = &until
	j.State = "reading"
	j.Reason = "source_read_pending"
	if e = t.SaveCollection(ctx, j, previous); e != nil {
		return nil, nil, nil, e
	}
	return j, d, c, t.Tx.Commit(ctx)
}
func (s *Service) captureCollectionManifest(ctx context.Context, scope store.Scope, id, owner string, fence int64, m *CollectionManifest, hash string) error {
	t, e := s.collectionWorkerBegin(ctx, scope)
	if e != nil {
		return e
	}
	defer t.Tx.Rollback(ctx)
	j, e := t.Collection(ctx, id, true)
	if e != nil {
		return e
	}
	d, _, e := s.collectionLease(ctx, t, j, owner, fence)
	if e != nil {
		return e
	}
	if j.Manifest != nil {
		return store.ErrState
	}
	encoded, actual, e := digest(m)
	if e != nil {
		return e
	}
	if actual != hash {
		return store.ErrState
	}
	prior, e := t.CollectionBatch(ctx, j.WorkflowID, d.SourceIdentity, m.Batch)
	if e != nil {
		return e
	}
	if prior != nil && (prior.Hash != hash || !jsonEqual(prior.Manifest, encoded)) {
		return store.ErrConflict
	}
	previous := j.Revision
	j.Revision++
	j.Manifest = encoded
	j.ManifestHash = &hash
	j.Reason = "producer_batch_bound"
	if e = t.SaveCollection(ctx, j, previous); e != nil {
		return e
	}
	if prior == nil {
		if e = t.SaveCollectionBatch(ctx, &store.CollectionBatch{ID: secure.NewID(), JobID: j.ID, WorkflowID: j.WorkflowID, SourceIdentity: d.SourceIdentity, ProducerID: m.Batch, Hash: hash, Manifest: encoded}); e != nil {
			return e
		}
	}
	for _, file := range m.Files {
		identity := secure.Digest([]byte(d.SourceIdentity + ":" + file.Name + ":" + strconv.FormatInt(file.Size, 10) + ":" + file.SHA256))
		existing, e := t.CollectionInputIdentity(ctx, j.WorkflowID, identity)
		if e != nil {
			return e
		}
		if existing != nil {
			if existing.State == "pending" && existing.JobID != j.ID {
				return store.ErrCollection
			}
			continue
		}
		i := &store.CollectionInput{ID: secure.NewID(), JobID: j.ID, WorkflowID: j.WorkflowID, SourceIdentity: d.SourceIdentity, Identity: identity, Name: file.Name, Size: file.Size, SHA256: file.SHA256, Target: path.Join(d.Source.Directory, file.SHA256+"-"+file.Name), ObjectID: secure.NewID(), State: "pending", Revision: 1, Fence: fence, Owner: owner}
		if e = t.SaveCollectionInput(ctx, i, 0); e != nil {
			return e
		}
	}
	return t.Tx.Commit(ctx)
}
func jsonEqual(a, b json.RawMessage) bool {
	var x, y any
	return json.Unmarshal(a, &x) == nil && json.Unmarshal(b, &y) == nil && reflect.DeepEqual(x, y)
}
func (s *Service) prepareCollectionInput(ctx context.Context, scope store.Scope, id, input, owner string, fence int64, sealed bool, object string) (*store.CollectionInput, error) {
	t, e := s.collectionWorkerBegin(ctx, scope)
	if e != nil {
		return nil, e
	}
	defer t.Tx.Rollback(ctx)
	j, e := t.Collection(ctx, id, true)
	if e != nil {
		return nil, e
	}
	if _, _, e = s.collectionLease(ctx, t, j, owner, fence); e != nil {
		return nil, e
	}
	i, e := t.CollectionInput(ctx, input, true)
	if e != nil {
		return nil, e
	}
	if i.JobID != j.ID || i.State != "pending" || i.ObjectID != object {
		return nil, store.ErrCollection
	}
	previous := i.Revision
	i.Revision++
	i.Owner = owner
	i.Fence = fence
	if !sealed {
		i.ObjectID = secure.NewID()
	}
	if e = t.SaveCollectionInput(ctx, i, previous); e != nil {
		return nil, e
	}
	return i, t.Tx.Commit(ctx)
}
func (s *Service) acceptCollectionInput(ctx context.Context, scope store.Scope, id, owner string, fence int64, i *store.CollectionInput) error {
	_, _, e := s.Custody.AcceptSealedAt(ctx, scope, "collect-"+i.ID, store.File{ID: i.ObjectID, Size: i.Size, SHA256: i.SHA256}, custody.UploadTarget{Path: i.Target}, func(ctx context.Context, t *store.Transaction, file *store.File, held bool) error {
		if e := t.CollectionLock(ctx, false); e != nil {
			return e
		}
		j, e := t.Collection(ctx, id, true)
		if e != nil {
			return e
		}
		if _, _, e = s.collectionLease(ctx, t, j, owner, fence); e != nil {
			return e
		}
		current, e := t.CollectionInput(ctx, i.ID, true)
		if e != nil {
			return e
		}
		if current.JobID != id || current.State != "pending" || current.ObjectID != file.ID || current.Owner != owner || current.Fence != fence || current.Target != i.Target || current.Size != file.Size || current.SHA256 != file.SHA256 {
			return store.ErrCollection
		}
		previous := current.Revision
		current.Revision++
		current.State = "accepted"
		current.FileID = &file.ID
		return t.SaveCollectionInput(ctx, current, previous)
	})
	return e
}
func (s *Service) completeCollectionWork(ctx context.Context, scope store.Scope, id, owner string, fence int64, key, meaning string) (*Result, error) {
	t, e := s.collectionWorkerBegin(ctx, scope)
	if e != nil {
		return nil, e
	}
	defer t.Tx.Rollback(ctx)
	if e = t.NamespaceLock(ctx); e != nil {
		return nil, e
	}
	j, e := t.Collection(ctx, id, true)
	if e != nil {
		return nil, e
	}
	if _, _, e = s.collectionLease(ctx, t, j, owner, fence); e != nil {
		return nil, e
	}
	inputs, e := t.CollectionInputs(ctx, j)
	if e != nil {
		return nil, e
	}
	if len(inputs) == 0 {
		return nil, store.ErrCollection
	}
	for _, i := range inputs {
		if i.State == "pending" || i.FileID == nil {
			return nil, store.ErrCollection
		}
	}
	previous := j.Revision
	j.Revision++
	j.State = "captured"
	j.Captured = true
	j.Owner = ""
	j.Until = nil
	j.Reason = "batch_captured"
	if e = t.SaveCollection(ctx, j, previous); e != nil {
		return nil, e
	}
	for _, input := range inputs {
		if input.JobID != j.ID || input.FileID == nil {
			continue
		}
		if e = t.FileAvailable(ctx, *input.FileID); errors.Is(e, store.ErrState) {
			continue
		} else if e != nil {
			return nil, e
		}
		if _, e = t.ApplyPathCommand(ctx, "collect-publish-"+input.ID, store.PathCommand{Operation: "publish", Path: input.Target, FileID: *input.FileID}, s.Custody.NamespaceMaxEntries); e != nil {
			return nil, e
		}
	}
	return collectionResult(ctx, t, key, meaning, j)
}
func (s *Service) failedCollectionWork(scope store.Scope, id, owner string, fence int64, key, meaning, reason string, attention bool) (*Result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	t, e := s.Custody.DB.Begin(ctx, scope)
	if e != nil {
		return nil, e
	}
	defer t.Tx.Rollback(ctx)
	if e = t.Require("workflow_execute"); e != nil {
		return nil, e
	}
	if e = t.CollectionLock(ctx, false); e != nil {
		return nil, e
	}
	j, e := t.Collection(ctx, id, true)
	if e != nil {
		return nil, e
	}
	if j.State != "reading" || j.Owner != owner || j.Fence != fence {
		return nil, store.ErrCollection
	}
	now, e := t.DatabaseTime(ctx)
	if e != nil {
		return nil, e
	}
	previous := j.Revision
	j.Revision++
	j.State = "retry"
	if attention || j.Attempts >= 8 || j.Until == nil || !j.Until.After(now) {
		j.State = "attention"
	}
	if !j.Deadline.After(now) {
		j.State = "expired"
	}
	j.Owner = ""
	j.Until = nil
	j.Reason = reason
	if j.State == "retry" {
		delay := time.Duration(1<<min(j.Attempts, 6)) * time.Second
		j.Next = now.Add(delay)
		if j.Next.After(j.Deadline) {
			j.Next = j.Deadline
		}
	}
	if e = t.SaveCollection(ctx, j, previous); e != nil {
		return nil, e
	}
	return collectionResult(ctx, t, key, meaning, j)
}

// WorkCollection performs only the approved read/copy input stage. Downstream
// intent admission is a separate metadata refresh; ordinary workflow Work and
// its exact-file independent approval remain responsible for every send.
func (s *Service) WorkCollection(ctx context.Context, scope store.Scope, id, key string, x CollectionWorkRequest) (*Result, error) {
	if !store.ValidID(id) || !keyPattern.MatchString(key) || !hashPattern.MatchString(x.Hash) {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	_, meaning, _ := digest(struct{ Kind, ID, Hash string }{"work_collection", id, x.Hash})
	t, e := s.collectionWorkerBegin(ctx, scope)
	if e != nil {
		return nil, e
	}
	defer t.Tx.Rollback(ctx)
	j, e := t.Collection(ctx, id, false)
	if e != nil {
		t.Tx.Rollback(ctx)
		return nil, e
	}
	if j.Hash != x.Hash {
		t.Tx.Rollback(ctx)
		return nil, store.ErrRevision
	}
	if prior, e := replay(t, ctx, key, meaning); e != nil || prior != nil {
		if prior == nil {
			t.Tx.Rollback(ctx)
		}
		return prior, e
	}
	if j.State == "captured" {
		return collectionResult(ctx, t, key, meaning, j)
	}
	if _, _, e = s.currentCollection(ctx, t, j); e != nil {
		t.Tx.Rollback(ctx)
		return nil, e
	}
	if e = t.Tx.Commit(ctx); e != nil {
		return nil, e
	}
	slotCheck, release, e := s.Custody.DB.CollectionWorkerSlot(ctx)
	if e != nil {
		return nil, e
	}
	defer release()
	owner := secure.NewID()
	j, d, connection, e := s.claimCollection(ctx, scope, id, x.Hash, owner)
	if e != nil {
		return nil, e
	}
	fence := j.Fence
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				if s.checkCollectionLease(ctx, scope, id, owner, fence, true) != nil {
					cancel()
					return
				}
			}
		}
	}()
	defer func() { close(stop); cancel(); <-done }()
	check := func() error {
		if e := slotCheck(); e != nil {
			return e
		}
		return s.checkCollectionLease(ctx, scope, id, owner, fence, false)
	}
	fail := func(reason string, attention bool) (*Result, error) {
		return s.failedCollectionWork(scope, id, owner, fence, key, meaning, reason, attention)
	}
	var peer *delivery.CollectionPeer
	defer func() {
		if peer != nil {
			peer.Close()
		}
	}()
	open := func() error {
		if peer != nil {
			return nil
		}
		var e error
		peer, e = delivery.OpenCollectionPeer(ctx, connection.Destination, connection.Directory, check)
		return e
	}
	if j.Manifest == nil {
		if e = open(); e != nil {
			return fail("source_connection_unavailable", false)
		}
		data, e := peer.ReadManifest(ctx, d.Source.Manifest, check)
		if e != nil {
			return fail("source_manifest_unavailable", false)
		}
		manifest, hash, e := parseCollectionManifest(data, d.Source)
		if e != nil {
			return fail("producer_manifest_invalid", true)
		}
		if e = s.captureCollectionManifest(ctx, scope, id, owner, fence, manifest, hash); e != nil {
			return fail("producer_batch_binding_refused", true)
		}
	}
	read, e := s.collectionRead(ctx, scope)
	if e != nil {
		return fail("collection_metadata_unavailable", false)
	}
	j, e = read.Collection(ctx, id, false)
	if e != nil {
		read.Tx.Rollback(ctx)
		return fail("collection_metadata_unavailable", false)
	}
	inputs, e := read.CollectionInputs(ctx, j)
	if e == nil {
		e = read.Tx.Commit(ctx)
	} else {
		read.Tx.Rollback(ctx)
	}
	if e != nil {
		return fail("collection_metadata_unavailable", false)
	}
	for index := range inputs {
		i := &inputs[index]
		if i.State != "pending" {
			continue
		}
		if i.JobID != id {
			return fail("input_claim_owned_by_prior_job", true)
		}
		if e = check(); e != nil {
			return fail("collection_authority_or_lease_changed", true)
		}
		sealed := false
		existing, verifyErr := s.Custody.Disk.VerifiedContext(ctx, custody.Name(scope.Tenant, scope.Partner, i.ObjectID), i.Size, i.SHA256)
		if verifyErr == nil {
			st, statErr := existing.Stat()
			sealed = statErr == nil && st.Mode().Perm() == 0400
			existing.Close()
		}
		i, e = s.prepareCollectionInput(ctx, scope, id, i.ID, owner, fence, sealed, i.ObjectID)
		if e != nil {
			return fail("input_fence_or_binding_changed", true)
		}
		if !sealed {
			generationCheck, releaseGeneration, e := s.Custody.DB.CustodyGenerationSlot(ctx)
			if e != nil {
				return fail("custody_capacity_unavailable", false)
			}
			e = s.Custody.Disk.Capacity(i.Size, s.Custody.MaxStored)
			if e == nil {
				e = open()
			}
			if e == nil {
				_, _, e = s.Custody.Disk.StageGenerated(ctx, custody.Name(scope.Tenant, scope.Partner, i.ObjectID), max(i.Size, 1), func(output io.Writer) error {
					if e := generationCheck(); e != nil {
						return e
					}
					return peer.CopyVerified(ctx, i.Name, i.Size, i.SHA256, output, func() error {
						if e := generationCheck(); e != nil {
							return e
						}
						return check()
					})
				})
			}
			releaseGeneration()
			if e != nil {
				return fail("source_file_verification_or_capacity_failed", false)
			}
		}
		if e = check(); e != nil {
			return fail("collection_authority_or_lease_changed", true)
		}
		if e = s.acceptCollectionInput(ctx, scope, id, owner, fence, i); e != nil {
			return fail("local_acceptance_not_confirmed", false)
		}
	}
	result, e := s.completeCollectionWork(ctx, scope, id, owner, fence, key, meaning)
	if e != nil {
		return fail("collection_capture_not_confirmed", false)
	}
	return result, nil
}
