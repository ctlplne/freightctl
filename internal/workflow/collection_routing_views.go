package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

// Historical metadata is distinct from permission to execute. Exact target and
// recipient references remain inspectable after revocation without opening a
// payload, reading a private key or contacting a peer.
type CollectionRoutingView struct {
	Authorization *store.CollectionRouting `json:"authorization"`
	Workflow      *store.Configuration     `json:"workflow,omitempty"`
	Effects       []Effect                 `json:"effects"`
	Current       bool                     `json:"current_authority"`
	Proposal      *store.CollectionRouting `json:"proposal,omitempty"`
}

func historicalWorkflowEffects(ctx context.Context, t *store.Transaction, d *Definition) ([]Effect, error) {
	effects := []Effect{}
	for _, step := range d.Steps {
		c, err := t.Configuration(ctx, true, step.Connection.ID, step.Connection.Version, false)
		if err != nil {
			return nil, err
		}
		var definition ConnectionDefinition
		// Stored schema-1 SSH host records retain their original Wire and
		// Fingerprint field names. The request/workflow decoder intentionally
		// accepts only lowercase keys, so use the existing connection contract
		// here and still verify its exact canonical fingerprint.
		if json.Unmarshal(c.Definition, &definition) != nil || definition.Schema != 1 {
			return nil, store.ErrState
		}
		_, hash, err := digest(definition)
		if err != nil || hash != c.Hash || c.Hash != step.Connection.Hash {
			return nil, store.ErrState
		}
		view, err := viewConnection(c)
		if err != nil {
			return nil, err
		}
		effect := Effect{StepID: step.ID, Connection: step.Connection, Address: view.Address, Directory: view.Directory, FinalNamePattern: "<delivery UUID>-" + step.Filename, HostFingerprint: view.HostFingerprint, Encryption: step.Encryption}
		if policy := step.Encryption; policy != nil {
			row, err := t.PGPKeySnapshot(ctx, policy.Key.ID, policy.Key.Version)
			if err != nil {
				return nil, err
			}
			var key secure.PGPPublicKey
			if json.Unmarshal(row.Definition, &key) != nil {
				return nil, store.ErrState
			}
			_, hash, err := digest(key)
			if err != nil || row.Hash != policy.Key.Hash || hash != row.Hash || key.Schema != 1 || key.Purpose != "encrypt" || key.Recipient == nil || !slices.Contains(key.Recipient.Profiles, policy.Profile) {
				return nil, store.ErrState
			}
			effect.RecipientFingerprint, effect.EncryptionFingerprint = key.Fingerprint, key.Recipient.Fingerprint
		}
		effects = append(effects, effect)
	}
	return effects, nil
}

func (s *Service) collectionRoutingView(ctx context.Context, t *store.Transaction, job *store.CollectionJob, r, effective *store.CollectionRouting) (*CollectionRoutingView, error) {
	v := &CollectionRoutingView{Authorization: r, Effects: []Effect{}}
	if r == nil {
		return v, nil
	}
	original, err := collectionDefinition(job)
	if err != nil {
		return nil, err
	}
	binding, err := collectionRoutingDefinition(r)
	if err != nil {
		return nil, err
	}
	if binding.Collection.ID != job.ID || binding.Collection.Hash != job.Hash || binding.Collection.Revision > job.Revision || binding.OriginalWorkflow != original.Workflow || job.ManifestHash == nil || binding.ManifestHash != *job.ManifestHash || binding.Authority != original.Authority || binding.StorageID != original.StorageID || binding.Root != original.Root {
		return nil, store.ErrState
	}
	w, err := t.Configuration(ctx, false, binding.Workflow.ID, binding.Workflow.Version, false)
	if err != nil {
		return nil, err
	}
	var d Definition
	if Decode(w.Definition, &d) != nil {
		return nil, store.ErrState
	}
	d, err = Normalize(d)
	if err != nil {
		return nil, err
	}
	_, hash, err := digest(d)
	if err != nil || hash != w.Hash || w.Hash != binding.Workflow.Hash || d.Schema != 2 || d.Source == nil || !reflect.DeepEqual(*d.Source, original.Source) {
		return nil, store.ErrState
	}
	v.Workflow = w
	v.Effects, err = historicalWorkflowEffects(ctx, t, &d)
	if err != nil {
		return nil, err
	}
	now, err := t.DatabaseTime(ctx)
	if err != nil {
		return nil, err
	}
	if effective == nil || effective.ID != r.ID || effective.Revision != r.Revision || r.State != "approved" || job.State != "captured" || !job.Deadline.After(now) || (len(d.Steps) > 0 && !t.Has("deliver")) {
		return v, nil
	}
	if err = t.CollectionDefinitionCurrent(ctx, job.Definition); errors.Is(err, store.ErrCollection) {
		return v, nil
	} else if err != nil {
		return nil, err
	}
	if _, err = s.effectiveCollectionRouting(ctx, t, job, original); err != nil {
		if errors.Is(err, store.ErrState) || errors.Is(err, store.ErrRevision) || errors.Is(err, store.ErrCollection) || errors.Is(err, store.ErrForbidden) {
			return v, nil
		}
		return nil, err
	}
	v.Current = true
	return v, nil
}

func (s *Service) routingMetadata(ctx context.Context, scope store.Scope, jobID, id string) (*CollectionRoutingView, error) {
	if !store.ValidID(jobID) || (id != "" && !store.ValidID(id)) {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.collectionRead(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	for attempt := 0; attempt < 3; attempt++ {
		job, err := t.Collection(ctx, jobID, false)
		if err != nil {
			return nil, err
		}
		current, err := t.CurrentCollectionRouting(ctx, jobID)
		if err != nil {
			return nil, err
		}
		var pending *store.CollectionRouting
		if id == "" {
			pending, err = t.PendingCollectionRouting(ctx, jobID)
			if err != nil {
				return nil, err
			}
		}
		r := current
		if id != "" {
			r, err = t.CollectionRouting(ctx, jobID, id, false)
			if err != nil {
				return nil, err
			}
		}
		v, err := s.collectionRoutingView(ctx, t, job, r, current)
		if err != nil {
			return nil, err
		}
		v.Proposal = pending
		after, err := t.CurrentCollectionRouting(ctx, jobID)
		if err != nil {
			return nil, err
		}
		lastJob, err := t.Collection(ctx, jobID, false)
		if err != nil {
			return nil, err
		}
		if !reflect.DeepEqual(routingReference(current), routingReference(after)) || lastJob.Revision != job.Revision {
			continue
		}
		if id == "" {
			lastPending, err := t.PendingCollectionRouting(ctx, jobID)
			if err != nil {
				return nil, err
			}
			if !reflect.DeepEqual(routingReference(pending), routingReference(lastPending)) {
				continue
			}
		}
		if id != "" {
			last, err := t.CollectionRouting(ctx, jobID, id, false)
			if err != nil {
				return nil, err
			}
			if last.Revision != r.Revision {
				continue
			}
		}
		if err = t.Reauthorize(ctx); err != nil {
			return nil, err
		}
		return v, t.Tx.Commit(ctx)
	}
	return nil, store.ErrRevision
}

func (s *Service) CurrentCollectionRouting(ctx context.Context, scope store.Scope, job string) (*CollectionRoutingView, error) {
	return s.routingMetadata(ctx, scope, job, "")
}

func (s *Service) CollectionRoutingDetails(ctx context.Context, scope store.Scope, job, id string) (*CollectionRoutingView, error) {
	if id == "" {
		return nil, ErrInput
	}
	return s.routingMetadata(ctx, scope, job, id)
}

// Receipt recovery is read-only, even when a saved browser key is missing or
// untrusted. An unknown key cannot accidentally create a new proposal/approval.
func (s *Service) CollectionRoutingReceipt(ctx context.Context, scope store.Scope, job, key string) (*Result, error) {
	if !store.ValidID(job) || !keyPattern.MatchString(key) {
		return nil, ErrInput
	}
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
	id, raw, err := t.CollectionRoutingReceipt(ctx, key)
	if err != nil {
		return nil, err
	}
	var a CollectionRoutingAction
	if Decode(raw, &a) != nil || a.Kind != "workflow_collection_routing" || a.JobID != job || a.ID != id {
		return nil, store.ErrNotFound
	}
	r, err := t.CollectionRouting(ctx, job, id, false)
	if err != nil {
		return nil, err
	}
	valid := a.Hash == r.Hash && a.Version == r.Version && ((a.State == "proposed" && a.Revision == 1) || (a.State == "approved" && a.Revision == 2 && (r.State == "approved" || r.State == "revoked")) || (a.State == "revoked" && a.Revision == 3 && r.State == "revoked") || (a.State == "withdrawn" && a.Revision == 2 && r.State == "withdrawn"))
	if !valid || a.Revision > r.Revision {
		return nil, store.ErrState
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return &Result{Resource: raw, Replayed: true}, t.Tx.Commit(ctx)
}
