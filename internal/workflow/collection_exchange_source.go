package workflow

import (
	"context"
	"strconv"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

const CollectedExchangeSourceProfile = "governed-collection-exchange-source-v1"

type CollectedExchangeOrigin struct {
	CollectionID      string    `json:"collection_id"`
	DefinitionHash    string    `json:"definition_hash"`
	Workflow          Reference `json:"workflow"`
	ManifestHash      string    `json:"manifest_sha256"`
	ProducerBatch     string    `json:"producer_batch_id"`
	InputID           string    `json:"input_id"`
	InputIdentity     string    `json:"input_identity"`
	FirstCollectionID string    `json:"first_collection_id"`
}
type CollectedExchangeSource struct {
	Profile             string                  `json:"profile"`
	Artifact            store.ExchangeArtifact  `json:"artifact"`
	Origin              CollectedExchangeOrigin `json:"origin"`
	State               string                  `json:"state"`
	StorageVerification string                  `json:"storage_verification"`
}

// Derive only an exact immutable collection/input correlation. This helper
// supplies no live permission: the caller must separately authorize the source.
func collectedExchangeInput(j *store.CollectionJob, inputs []store.CollectionInput, inputID string) (*CollectedExchangeOrigin, *store.CollectionInput, error) {
	if j == nil || !store.ValidID(j.ID) || !store.ValidID(inputID) || !j.Captured || j.ManifestHash == nil {
		return nil, nil, store.ErrState
	}
	d, err := collectionDefinition(j)
	if err != nil {
		return nil, nil, err
	}
	m, hash, err := parseCollectionManifest(j.Manifest, d.Source)
	if err != nil || hash != *j.ManifestHash || len(inputs) != len(m.Files) {
		return nil, nil, store.ErrState
	}
	seen := map[string]bool{}
	var found *store.CollectionInput
	for index := range inputs {
		i := &inputs[index]
		f := m.Files[index]
		identity := secure.Digest([]byte(i.SourceIdentity + ":" + i.Name + ":" + strconv.FormatInt(i.Size, 10) + ":" + i.SHA256))
		if !store.ValidID(i.ID) || seen[i.ID] || i.WorkflowID != j.WorkflowID || i.SourceIdentity != d.SourceIdentity || i.Name != f.Name || i.Size != f.Size || i.SHA256 != f.SHA256 || !store.ValidID(i.JobID) || i.Identity != identity || !store.ValidID(i.ObjectID) || i.FileID == nil || *i.FileID != i.ObjectID || i.State != "accepted" && i.State != "queued" {
			return nil, nil, store.ErrState
		}
		seen[i.ID] = true
		if i.ID == inputID {
			found = i
		}
	}
	if found == nil {
		return nil, nil, store.ErrNotFound
	}
	if found.FileID == nil || !store.ValidID(*found.FileID) || found.State != "accepted" && found.State != "queued" {
		return nil, nil, store.ErrState
	}
	origin := &CollectedExchangeOrigin{CollectionID: j.ID, DefinitionHash: j.Hash, Workflow: d.Workflow, ManifestHash: hash, ProducerBatch: m.Batch, InputID: found.ID, InputIdentity: found.Identity, FirstCollectionID: found.JobID}
	return origin, found, nil
}

// Read one actor-private collected input and its current ordinary source grant
// in the same transaction. Old collection revocation/deadline facts do not recall
// captured source bytes; new source/path/intake permissions still apply. No
// offer,run,intent,receipt,event,reservation,physical-byte claim or peer contact.
func (s *Service) InspectCollectedExchangeSource(ctx context.Context, scope store.Scope, collectionID, inputID string) (*CollectedExchangeSource, error) {
	if !store.ValidID(collectionID) || !store.ValidID(inputID) {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.collectionRead(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	for _, grant := range []string{"read", "deliver"} {
		if err = t.Require(grant); err != nil {
			return nil, err
		}
	}
	j, err := t.Collection(ctx, collectionID, false)
	if err != nil {
		return nil, err
	}
	inputs, err := t.CollectionInputs(ctx, j)
	if err != nil {
		return nil, err
	}
	origin, input, err := collectedExchangeInput(j, inputs, inputID)
	if err != nil {
		return nil, err
	}
	f, err := t.AuthorizeExchangeSource(ctx, *input.FileID)
	if err != nil {
		return nil, err
	}
	if f.ID != *input.FileID || f.Size != input.Size || f.SHA256 != input.SHA256 {
		return nil, store.ErrRevision
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	result := &CollectedExchangeSource{Profile: CollectedExchangeSourceProfile, Artifact: store.ExchangeArtifact{ID: f.ID, Size: f.Size, SHA256: f.SHA256, Policy: f.Policy}, Origin: *origin, State: "source-review-only", StorageVerification: "not-checked"}
	return result, t.Tx.Rollback(ctx)
}
