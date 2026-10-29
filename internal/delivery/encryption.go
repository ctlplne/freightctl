package delivery

import (
	"context"
	"errors"
	"io"
	"os"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
)

type encryptionReader struct {
	ctx    context.Context
	source io.Reader
	check  func() error
}

func (r encryptionReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if err := r.check(); err != nil {
		return 0, err
	}
	if len(p) > 32<<10 {
		p = p[:32<<10]
	}
	return r.source.Read(p)
}
func encryptedDefinition(spec *Definition, a *store.DeliveryCiphertext) (*Definition, error) {
	if spec.Encryption == nil || a.Policy != *spec.Encryption || a.SourceID != spec.Source.ID || a.SourceSHA256 != spec.Source.SHA256 || a.StorageID != spec.StorageID || a.Proof.Profile != spec.Encryption.Profile || a.Proof.Cipher != "AES-256" || a.Size <= 0 || a.Size > secure.PGPCiphertextLimit(spec.Source.Size) {
		return nil, store.ErrState
	}
	wire := *spec
	wire.Source = store.File{ID: a.ObjectID, Size: a.Size, SHA256: a.SHA256, Policy: "encrypted-delivery-v1"}
	wire.Transfer = a
	return &wire, nil
}

// prepareCiphertext is local-only. No receiver connection is opened until one
// exact sealed artifact and its event/projection have committed under the live
// delivery fence. Retry reuses that artifact instead of re-encrypting randomly.
func (s *Service) prepareCiphertext(ctx context.Context, scope store.Scope, d *store.Delivery, spec *Definition, check func() error) (*Definition, *os.File, error) {
	t, err := s.Custody.DB.Begin(ctx, scope)
	if err != nil {
		return nil, nil, err
	}
	defer t.Tx.Rollback(context.Background())
	key, err := t.EncryptionKey(ctx, *spec.Encryption)
	if err != nil {
		return nil, nil, err
	}
	now, err := t.DatabaseTime(ctx)
	if err != nil {
		return nil, nil, err
	}
	artifact, err := t.DeliveryCiphertext(ctx, d.ID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, nil, err
	}
	if err = t.Tx.Commit(ctx); err != nil {
		return nil, nil, err
	}
	if artifact == nil {
		_, release, err := s.Custody.DB.CustodyGenerationSlot(ctx)
		if err != nil {
			return nil, nil, err
		}
		defer release()
		maximum := secure.PGPCiphertextLimit(spec.Source.Size)
		if err = s.Custody.Disk.Capacity(maximum, s.Custody.MaxStored); err != nil {
			return nil, nil, err
		}
		_, source, err := s.Custody.Download(ctx, scope, d.FileID)
		if err != nil {
			return nil, nil, err
		}
		defer source.Close()
		artifact = &store.DeliveryCiphertext{DeliveryID: d.ID, ObjectID: secure.NewID(), StorageID: spec.StorageID, SourceID: spec.Source.ID, SourceSHA256: spec.Source.SHA256, DefinitionHash: d.DefinitionHash, Policy: *spec.Encryption, Fence: d.Fence, Owner: d.LeaseOwner}
		processing, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		artifact.Size, artifact.SHA256, err = s.Custody.Disk.StageGenerated(processing, custody.Name(scope.Tenant, scope.Partner, artifact.ObjectID), maximum, func(output io.Writer) error {
			proof, err := secure.EncryptPGP(processing, *key, spec.Encryption.Profile, encryptionReader{ctx: processing, source: source, check: check}, spec.Source.Size, spec.Source.SHA256, output, now)
			if err == nil {
				artifact.Proof = *proof
			}
			return err
		})
		if err != nil {
			return nil, nil, err
		}
		if err = check(); err != nil {
			return nil, nil, err
		}
		record, current, original, err := s.begin(ctx, scope, d.ID, true)
		if err != nil {
			return nil, nil, err
		}
		defer record.Tx.Rollback(context.Background())
		if current.DefinitionHash != d.DefinitionHash || current.State != "staging" || current.LeaseOwner != d.LeaseOwner || current.Fence != d.Fence {
			return nil, nil, store.ErrRevision
		}
		if _, err = record.EncryptionKey(ctx, *original.Encryption); err != nil {
			return nil, nil, err
		}
		if err = record.CheckExecutionBinding(ctx, original.Binding); err != nil {
			return nil, nil, err
		}
		if err = record.SaveDeliveryCiphertext(ctx, artifact); err != nil {
			return nil, nil, err
		}
		if err = record.Reauthorize(ctx); err != nil {
			return nil, nil, err
		}
		if err = record.Tx.Commit(ctx); err != nil {
			return nil, nil, err
		}
	}
	if artifact.DefinitionHash != d.DefinitionHash || artifact.DeliveryID != d.ID || artifact.Proof.PrimaryFingerprint != key.Fingerprint || artifact.Proof.EncryptionFingerprint != key.Recipient.Fingerprint {
		return nil, nil, store.ErrState
	}
	wire, err := encryptedDefinition(spec, artifact)
	if err != nil {
		return nil, nil, err
	}
	content, err := s.Custody.Disk.VerifiedContext(ctx, custody.Name(scope.Tenant, scope.Partner, artifact.ObjectID), artifact.Size, artifact.SHA256)
	return wire, content, err
}
