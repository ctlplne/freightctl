package delivery

import (
	"context"
	"encoding/json"

	"github.com/ctlplne/freightctl/internal/store"
)

// VerifyWorkflowReadback checks a historical receipt inside the caller's
// already authorized workflow transaction. It reads records and makes no
// connection to the receiver or to the encryption key service.
func VerifyWorkflowReadback(ctx context.Context, t *store.Transaction, d *store.Delivery, run *store.WorkflowRun, step store.WorkflowStep) error {
	spec, err := storedDefinition(d)
	if err != nil {
		return err
	}
	binding := store.ExecutionBinding{
		WorkflowID: run.WorkflowID, WorkflowVersion: run.WorkflowVersion, WorkflowHash: run.WorkflowHash,
		RunID: run.ID, StepID: step.ID, ConnectionID: step.ConnectionID,
		ConnectionVersion: step.ConnectionVersion, ConnectionHash: step.ConnectionHash,
	}
	if step.RunID != run.ID || step.DeliveryID != d.ID || spec.Binding == nil || *spec.Binding != binding || spec.Source != run.Source || spec.StorageID != run.StorageID {
		return store.ErrState
	}
	var artifact *store.DeliveryCiphertext
	if spec.Encryption != nil {
		artifact, err = t.DeliveryCiphertext(ctx, d.ID)
		if err != nil {
			return err
		}
	}
	return verifyCompletedReadback(d, spec, artifact)
}

func verifyCompletedReadback(d *store.Delivery, spec *Definition, artifact *store.DeliveryCiphertext) error {
	var observation struct {
		Code       string `json:"code"`
		SHA256     string `json:"sha256"`
		Size       *int64 `json:"size_bytes"`
		Encryption *struct {
			ObjectID     string             `json:"ciphertext_object_id"`
			SourceID     string             `json:"source_file_id"`
			SourceSHA256 string             `json:"source_sha256"`
			Key          store.PGPReference `json:"key"`
			Profile      string             `json:"profile"`
			Primary      string             `json:"primary_fingerprint"`
			Recipient    string             `json:"encryption_fingerprint"`
			Cipher       string             `json:"cipher"`
			Compression  string             `json:"compression"`
		} `json:"encryption"`
	}
	if d.State != "succeeded" || json.Unmarshal(d.Observation, &observation) != nil || observation.Code != "remote_file_integrity_observed" || observation.Size == nil {
		return store.ErrState
	}
	expected := spec.Source
	proof := observation.Encryption
	if spec.Encryption != nil {
		if artifact == nil || proof == nil || artifact.DeliveryID != d.ID || artifact.DefinitionHash != d.DefinitionHash ||
			proof.ObjectID != artifact.ObjectID || proof.SourceID != artifact.SourceID || proof.SourceSHA256 != artifact.SourceSHA256 ||
			proof.Key != artifact.Policy.Key || proof.Profile != artifact.Policy.Profile || proof.Primary != artifact.Proof.PrimaryFingerprint ||
			proof.Recipient != artifact.Proof.EncryptionFingerprint || proof.Cipher != artifact.Proof.Cipher || proof.Compression != artifact.Proof.Compression {
			return store.ErrState
		}
		wire, err := encryptedDefinition(spec, artifact)
		if err != nil {
			return err
		}
		expected = wire.Source
	} else if proof != nil {
		return store.ErrState
	}
	if observation.SHA256 != expected.SHA256 || *observation.Size != expected.Size {
		return store.ErrState
	}
	return nil
}
