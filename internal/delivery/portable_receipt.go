package delivery

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"reflect"
	"time"

	"github.com/ctlplne/freightctl/internal/portability"
	"github.com/ctlplne/freightctl/internal/store"
)

const PortableReceiptProfile = "freightctl-portable-delivery-receipt-v1"

type ReceiptReference struct {
	ID       string `json:"id"`
	Revision int64  `json:"revision"`
	Hash     string `json:"definition_hash"`
}

type PortableExportReceipt = portability.JSONExportReceipt[ReceiptReference]

type PortableReceipt struct {
	SchemaVersion int              `json:"schema_version"`
	Profile       string           `json:"profile"`
	SourceTenant  string           `json:"source_tenant_id"`
	SourcePartner string           `json:"source_partner_id"`
	SourceActor   string           `json:"source_actor_id"`
	Source        ReceiptReference `json:"source"`
	Event         string           `json:"completed_event_id"`
	File          store.File       `json:"source_file"`
	Protocol      string           `json:"protocol"`
	Observation   json.RawMessage  `json:"observation"`
}

func canonicalPortableObservation(d *store.Delivery, spec *Definition) (string, json.RawMessage, error) {
	protocol := "sftp"
	var historical struct {
		Reconciled *bool `json:"reconciled"`
	}
	if json.Unmarshal(d.Observation, &historical) != nil || historical.Reconciled == nil {
		return "", nil, store.ErrState
	}
	observation := receipt(d, spec, *historical.Reconciled)
	if spec.FTPS != nil {
		protocol, observation = "ftps", ftpsReceipt(d, spec, *historical.Reconciled)
	}
	if spec.DAV != nil {
		protocol, observation = "webdav", davReceipt(d, spec, *historical.Reconciled)
	}
	decode := func(raw []byte) (any, error) {
		var value any
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		err := decoder.Decode(&value)
		return value, err
	}
	actual, err := decode(d.Observation)
	expected, expectedErr := decode(observation)
	if err != nil || expectedErr != nil || !reflect.DeepEqual(actual, expected) {
		return "", nil, store.ErrState
	}
	return protocol, observation, nil
}

func (s *Service) PreparePortableReceipt(ctx context.Context, scope store.Scope, ref ReceiptReference, output io.Writer) (*PortableExportReceipt, error) {
	if !store.ValidID(ref.ID) || !dispatchHashPattern.MatchString(ref.Hash) || ref.Revision < 1 {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, d, spec, err := s.begin(ctx, scope, ref.ID, false)
	if err != nil {
		return nil, err
	}
	defer tx.Tx.Rollback(ctx)
	if d.Revision != ref.Revision || d.DefinitionHash != ref.Hash {
		return nil, store.ErrRevision
	}
	var artifact *store.DeliveryCiphertext
	if spec.Encryption != nil {
		artifact, err = tx.DeliveryCiphertext(ctx, d.ID)
		if err != nil {
			return nil, err
		}
	}
	if err = verifyCompletedReadback(d, spec, artifact); err != nil {
		return nil, err
	}
	wire := spec
	if artifact != nil {
		wire, err = encryptedDefinition(spec, artifact)
		if err != nil {
			return nil, err
		}
	}
	protocol, observation, err := canonicalPortableObservation(d, wire)
	if err != nil {
		return nil, err
	}
	event, err := tx.CompletedDeliveryEvent(ctx, d)
	if err != nil {
		return nil, err
	}
	manifest := PortableReceipt{
		SchemaVersion: 1, Profile: PortableReceiptProfile,
		SourceTenant: scope.Tenant, SourcePartner: scope.Partner, SourceActor: tx.Actor,
		Source: ref, Event: event, File: spec.Source, Protocol: protocol, Observation: observation,
	}
	return portability.WritePreparedJSON(ctx, tx, "PortableDeliveryReceiptExportPrepared", d.ID, ref, manifest, output)
}
