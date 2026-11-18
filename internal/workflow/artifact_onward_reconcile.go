package workflow

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"time"

	"github.com/ctlplne/freightctl/internal/delivery"
	"github.com/ctlplne/freightctl/internal/store"
)

type OnwardReconcileRequest struct {
	OnwardLookup
	RunID      string `json:"run_id"`
	DeliveryID string `json:"delivery_id"`
}

type OnwardReconciliation struct {
	RunID               string `json:"run_id"`
	DeliveryID          string `json:"delivery_id"`
	Observation         string `json:"observation"`
	ObservationSHA256   string `json:"observation_sha256"`
	DeliveryState       string `json:"delivery_state"`
	Replayed            bool   `json:"replayed"`
	ReceiverPersistence string `json:"receiver_persistence"`
	BusinessProcessing  string `json:"business_processing"`
}

// ReconcileOnward authorizes one immutable intent from a previously reviewed
// run. Its exact readback result, delivery transition and run projection commit
// together. Replaying the request returns the recorded result without a read.
func (s *Service) ReconcileOnward(ctx context.Context, scope store.Scope, key string, request OnwardReconcileRequest) (*OnwardReconciliation, error) {
	if !s.validOnwardLookup(request.OnwardLookup) || !store.ValidID(request.RunID) || !store.ValidID(request.DeliveryID) || !keyPattern.MatchString(key) {
		return nil, ErrInput
	}
	_, meaning, err := digest(struct {
		Kind    string                 `json:"kind"`
		Request OnwardReconcileRequest `json:"request"`
	}{"reviewed-onward-reconcile-v1", request})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	t, err := s.begin(ctx, scope, "workflow_execute", "read", "deliver")
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	_, accepted, err := readOnwardReceipt(ctx, t, request.OnwardLookup)
	if err != nil {
		return nil, err
	}
	if accepted.ID != request.RunID {
		return nil, store.ErrRevision
	}
	run, err := t.WorkflowRun(ctx, accepted.ID, true)
	if err != nil {
		return nil, err
	}
	steps, err := t.WorkflowSteps(ctx, run.ID)
	if err != nil {
		return nil, err
	}
	index := slices.IndexFunc(steps, func(step store.WorkflowStep) bool { return step.DeliveryID == request.DeliveryID })
	if index < 0 {
		return nil, store.ErrNotFound
	}
	step := steps[index]
	target := delivery.ReviewedObservationTarget{DeliveryID: step.DeliveryID, FileID: run.FileID, Binding: store.ExecutionBinding{
		WorkflowID: run.WorkflowID, WorkflowVersion: run.WorkflowVersion, WorkflowHash: run.WorkflowHash,
		RunID: run.ID, StepID: step.ID, ConnectionID: step.ConnectionID, ConnectionVersion: step.ConnectionVersion, ConnectionHash: step.ConnectionHash,
	}}
	observed, err := (&delivery.Service{Custody: s.Custody}).ObserveReviewedDelivery(ctx, t, target, key, meaning)
	if err != nil {
		return nil, err
	}
	if !observed.Replayed {
		_, state, reason, err := s.runSnapshot(ctx, t, run)
		if err != nil {
			return nil, err
		}
		if err = setProjection(ctx, t, run, state, reason); err != nil {
			return nil, err
		}
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	outcome := "unconfirmed"
	if observed.Delivery.State == "succeeded" {
		outcome = "integrity-observed"
	}
	hash, err := onwardObservationHash(observed.Delivery.Observation)
	if err != nil {
		return nil, err
	}
	result := &OnwardReconciliation{RunID: run.ID, DeliveryID: step.DeliveryID, Observation: outcome,
		ObservationSHA256: hash, DeliveryState: observed.Delivery.State, Replayed: observed.Replayed,
		ReceiverPersistence: "unknown", BusinessProcessing: "unknown"}
	return result, t.Tx.Commit(ctx)
}

// JSONB may reorder the fields or format them differently after persistence.
// Hash the ordered JSON encoding of the observation values for both replies.
func onwardObservationHash(raw json.RawMessage) (string, error) {
	var fields map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&fields); err != nil || fields == nil {
		return "", store.ErrIsolation
	}
	_, hash, err := digest(fields)
	return hash, err
}
