package checks

import (
	"context"
	"errors"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

type OutputPolicyRequest struct {
	ID              string `json:"policy_id,omitempty"`
	ExpectedVersion int    `json:"expected_version"`
	Producer        string `json:"producer_id"`
	Definition      Policy `json:"definition"`
}

type OutputPolicyRecord struct {
	Profile        string                         `json:"profile"`
	Policy         *store.Configuration           `json:"policy"`
	Binding        *store.ProcessingOutputBinding `json:"binding"`
	Observation    string                         `json:"observation"`
	IngressChanged bool                           `json:"ingress_changed"`
	Usage          string                         `json:"usage"`
}
type OutputPolicyView struct {
	OutputPolicyRecord
	ProducerCurrent bool `json:"producer_binding_current_at_observation"`
}
type OutputPolicySummary struct {
	ID              string `json:"id"`
	Version         int    `json:"version"`
	Hash            string `json:"definition_hash"`
	State           string `json:"state"`
	Revision        int64  `json:"revision"`
	Producer        string `json:"producer_id"`
	ProducerCurrent bool   `json:"producer_binding_current_at_observation"`
	Kind            string `json:"kind"`
	Columns         int    `json:"column_count"`
}
type OutputPolicyPage struct {
	Profile  string                `json:"profile"`
	Policies []OutputPolicySummary `json:"policies"`
	Next     string                `json:"next,omitempty"`
}

func (s *Service) outputAdministration(ctx context.Context, scope store.Scope) (*store.Transaction, error) {
	t, err := s.Custody.DB.BeginApproval(ctx, scope)
	if err != nil {
		return nil, err
	}
	if t.Root != "/" || !t.Has("admin") || !t.Has("intake_manage") {
		t.Tx.Rollback(ctx)
		return nil, store.ErrForbidden
	}
	return t, nil
}
func outputProducerCurrent(ctx context.Context, t *store.Transaction, b *store.ProcessingOutputBinding) (bool, error) {
	actual, err := t.ProcessingOutputProducer(ctx, b.Producer.Actor)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return actual == b.Producer, nil
}
func outputRecord(ctx context.Context, t *store.Transaction, c *store.Configuration) (*OutputPolicyRecord, error) {
	b, err := t.ProcessingOutputBinding(ctx, c.ID, c.Version)
	if err != nil {
		return nil, err
	}
	expected, err := outputPolicyBinding(t.Scope, b.Publisher, c, b.Producer)
	if err != nil || *expected != *b {
		return nil, store.ErrIsolation
	}
	return &OutputPolicyRecord{Profile: "producer-processing-output-policy-v1", Policy: c, Binding: b, Observation: "current-contract-metadata-only", IngressChanged: false, Usage: "producer-workflow-output-contract"}, nil
}
func (s *Service) RegisterOutputPolicy(ctx context.Context, scope store.Scope, key string, r OutputPolicyRequest) (*Result, error) {
	if !keyPattern.MatchString(key) || !store.ValidID(r.Producer) || r.ExpectedVersion < 0 || (r.ID == "" && r.ExpectedVersion != 0) || (r.ID != "" && (!store.ValidID(r.ID) || r.ExpectedVersion < 1)) {
		return nil, ErrInput
	}
	d, err := Normalize(r.Definition)
	if err != nil {
		return nil, err
	}
	r.Definition = d
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.outputAdministration(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	_, meaning, _ := canonical(struct {
		Kind    string
		Request OutputPolicyRequest
	}{"register_processing_output_policy", r})
	prior, err := t.CheckReplay(ctx, key, meaning)
	if err != nil {
		return nil, err
	}
	if prior != nil {
		if err = t.Reauthorize(ctx); err != nil {
			return nil, err
		}
		return &Result{Resource: prior, Replayed: true}, t.Tx.Commit(ctx)
	}
	id := r.ID
	if id == "" {
		id = secure.NewID()
	}
	head, err := t.ProcessingOutputHead(ctx, id, true)
	if err != nil {
		return nil, err
	}
	version := 0
	if head != nil {
		version = head.Version
	}
	if version != r.ExpectedVersion {
		return nil, store.ErrRevision
	}
	producer, err := t.ProcessingOutputProducer(ctx, r.Producer)
	if err != nil {
		return nil, err
	}
	if d.Signature != nil {
		if _, _, err = keyCurrent(ctx, t, d.Signature); err != nil {
			return nil, err
		}
	}
	if d.Scanner != nil {
		if _, _, err = t.CurrentScanner(ctx, *d.Scanner); err != nil {
			return nil, err
		}
	}
	if head != nil && head.State == "output_active" {
		previous := head.Revision
		head.Revision++
		head.State = "output_retired"
		if err = t.SaveIntakePolicy(ctx, head, previous); err != nil {
			return nil, err
		}
	}
	raw, hash, err := canonical(d)
	if err != nil {
		return nil, err
	}
	c := &store.Configuration{ID: id, Version: version + 1, Definition: raw, Hash: hash, State: "output_active", Revision: 1}
	b, err := outputPolicyBinding(scope, t.Actor, c, producer)
	if err != nil {
		return nil, err
	}
	if err = t.SaveIntakePolicy(ctx, c, 0); err != nil {
		return nil, err
	}
	if err = t.SaveProcessingOutputBinding(ctx, b); err != nil {
		return nil, err
	}
	return finish(ctx, t, key, meaning, id, &OutputPolicyRecord{Profile: b.Profile, Policy: c, Binding: b, Observation: "original-command-receipt;current-state-not-checked", IngressChanged: false, Usage: "producer-workflow-output-contract"})
}
func (s *Service) OutputPolicy(ctx context.Context, scope store.Scope, id string, version int) (*OutputPolicyView, error) {
	if !store.ValidID(id) || version < 1 {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	c, err := t.ProcessingOutputPolicy(ctx, id, version, false)
	if err != nil {
		return nil, err
	}
	r, err := outputRecord(ctx, t, c)
	if err != nil {
		return nil, err
	}
	current, err := outputProducerCurrent(ctx, t, r.Binding)
	if err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return &OutputPolicyView{OutputPolicyRecord: *r, ProducerCurrent: current}, t.Tx.Commit(ctx)
}
func (s *Service) OutputPolicies(ctx context.Context, scope store.Scope, after string, limit int) (*OutputPolicyPage, error) {
	if (after != "" && !store.ValidID(after)) || limit < 1 || limit > 100 {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	rows, err := t.ProcessingOutputPolicies(ctx, after, limit)
	if err != nil {
		return nil, err
	}
	page := &OutputPolicyPage{Profile: "producer-processing-output-policy-v1", Policies: []OutputPolicySummary{}}
	if len(rows) > limit {
		page.Next = rows[limit-1].ID
		rows = rows[:limit]
	}
	for _, c := range rows {
		r, err := outputRecord(ctx, t, c)
		if err != nil {
			return nil, err
		}
		current, err := outputProducerCurrent(ctx, t, r.Binding)
		if err != nil {
			return nil, err
		}
		d, err := decodePolicy(c)
		if err != nil {
			return nil, err
		}
		page.Policies = append(page.Policies, OutputPolicySummary{ID: c.ID, Version: c.Version, Hash: c.Hash, State: c.State, Revision: c.Revision, Producer: r.Binding.Producer.Actor, ProducerCurrent: current, Kind: d.Kind, Columns: len(d.Columns)})
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return page, t.Tx.Commit(ctx)
}
func (s *Service) RevokeOutputPolicy(ctx context.Context, scope store.Scope, id string, version int, key string, decision PolicyDecision) (*Result, error) {
	if !store.ValidID(id) || version < 1 || decision.Version != version || !keyPattern.MatchString(key) || !hashPattern.MatchString(decision.Hash) || decision.Revision < 1 {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.outputAdministration(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	_, meaning, _ := canonical(struct {
		Kind, ID string
		Version  int
		Decision PolicyDecision
	}{"revoke_processing_output_policy", id, version, decision})
	prior, err := t.CheckReplay(ctx, key, meaning)
	if err != nil {
		return nil, err
	}
	if prior != nil {
		if err = t.Reauthorize(ctx); err != nil {
			return nil, err
		}
		return &Result{Resource: prior, Replayed: true}, t.Tx.Commit(ctx)
	}
	if _, err = t.ProcessingOutputHead(ctx, id, true); err != nil {
		return nil, err
	}
	c, err := t.ProcessingOutputPolicy(ctx, id, version, true)
	if err != nil {
		return nil, err
	}
	if c.Hash != decision.Hash || c.Revision != decision.Revision {
		return nil, store.ErrRevision
	}
	if c.State != "output_active" {
		return nil, store.ErrState
	}
	r, err := outputRecord(ctx, t, c)
	if err != nil {
		return nil, err
	}
	previous := c.Revision
	c.State = "output_revoked"
	c.Revision++
	if err = t.SaveIntakePolicy(ctx, c, previous); err != nil {
		return nil, err
	}
	r.Observation = "original-command-receipt;current-state-not-checked"
	return finish(ctx, t, key, meaning, id, r)
}

// outputPolicyBinding validates immutable metadata only. Administration and
// producer authority must also be checked in the owning database transaction.
func outputPolicyBinding(scope store.Scope, publisher string, policy *store.Configuration, producer store.ExchangeParticipant) (*store.ProcessingOutputBinding, error) {
	if policy == nil || !store.ValidID(scope.Tenant) || !store.ValidID(scope.Partner) || !store.ValidID(publisher) || !store.ValidID(policy.ID) || policy.Version < 1 || policy.Revision < 1 || !hashPattern.MatchString(policy.Hash) || !store.ValidID(producer.Actor) || producer.Tenant != scope.Tenant || producer.Partner != scope.Partner || producer.AuthorityRevision < 1 || !hashPattern.MatchString(producer.RootPolicyDigest) {
		return nil, ErrInput
	}
	if policy.State != "output_active" && policy.State != "output_retired" && policy.State != "output_revoked" {
		return nil, ErrInput
	}
	var definition Policy
	if workflow.Decode(policy.Definition, &definition) != nil {
		return nil, ErrInput
	}
	normalized, err := Normalize(definition)
	if err != nil {
		return nil, err
	}
	_, hash, err := canonical(normalized)
	if err != nil || hash != policy.Hash {
		return nil, store.ErrRevision
	}
	return &store.ProcessingOutputBinding{Profile: "producer-processing-output-policy-v1", PolicyID: policy.ID, Version: policy.Version, Hash: hash, Publisher: publisher, Producer: producer}, nil
}
