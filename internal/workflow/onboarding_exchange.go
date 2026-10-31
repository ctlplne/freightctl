package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/ctlplne/freightctl/internal/delivery"
	"github.com/ctlplne/freightctl/internal/store"
)

// Review selects existing evidence only. No client-supplied observation,
// endpoint, credential, approval or activation belongs in this request.
type OnboardingExchangeRequest struct {
	Plan              store.OnboardingReference `json:"plan"`
	RequirementID     string                    `json:"requirement_id"`
	ProbeID           string                    `json:"probe_id"`
	RunID             string                    `json:"run_id"`
	StepID            string                    `json:"step_id"`
	ExpectedAuthority int64                     `json:"expected_authority_revision"`
}
type ExchangeResource struct {
	ID       string `json:"id"`
	Revision int64  `json:"revision"`
	Hash     string `json:"hash"`
}
type OnboardingExchangeSnapshot struct {
	Schema           int                       `json:"schema_version"`
	Selection        OnboardingExchangeRequest `json:"selection"`
	Probe            ExchangeResource          `json:"probe"`
	ProbeCompletedAt *time.Time                `json:"probe_completed_at"`
	Connection       store.OnboardingReference `json:"connection"`
	Workflow         Reference                 `json:"workflow"`
	WorkflowRevision int64                     `json:"workflow_revision"`
	RunRevision      int64                     `json:"run_revision"`
	Delivery         ExchangeResource          `json:"delivery"`
	File             store.File                `json:"file"`
	ReceiptHash      string                    `json:"receipt_hash"`
	TransferSHA256   string                    `json:"transfer_sha256"`
	TransferBytes    int64                     `json:"transfer_bytes"`
	RequiredReceipt  string                    `json:"required_receipt"`
	ObservedReceipt  string                    `json:"observed_receipt"`
	FileFsync        bool                      `json:"file_fsync_acknowledged"`
	Reconciled       bool                      `json:"reconciled"`
}
type OnboardingExchangeReview struct {
	Snapshot           OnboardingExchangeSnapshot `json:"snapshot"`
	Hash               string                     `json:"snapshot_hash"`
	ObservedAt         time.Time                  `json:"observed_at"`
	Ready              bool                       `json:"ready_for_approval_review"`
	Reason             string                     `json:"reason"`
	BusinessAcceptance string                     `json:"business_acceptance"`
	ProductionActive   bool                       `json:"production_active"`
	ExternalContact    bool                       `json:"external_contact"`
}

type exchangeReceipt struct {
	Code                string `json:"code"`
	SHA256              string `json:"sha256"`
	Size                int64  `json:"size_bytes"`
	Host                string `json:"host_fingerprint"`
	FileFsync           bool   `json:"file_fsync_acknowledged"`
	Reconciled          bool   `json:"reconciled"`
	Business            string `json:"business_acceptance"`
	DirectoryDurability string `json:"directory_power_loss_durability"`
}

func validExchangeRequest(r OnboardingExchangeRequest) bool {
	return validProbeReference(r.Plan) && store.ValidID(r.RequirementID) && store.ValidID(r.ProbeID) && store.ValidID(r.RunID) && stepPattern.MatchString(r.StepID) && r.ExpectedAuthority > 0
}

// assessExchange binds a receipt to its exact workflow/delivery/source. It is
// deterministic and never treats a transport receipt as business acceptance.
func assessExchange(required string, p *store.OnboardingProbe, run *RunView, step Step, conn *ConnectionDefinition, intent *store.Delivery, cipher *store.DeliveryCiphertext, out *OnboardingExchangeSnapshot) (string, error) {
	if required != "transport" && required != "integrity" && required != "business" {
		return "", store.ErrIsolation
	}
	out.RequiredReceipt = required
	out.ObservedReceipt = "none"
	if p.State != "succeeded" || p.CompletedAt == nil || p.Observation.Code != "connectivity_verified" || !p.Observation.SSH || !p.Observation.SFTP || !p.Observation.Extensions || !p.Observation.Directory {
		return "probe_not_succeeded", nil
	}
	if run.ObservedState != "succeeded" || intent.State != "succeeded" {
		return "exchange_not_succeeded", nil
	}
	var spec delivery.Definition
	if json.Unmarshal(intent.Definition, &spec) != nil {
		return "", store.ErrIsolation
	}
	_, hash, err := digest(spec)
	expected := store.ExecutionBinding{WorkflowID: run.Run.WorkflowID, WorkflowVersion: run.Run.WorkflowVersion, WorkflowHash: run.Run.WorkflowHash, RunID: run.Run.ID, StepID: step.ID, ConnectionID: step.Connection.ID, ConnectionVersion: step.Connection.Version, ConnectionHash: step.Connection.Hash}
	if err != nil || hash != intent.DefinitionHash || spec.Schema != 1 || spec.Binding == nil || *spec.Binding != expected || spec.Source != run.Run.Source || intent.FileID != run.Run.FileID || spec.Source.ID != run.Run.FileID || spec.StorageID != run.Run.StorageID || spec.Root != run.Run.Root || spec.Authority != run.Run.Authority || spec.Directory != conn.Directory || spec.Filename != step.Filename || !reflect.DeepEqual(spec.Destination, conn.Destination) || !reflect.DeepEqual(spec.Encryption, step.Encryption) {
		return "", store.ErrIsolation
	}
	transferHash, transferSize := spec.Source.SHA256, spec.Source.Size
	if step.Encryption != nil {
		if cipher == nil || cipher.DeliveryID != intent.ID || cipher.SourceID != spec.Source.ID || cipher.SourceSHA256 != spec.Source.SHA256 || cipher.DefinitionHash != intent.DefinitionHash || cipher.StorageID != spec.StorageID || cipher.Policy != *step.Encryption || !hashPattern.MatchString(cipher.SHA256) || cipher.Size <= 0 {
			return "", store.ErrIsolation
		}
		transferHash, transferSize = cipher.SHA256, cipher.Size
	} else if cipher != nil {
		return "", store.ErrIsolation
	}
	var observed exchangeReceipt
	if json.Unmarshal(intent.Observation, &observed) != nil || observed.Code != "remote_file_integrity_observed" || observed.SHA256 != transferHash || observed.Size != transferSize || observed.Host != conn.Destination.Host.Fingerprint || observed.Business != "unknown" || observed.DirectoryDurability != "not established" || observed.FileFsync == observed.Reconciled {
		return "", store.ErrIsolation
	}
	out.ObservedReceipt = "integrity"
	out.TransferSHA256 = transferHash
	out.TransferBytes = transferSize
	out.FileFsync = observed.FileFsync
	out.Reconciled = observed.Reconciled
	if required == "business" {
		return "business_receipt_missing", nil
	}
	return "recorded_evidence_matches", nil
}

// ReviewOnboardingExchange makes no external contact and changes no domain
// state. All selected objects are read through one scoped transaction. This
// snapshot is evidence for a later approval, never permission to execute.
func (s *Service) ReviewOnboardingExchange(ctx context.Context, scope store.Scope, request OnboardingExchangeRequest) (*OnboardingExchangeReview, error) {
	if !validExchangeRequest(request) {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.probeBegin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	result, err := s.reviewExchange(ctx, t, request)
	if err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return result, t.Tx.Commit(ctx)
}

// reviewExchange composes evidence with a caller-owned scoped transaction.
// It neither commits nor makes external contact.
func (s *Service) reviewExchange(ctx context.Context, t *store.Transaction, request OnboardingExchangeRequest) (*OnboardingExchangeReview, error) {
	var err error
	if err = t.Require("read"); err != nil {
		return nil, err
	}
	if !t.Has("workflow_manage") && !t.Has("workflow_approve") && !t.Has("workflow_execute") {
		return nil, store.ErrForbidden
	}
	if t.Root != "/" || t.AuthorityRevision != request.ExpectedAuthority {
		return nil, store.ErrRevision
	}
	p, err := t.OnboardingProbe(ctx, request.ProbeID, true)
	if err != nil {
		return nil, err
	}
	if p.Definition.Plan != request.Plan || p.Definition.RequirementID != request.RequirementID {
		return nil, store.ErrRevision
	}
	conn, _, err := probeBindings(ctx, t, p.Definition)
	if err != nil {
		return nil, err
	}
	plan, err := t.OnboardingPlan(ctx, request.Plan.ID, 0)
	if err != nil {
		return nil, err
	}
	var required string
	for _, r := range plan.Definition.Requirements {
		if r.ID == request.RequirementID {
			required = r.Receipt
			break
		}
	}
	run, err := t.WorkflowRun(ctx, request.RunID, true)
	if err != nil {
		return nil, err
	}
	if run.Authority != t.AuthorityRevision || run.Root != t.Root {
		return nil, store.ErrRevision
	}
	if err = t.FileAccessible(ctx, run.FileID); err != nil {
		return nil, err
	}
	currentFile, err := t.File(ctx, run.FileID)
	if err != nil {
		return nil, err
	}
	if *currentFile != run.Source {
		return nil, store.ErrIsolation
	}
	wf, definition, err := approved(ctx, t, Reference{ID: run.WorkflowID, Version: run.WorkflowVersion, Hash: run.WorkflowHash})
	if err != nil {
		return nil, err
	}
	var selected *Step
	for i := range definition.Steps {
		if definition.Steps[i].ID == request.StepID {
			selected = &definition.Steps[i]
			break
		}
	}
	if selected == nil || selected.Connection != (Reference{ID: p.Definition.Connection.ID, Version: p.Definition.Connection.Version, Hash: p.Definition.Connection.Hash}) {
		return nil, store.ErrRevision
	}
	steps, err := t.WorkflowSteps(ctx, run.ID)
	if err != nil {
		return nil, err
	}
	var intent *store.Delivery
	for _, step := range steps {
		if step.ID != request.StepID {
			continue
		}
		if step.ConnectionID != selected.Connection.ID || step.ConnectionVersion != selected.Connection.Version || step.ConnectionHash != selected.Connection.Hash {
			return nil, store.ErrIsolation
		}
		intent, err = t.Delivery(ctx, step.DeliveryID, true)
		if err != nil {
			return nil, err
		}
		break
	}
	if intent == nil {
		return nil, store.ErrIsolation
	}
	view, _, _, err := snapshot(ctx, t, run)
	if err != nil {
		return nil, err
	}
	cipher, err := t.DeliveryCiphertext(ctx, intent.ID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	now, err := t.DatabaseTime(ctx)
	if err != nil {
		return nil, err
	}
	result := &OnboardingExchangeReview{ObservedAt: now, BusinessAcceptance: "unknown"}
	result.Snapshot = OnboardingExchangeSnapshot{Schema: 1, Selection: request, Probe: ExchangeResource{ID: p.ID, Revision: p.Revision, Hash: p.Hash}, ProbeCompletedAt: p.CompletedAt, Connection: p.Definition.Connection, Workflow: Reference{ID: wf.ID, Version: wf.Version, Hash: wf.Hash}, WorkflowRevision: wf.Revision, RunRevision: run.Revision, Delivery: ExchangeResource{ID: intent.ID, Revision: intent.Revision, Hash: intent.DefinitionHash}, File: run.Source}
	// Hash the complete stored receipt, while exposing only its bounded safe
	// interpretation. Raw peer/path text and private connection fields stay private.
	_, result.Snapshot.ReceiptHash, err = digest(json.RawMessage(intent.Observation))
	if err != nil {
		return nil, store.ErrIsolation
	}
	result.Reason, err = assessExchange(required, p, view, *selected, conn, intent, cipher, &result.Snapshot)
	if err != nil {
		return nil, err
	}
	result.Ready = result.Reason == "recorded_evidence_matches"
	_, result.Hash, err = digest(result.Snapshot)
	if err != nil {
		return nil, err
	}
	return result, nil
}
