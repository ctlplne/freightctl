package workflow

import (
	"context"
	"encoding/json"
	"io"
	"time"

	"github.com/ctlplne/freightctl/internal/calendar"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

const PortableWorkflowProfile = "freightctl-portable-workflow-v1"
const PortableScheduleProfile = "freightctl-portable-schedule-v1"

type PortableWorkflowDependency struct {
	Kind    string `json:"kind"`
	ID      string `json:"id,omitempty"`
	Version int    `json:"version,omitempty"`
	Hash    string `json:"hash"`
}

type PortableWorkflow struct {
	SchemaVersion int                          `json:"schema_version"`
	Profile       string                       `json:"profile"`
	SourceTenant  string                       `json:"source_tenant_id"`
	SourcePartner string                       `json:"source_partner_id"`
	Source        Reference                    `json:"source"`
	ObservedState string                       `json:"observed_state"`
	Draft         DraftRequest                 `json:"draft"`
	Dependencies  []PortableWorkflowDependency `json:"dependencies"`
}

type PortableSchedule struct {
	SchemaVersion  int                 `json:"schema_version"`
	Profile        string              `json:"profile"`
	SourceTenant   string              `json:"source_tenant_id"`
	SourcePartner  string              `json:"source_partner_id"`
	Source         Reference           `json:"source"`
	ObservedState  string              `json:"observed_state"`
	FrozenCalendar calendar.Definition `json:"source_frozen_calendar"`
	Selection      ScheduleSelection   `json:"destination_preview_selection"`
}

type PortableExportReceipt struct {
	Source Reference `json:"source"`
	SHA256 string    `json:"sha256"`
	Size   int       `json:"size_bytes"`
}

func portableDependencies(d Definition) []PortableWorkflowDependency {
	dependencies := make([]PortableWorkflowDependency, 0)
	seen := map[PortableWorkflowDependency]bool{}
	add := func(kind string, ref Reference) {
		item := PortableWorkflowDependency{Kind: kind, ID: ref.ID, Version: ref.Version, Hash: ref.Hash}
		if !seen[item] {
			seen[item] = true
			dependencies = append(dependencies, item)
		}
	}
	if d.Source != nil {
		add("connection", d.Source.Connection)
	}
	for _, step := range d.Steps {
		add("connection", step.Connection)
		if step.Encryption != nil {
			add("public_encryption_key", Reference(step.Encryption.Key))
		}
	}
	if d.Processing != nil {
		add("source_intake_policy", Reference{Hash: d.Processing.Definition.SourcePolicyHash})
		add("processing_output_policy", d.Processing.OutputPolicy)
	}
	return dependencies
}

// PreparePortableWorkflow writes an inert draft and exact dependency references
// to private staging. Source approval and execution authority stay in the
// original workspace.
func (s *Service) PreparePortableWorkflow(ctx context.Context, scope store.Scope, ref Reference, output io.Writer) (*PortableExportReceipt, error) {
	if !store.ValidID(ref.ID) || ref.Version < 1 || !hashPattern.MatchString(ref.Hash) {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.beginWorkflow(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer tx.Tx.Rollback(ctx)
	if !tx.Has("workflow_manage") && !tx.Has("workflow_approve") && !tx.Has("workflow_execute") {
		return nil, store.ErrForbidden
	}
	stored, err := tx.Configuration(ctx, false, ref.ID, ref.Version, false)
	if err != nil {
		return nil, err
	}
	if stored.Hash != ref.Hash {
		return nil, store.ErrRevision
	}
	var definition Definition
	if Decode(stored.Definition, &definition) != nil {
		return nil, store.ErrState
	}
	if err = workflowDefinitionScope(tx, definition); err != nil {
		return nil, err
	}
	normalized, err := Normalize(definition)
	if err != nil {
		return nil, store.ErrState
	}
	if _, hash, err := digest(normalized); err != nil || hash != stored.Hash {
		return nil, store.ErrIsolation
	}
	manifest := PortableWorkflow{
		SchemaVersion: 1, Profile: PortableWorkflowProfile,
		SourceTenant: scope.Tenant, SourcePartner: scope.Partner,
		Source: ref, ObservedState: stored.State, Draft: DraftRequest{Definition: normalized},
		Dependencies: portableDependencies(normalized),
	}
	return writePortableExport(ctx, tx, "PortableWorkflowExportPrepared", ref, manifest, output)
}

func (s *Service) PreparePortableSchedule(ctx context.Context, scope store.Scope, ref Reference, output io.Writer) (*PortableExportReceipt, error) {
	if !store.ValidID(ref.ID) || ref.Version < 1 || !hashPattern.MatchString(ref.Hash) {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.scheduleRead(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer tx.Tx.Rollback(ctx)
	if err = tx.ScheduleLock(ctx, false); err != nil {
		return nil, err
	}
	stored, err := tx.Schedule(ctx, ref.ID, ref.Version, false)
	if err != nil {
		return nil, err
	}
	if stored.Hash != ref.Hash {
		return nil, store.ErrRevision
	}
	definition, _, err := scheduleDefinition(stored)
	if err != nil {
		return nil, err
	}
	selection := definition.selection()
	selection.ExpectedAuthority = 0
	manifest := PortableSchedule{
		SchemaVersion: 1, Profile: PortableScheduleProfile,
		SourceTenant: scope.Tenant, SourcePartner: scope.Partner,
		Source: ref, ObservedState: stored.State, FrozenCalendar: definition.Calendar, Selection: selection,
	}
	return writePortableExport(ctx, tx, "PortableScheduleExportPrepared", ref, manifest, output)
}

func writePortableExport(ctx context.Context, tx *store.Transaction, event string, ref Reference, manifest any, output io.Writer) (*PortableExportReceipt, error) {
	payload, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	payload = append(payload, '\n')
	if len(payload) > 48<<10 {
		return nil, store.ErrLimit
	}
	written, err := output.Write(payload)
	if err != nil {
		return nil, err
	}
	if written != len(payload) {
		return nil, io.ErrShortWrite
	}
	if err = tx.Reauthorize(ctx); err != nil {
		return nil, err
	}
	receipt := &PortableExportReceipt{Source: ref, SHA256: secure.Digest(payload), Size: written}
	if _, err = tx.Append(ctx, event, ref.ID, receipt); err != nil {
		return nil, err
	}
	if err = tx.Tx.Commit(ctx); err != nil {
		return nil, err
	}
	return receipt, nil
}
