package workflow

import (
	"context"
	"io"
	"time"

	"github.com/ctlplne/freightctl/internal/portability"
	"github.com/ctlplne/freightctl/internal/store"
)

const PortableRunHistoryProfile = "freightctl-portable-workflow-run-history-v1"

type RunHistorySelection struct {
	RunID           string `json:"run_id"`
	WorkflowHash    string `json:"workflow_hash"`
	ThroughRevision int64  `json:"through_revision"`
	AfterRevision   int64  `json:"after_revision"`
	Limit           int    `json:"limit"`
}

type PortableRunHistory struct {
	SchemaVersion     int                           `json:"schema_version"`
	Profile           string                        `json:"profile"`
	SourceTenant      string                        `json:"source_tenant_id"`
	SourcePartner     string                        `json:"source_partner_id"`
	SourceActor       string                        `json:"source_actor_id"`
	Selection         RunHistorySelection           `json:"source"`
	Workflow          Reference                     `json:"workflow"`
	File              store.File                    `json:"source_file"`
	Transitions       []store.WorkflowRunTransition `json:"transitions"`
	NextAfterRevision *int64                        `json:"next_after_revision,omitempty"`
}

type RunHistoryExportReceipt = portability.JSONExportReceipt[RunHistorySelection]

func (s *Service) PreparePortableRunHistory(ctx context.Context, scope store.Scope, request RunHistorySelection, output io.Writer) (*RunHistoryExportReceipt, error) {
	if !store.ValidID(request.RunID) || !hashPattern.MatchString(request.WorkflowHash) ||
		request.AfterRevision < 0 || request.ThroughRevision <= request.AfterRevision ||
		request.Limit < 1 || request.Limit > store.MaxWorkflowRunHistoryPage {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.beginWorkflow(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer tx.Tx.Rollback(ctx)
	view, err := s.readRunStatus(ctx, tx, request.RunID)
	if err != nil {
		return nil, err
	}
	run := view.Run
	if tx.Root != run.Root || tx.AuthorityRevision != run.Authority {
		return nil, store.ErrUnauthorized
	}
	if request.ThroughRevision > run.Revision || request.WorkflowHash != run.WorkflowHash {
		return nil, store.ErrRevision
	}
	last := request.AfterRevision + min(int64(request.Limit), request.ThroughRevision-request.AfterRevision)
	entries, err := tx.WorkflowRunHistory(ctx, run, request.AfterRevision, last)
	if err != nil {
		return nil, err
	}
	manifest := PortableRunHistory{
		SchemaVersion: 1, Profile: PortableRunHistoryProfile,
		SourceTenant: scope.Tenant, SourcePartner: scope.Partner, SourceActor: tx.Actor, Selection: request,
		Workflow: Reference{ID: run.WorkflowID, Version: run.WorkflowVersion, Hash: run.WorkflowHash},
		File:     run.Source, Transitions: entries,
	}
	if last != request.ThroughRevision {
		manifest.NextAfterRevision = &last
	}
	return portability.WritePreparedJSON(ctx, tx, "PortableWorkflowRunHistoryPrepared", run.ID, request, manifest, output)
}
