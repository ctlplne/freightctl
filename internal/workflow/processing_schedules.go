package workflow

import (
	"context"
	"reflect"

	"github.com/ctlplne/freightctl/internal/store"
)

// A calendar may select already released,owned record inputs. It never turns
// an arrival,a release or the clock into approval for a different task.
const ProcessingScheduleSource = "owned_released_records"

type ScheduledProcessing struct {
	Profile string         `json:"profile"`
	Task    ProcessingTask `json:"task"`
}

func processingScheduleResource(record *store.Schedule, binding *ScheduledProcessing) ScheduleResource {
	r := ScheduleResource{Kind: "workflow_schedule", Schedule: record.ScheduleSummary}
	if binding != nil {
		r.Profile = "owned-record-processing-schedule-v1"
	}
	return r
}

func processingScheduleBinding(w *Definition, source ScheduleSourceSelection) (*ScheduledProcessing, error) {
	if w == nil {
		return nil, ErrInput
	}
	normalized, err := Normalize(*w)
	if err != nil {
		return nil, err
	}
	if normalized.Schema != 3 {
		if source.Kind == ProcessingScheduleSource {
			return nil, ErrInput
		}
		return nil, nil
	}
	if normalized.Processing == nil || len(normalized.Steps) != 0 || normalized.Source != nil || source.Kind != ProcessingScheduleSource || !schedulePattern.MatchString(source.Pattern) {
		return nil, ErrInput
	}
	return &ScheduledProcessing{Profile: "owned-record-processing-schedule-v1", Task: *normalized.Processing}, nil
}

func checkProcessingSchedule(d *ScheduleDefinition, w *Definition) error {
	bound, err := processingScheduleBinding(w, d.Source.ScheduleSourceSelection)
	if err != nil || d.Schema != 2 || d.Processing == nil || bound == nil || d.Collection != nil || len(d.Effects) != 0 || !reflect.DeepEqual(*bound, *d.Processing) {
		return store.ErrSchedule
	}
	return nil
}

func processingScheduleGrants(t *store.Transaction) error {
	for _, grant := range []string{"read", "write", "check_run", "workflow_execute", "list"} {
		if err := t.Require(grant); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) stageScheduledProcessing(ctx context.Context, t *store.Transaction, request RunRequest, w *Definition, source *store.File, storage string) (*store.WorkflowRun, error) {
	if s.Processor == nil || w.Schema != 3 || w.Processing == nil || source == nil || source.ID != request.FileID || source.Size > s.Custody.MaxFile {
		return nil, store.ErrState
	}
	if err := processingScheduleGrants(t); err != nil {
		return nil, err
	}
	if err := s.checkStorage(storage); err != nil {
		return nil, err
	}
	return s.stageProcessingRun(ctx, t, request, w, source, storage)
}
