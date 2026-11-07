package checks

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"

	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
)

type projectionReader struct {
	*os.File
	check func() error
}

func (r projectionReader) Read(p []byte) (int, error) {
	if err := r.check(); err != nil {
		return 0, err
	}
	return r.File.Read(p[:min(len(p), 32<<10)])
}

// Preserve ReaderAt/Seek for ZIP/XLSX while checking every bounded random read.
func (r projectionReader) ReadAt(p []byte, offset int64) (int, error) {
	n := 0
	for n < len(p) {
		if err := r.check(); err != nil {
			return n, err
		}
		k, err := r.File.ReadAt(p[n:min(len(p), n+(32<<10))], offset+int64(n))
		n += k
		if err != nil {
			return n, err
		}
		if k == 0 {
			return n, io.ErrNoProgress
		}
	}
	return n, nil
}

type projectionSink struct {
	writer io.Writer
	check  func() error
}

func (w projectionSink) Write(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if err := w.check(); err != nil {
			return n, err
		}
		chunk := p[n:min(len(p), n+(32<<10))]
		k, err := w.writer.Write(chunk)
		n += k
		if err != nil {
			return n, err
		}
		if k != len(chunk) {
			return n, io.ErrShortWrite
		}
	}
	return n, nil
}

// stageProjection has no SQL acceptance/publication capability. The caller must
// hold the ordinary custody capacity reservation and the exact current intent.
func stageProjection(ctx context.Context, disk *custody.Disk, scope store.Scope, source Policy, d ProjectionDefinition, maxFile, maxStored int64, guard func() error) (file *store.File, report ProjectionReport, err error) {
	defer func() {
		if err != nil {
			file = nil
			report.OutputSHA256 = ""
			report.Code = "staging_unavailable"
		}
	}()
	if disk == nil || guard == nil || maxFile < 1 || maxStored < 1 || d.Plan.Projection.MaxBytes > maxFile || len(d.Slots) != 3 {
		return nil, report, custody.ErrCapacity
	}
	if err := guard(); err != nil {
		return nil, report, err
	}
	f := d.Plan.Context.Source.File
	input, err := disk.VerifiedContext(ctx, custody.Name(scope.Tenant, scope.Partner, f.ID), f.Size, f.SHA256)
	if err != nil {
		return nil, report, err
	}
	defer input.Close()
	generate := func(output io.Writer) error {
		if _, err := input.Seek(0, io.SeekStart); err != nil {
			return err
		}
		var err error
		report, err = ProjectRecords(ctx, source, d.Plan.Projection, f, projectionReader{input, guard}, projectionSink{output, guard})
		if err != nil {
			if denied := guard(); denied != nil {
				return denied
			}
			return err
		}
		if report.Code != "transformed" || report.OutputContractHash != d.Plan.OutputContractHash || report.OutputBytes > maxFile {
			return store.ErrState
		}
		return guard()
	}
	computed := false
	for _, id := range d.Slots {
		if !store.ValidID(id) || id == f.ID {
			return nil, report, store.ErrState
		}
		name := custody.Name(scope.Tenant, scope.Partner, id)
		state, err := disk.GeneratedSlotState(ctx, name)
		if err != nil {
			return nil, report, err
		}
		if state == "partial" {
			continue
		}
		if state == "sealed" {
			if err = disk.Capacity(0, maxStored); err != nil {
				return nil, report, err
			}
			if !computed {
				if err = generate(io.Discard); err != nil {
					return nil, report, err
				}
				computed = true
			}
			if err = disk.VerifyGenerated(ctx, name, report.OutputBytes, report.OutputSHA256); err != nil {
				return nil, report, err
			}
		} else {
			if err = disk.Capacity(d.Plan.Projection.MaxBytes, maxStored); err != nil {
				return nil, report, err
			}
			size, hash, err := disk.StageGenerated(ctx, name, d.Plan.Projection.MaxBytes, generate)
			if err != nil {
				return nil, report, err
			}
			if size != report.OutputBytes || hash != report.OutputSHA256 {
				return nil, report, custody.ErrIntegrity
			}
		}
		if err = guard(); err != nil {
			return nil, report, err
		}
		return &store.File{ID: id, Size: report.OutputBytes, SHA256: report.OutputSHA256}, report, nil
	}
	return nil, report, store.ErrLimit
}

func projectionWorkMeaning(a ProjectionAttempt) string {
	_, hash, _ := canonical(struct {
		Kind    string
		Attempt ProjectionAttempt
	}{"work_record_projection", a})
	return hash
}
func (s *Service) WorkProjection(ctx context.Context, scope store.Scope, key string, a ProjectionAttempt) (*Result, error) {
	if !keyPattern.MatchString(key) || !store.ValidID(a.ID) || !store.ValidID(a.WorkerID) || a.Number < 1 || a.Number > 3 {
		return nil, ErrInput
	}
	result, err := s.workProjection(ctx, scope, key, a)
	if err == nil {
		return result, nil
	}
	// A committed failure is itself an idempotent result,not a clean output.
	// If completion committed but its response was lost,this finds its receipt.
	code := "processing_unavailable"
	switch {
	case errors.Is(err, context.Canceled):
		code = "processing_cancelled"
	case errors.Is(err, context.DeadlineExceeded):
		code = "processing_deadline"
	case errors.Is(err, store.ErrRevision):
		code = "review_stale"
	case errors.Is(err, custody.ErrIntegrity):
		code = "integrity_mismatch"
	case errors.Is(err, custody.ErrCapacity), errors.Is(err, store.ErrLimit):
		code = "capacity_unavailable"
	}
	record, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	t, e := s.projectionExistingBegin(record, scope, a.ID, "workflow_execute")
	if e != nil {
		return nil, err
	}
	defer t.Tx.Rollback(record)
	meaning := projectionWorkMeaning(a)
	if prior, e := t.CheckReplay(record, key, meaning); e != nil {
		return nil, e
	} else if prior != nil {
		return projectionReplayed(record, t, prior)
	}
	r, e := t.RecordProjection(record, a.ID, true)
	if e != nil {
		return nil, err
	}
	now, e := t.DatabaseTime(record)
	if e != nil || projectionLeaseCurrent(r, a, now) != nil {
		return nil, err
	}
	previous := r.Revision
	r.Revision++
	r.State = "failed"
	r.WorkerID = ""
	r.LeaseUntil = nil
	r.Result, _, e = canonical(struct {
		Kind    string            `json:"kind"`
		Attempt ProjectionAttempt `json:"attempt"`
		Code    string            `json:"code"`
	}{"record_projection_failure", a, code})
	if e != nil {
		return nil, e
	}
	if e = t.SaveRecordProjection(record, r, previous); e != nil {
		return nil, e
	}
	return finishProjection(record, t, key, meaning, r)
}

func (s *Service) workProjection(ctx context.Context, scope store.Scope, key string, a ProjectionAttempt) (*Result, error) {
	ctx, cancel := context.WithTimeout(ctx, 65*time.Second)
	defer cancel()
	meaning := projectionWorkMeaning(a)
	pre, err := s.projectionExistingBegin(ctx, scope, a.ID, "workflow_execute")
	if err != nil {
		return nil, err
	}
	if prior, e := pre.CheckReplay(ctx, key, meaning); e != nil {
		pre.Tx.Rollback(ctx)
		return nil, e
	} else if prior != nil {
		return projectionReplayed(ctx, pre, prior)
	}
	if err = pre.Tx.Rollback(ctx); err != nil {
		return nil, err
	}
	admission, release, err := s.Custody.DB.ProjectionSlot(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	capacity, releaseCapacity, err := s.Custody.DB.CustodyGenerationSlot(ctx)
	if err != nil {
		return nil, err
	}
	defer releaseCapacity()
	t, err := s.projectionExistingBegin(ctx, scope, a.ID, "workflow_execute")
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if prior, e := t.CheckReplay(ctx, key, meaning); e != nil {
		return nil, e
	} else if prior != nil {
		return projectionReplayed(ctx, t, prior)
	}
	r, err := t.RecordProjection(ctx, a.ID, true)
	if err != nil {
		return nil, err
	}
	now, err := t.DatabaseTime(ctx)
	if err != nil {
		return nil, err
	}
	if err = projectionLeaseCurrent(r, a, now); err != nil {
		return nil, err
	}
	d, err := decodeProjection(r)
	if err != nil {
		return nil, err
	}
	if err = t.NamespaceLock(ctx); err != nil {
		return nil, err
	}
	fresh, err := s.projectionCurrent(ctx, t, d, true)
	if err != nil {
		return nil, err
	}
	guard := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := admission(); err != nil {
			return err
		}
		if err := capacity(); err != nil {
			return err
		}
		now, err := t.DatabaseTime(ctx)
		if err != nil {
			return err
		}
		if err = projectionLeaseCurrent(r, a, now); err != nil {
			return err
		}
		if err = s.Custody.Disk.CheckIdentity(); err != nil {
			return err
		}
		return t.Reauthorize(ctx)
	}
	file, report, err := stageProjection(ctx, s.Custody.Disk, scope, fresh.SourcePolicy.Definition, d, s.Custody.MaxFile, s.Custody.MaxStored, guard)
	if err != nil {
		return nil, err
	}
	if _, err = s.projectionCurrent(ctx, t, d, true); err != nil {
		return nil, err
	}
	check, err := t.FileCheck(ctx, r.SourceID, false)
	if err != nil {
		return nil, err
	}
	var approved Report
	if json.Unmarshal(check.Report, &approved) != nil || approved.Rows != report.Source.Rows {
		return nil, store.ErrState
	}
	// Re-establish source immutability after all sequential/random parser reads.
	verified, err := s.Custody.Disk.VerifiedContext(ctx, custody.Name(scope.Tenant, scope.Partner, r.SourceID), d.Plan.Context.Source.File.Size, d.Plan.Context.Source.File.SHA256)
	if err != nil {
		return nil, err
	}
	if err = verified.Close(); err != nil {
		return nil, err
	}
	if err = guard(); err != nil {
		return nil, err
	}
	if err = t.ConfigureIntakeFile(ctx, file); err != nil {
		return nil, err
	}
	if err = t.AcceptProjectedFile(ctx, r, file, s.Custody.Disk.Identity(), report, a); err != nil {
		return nil, err
	}
	var target *store.PathCommand
	if d.Plan.Context.Target != nil {
		copy := d.Plan.Context.Target.Command
		copy.FileID = file.ID
		target = &copy
	}
	held, err := t.BindIntake(ctx, file, s.Custody.Disk.Identity(), target)
	if err != nil {
		return nil, err
	}
	if !held {
		return nil, store.ErrState
	}
	previous := r.Revision
	r.Revision++
	r.State = "completed"
	r.WorkerID = ""
	r.LeaseUntil = nil
	r.FileID = file.ID
	r.Result, _, err = canonical(ProjectionOutput{Kind: "record_projection_output", Attempt: a, File: *file, Acceptance: "durable-held-pending-checks-and-release", Report: report})
	if err != nil {
		return nil, err
	}
	if err = t.SaveRecordProjection(ctx, r, previous); err != nil {
		return nil, err
	}
	return finishProjection(ctx, t, key, meaning, r)
}
