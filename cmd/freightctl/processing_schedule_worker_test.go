package main

import (
	"strings"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func TestProcessingScheduleWorkerKeepsAttemptKeysAndWaitsForSeparateChecksAndRelease(t *testing.T) {
	p := workflow.ProcessingObservation{ID: secure.NewID(), Hash: strings.Repeat("a", 64), State: "approved", Current: true, Revision: 1}
	first, wait, err := processingScheduleWork(&p)
	if err != nil || wait != "" || first == "" {
		t.Fatal("first scheduled processing attempt", err)
	}
	p.State, p.Attempts = "running", 1
	resumed, wait, err := processingScheduleWork(&p)
	if err != nil || wait != "" || resumed != first {
		t.Fatal("running retry changed its original attempt key", err)
	}
	p.State = "failed"
	next, wait, err := processingScheduleWork(&p)
	if err != nil || wait != "" || next == "" || next == first {
		t.Fatal("bounded next attempt reused original work receipt", err)
	}
	p.Attempts = 3
	if key, wait, err := processingScheduleWork(&p); err != nil || key != "" || wait != "processing_attempts_exhausted" {
		t.Fatal("scheduler exceeded processing attempts", err)
	}
	p.State, p.FileID = "completed", secure.NewID()
	if key, wait, err := processingScheduleWork(&p); err != nil || key != "" || wait != "processing_output_awaiting_checks_and_release" {
		t.Fatal("worker treated output as release authority", err)
	}
	p.State, p.Attempts, p.Current = "approved", 0, false
	if key, wait, err := processingScheduleWork(&p); err != nil || key != "" || wait != "processing_policy_or_schedule_changed" {
		t.Fatal("stale task produced a work key", err)
	}
	p.Current, p.State = true, "unqualified"
	if _, _, err := processingScheduleWork(&p); err == nil {
		t.Fatal("unknown processing state")
	}
}
