package main

import (
	"encoding/hex"
	"strconv"

	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

// Restarting a running attempt uses its original receipt key. Only a recorded
// failed attempt can advance to the next of the engine's three attempts.
func processingScheduleWork(p *workflow.ProcessingObservation) (string, string, error) {
	if p == nil || !store.ValidID(p.ID) || len(p.Hash) != 64 || p.Revision < 1 || p.Attempts < 0 || p.Attempts > 3 {
		return "", "", store.ErrState
	}
	if _, err := hex.DecodeString(p.Hash); err != nil {
		return "", "", store.ErrState
	}
	switch p.State {
	case "completed":
		if !store.ValidID(p.FileID) || p.Attempts < 1 {
			return "", "", store.ErrState
		}
		return "", "processing_output_awaiting_checks_and_release", nil
	case "cancelled":
		return "", "processing_cancelled", nil
	case "approved":
		if p.Attempts != 0 {
			return "", "", store.ErrState
		}
	case "running", "failed":
		if p.Attempts < 1 {
			return "", "", store.ErrState
		}
	default:
		return "", "", store.ErrState
	}
	if !p.Current {
		return "", "processing_policy_or_schedule_changed", nil
	}
	if p.State == "failed" && p.Attempts == 3 {
		return "", "processing_attempts_exhausted", nil
	}
	attempt := p.Attempts
	if p.State != "running" {
		attempt++
	}
	return "processing:" + p.ID + ":attempt:" + strconv.Itoa(attempt), "", nil
}
