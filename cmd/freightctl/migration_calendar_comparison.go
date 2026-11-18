package main

import (
	"errors"
	"time"

	"github.com/ctlplne/freightctl/internal/calendar"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/workflow"
)

const maxMigrationCalendarOccurrences = 512

type migrationCalendarObservations struct {
	Schema         int         `json:"schema_version"`
	SourceSHA256   string      `json:"source_sha256"`
	SourceSchedule string      `json:"source_schedule"`
	Start          time.Time   `json:"starts_at"`
	End            time.Time   `json:"ends_at"`
	Occurrences    []time.Time `json:"occurrences"`
}

type migrationCalendarComparison struct {
	ObservationsSHA256 string      `json:"observations_sha256"`
	StartsAt           time.Time   `json:"starts_at"`
	EndsAt             time.Time   `json:"ends_at"`
	RecordedCount      int         `json:"recorded_count"`
	PreparedCount      int         `json:"prepared_count"`
	Match              bool        `json:"matches_supplied_occurrences"`
	OnlyRecorded       []time.Time `json:"only_recorded"`
	OnlyPrepared       []time.Time `json:"only_prepared"`
}

func compareProtectedCalendarOccurrences(prepared preparedSFTPGoCalendar, path string) (*migrationCalendarComparison, error) {
	input, err := secure.ReadSecret(path, 32<<10)
	if err != nil {
		return nil, err
	}
	defer input.Close()
	var observed migrationCalendarObservations
	if workflow.Decode(input.Bytes, &observed) != nil {
		return nil, errors.New("invalid protected calendar occurrence record")
	}
	comparison, err := compareCalendarOccurrences(prepared, observed)
	if err != nil {
		return nil, err
	}
	comparison.ObservationsSHA256 = secure.Digest(input.Bytes)
	return comparison, nil
}

func compareCalendarOccurrences(prepared preparedSFTPGoCalendar, observed migrationCalendarObservations) (*migrationCalendarComparison, error) {
	chosen := prepared.Selection.Calendar
	if observed.Schema != 1 || observed.SourceSHA256 != prepared.SourceSHA256 || observed.SourceSchedule != prepared.SourceSchedule ||
		!observed.Start.Equal(chosen.Start) || !observed.End.Equal(chosen.End) {
		return nil, errors.New("calendar occurrence record differs from the selected source or window")
	}
	if observed.Occurrences == nil || len(observed.Occurrences) > maxMigrationCalendarOccurrences {
		return nil, errors.New("calendar occurrence record must contain an array of up to 512 occurrences")
	}
	recorded := make(map[time.Time]bool, len(observed.Occurrences))
	var previous time.Time
	for i, occurrence := range observed.Occurrences {
		_, offset := occurrence.Zone()
		if offset != 0 || occurrence.Nanosecond() != 0 || occurrence.Before(chosen.Start) || !occurrence.Before(chosen.End) ||
			(i > 0 && !occurrence.After(previous)) {
			return nil, errors.New("calendar occurrence record must contain unique, ordered UTC seconds inside its window")
		}
		recorded[occurrence.UTC()] = true
		previous = occurrence
	}
	snapshot, err := calendar.Snapshot(chosen)
	if err != nil {
		return nil, err
	}
	plan, err := calendar.Compile(snapshot)
	if err != nil {
		return nil, err
	}
	result := &migrationCalendarComparison{
		StartsAt: chosen.Start, EndsAt: chosen.End, RecordedCount: len(recorded),
		OnlyRecorded: []time.Time{}, OnlyPrepared: []time.Time{},
	}
	for at := plan.Next(chosen.Start.Add(-time.Nanosecond)); at != nil; at = plan.Next(*at) {
		if result.PreparedCount == maxMigrationCalendarOccurrences {
			return nil, errors.New("prepared calendar exceeds 512 occurrences in the comparison window")
		}
		result.PreparedCount++
		instant := at.UTC()
		if recorded[instant] {
			delete(recorded, instant)
		} else {
			result.OnlyPrepared = append(result.OnlyPrepared, instant)
		}
	}
	for _, at := range observed.Occurrences {
		if recorded[at.UTC()] {
			result.OnlyRecorded = append(result.OnlyRecorded, at.UTC())
		}
	}
	result.Match = len(result.OnlyRecorded) == 0 && len(result.OnlyPrepared) == 0
	return result, nil
}
