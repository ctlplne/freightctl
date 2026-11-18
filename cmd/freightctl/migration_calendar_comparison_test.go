package main

import (
	"reflect"
	"testing"
	"time"

	"github.com/ctlplne/freightctl/internal/calendar"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func TestCompareMigrationCalendarOccurrencesReportsExactDifferences(t *testing.T) {
	start := time.Date(2027, 1, 1, 7, 0, 0, 0, time.UTC)
	prepared := preparedSFTPGoCalendar{
		SourceSHA256: "source-digest", SourceSchedule: "/event_rules/0/conditions/schedules/0",
		Selection: workflow.ScheduleSelection{Calendar: calendar.Selection{
			Zone: "UTC", Start: start, End: start.AddDate(0, 0, 3), Times: []string{"07:00:00"},
			Weekdays: []int{0, 1, 2, 3, 4, 5, 6}, Gap: "skip", Fold: "first",
		}},
	}
	observations := migrationCalendarObservations{
		Schema: 1, SourceSHA256: prepared.SourceSHA256, SourceSchedule: prepared.SourceSchedule,
		Start: start, End: prepared.Selection.Calendar.End,
		Occurrences: []time.Time{start, start.AddDate(0, 0, 1), start.AddDate(0, 0, 2)},
	}
	result, err := compareCalendarOccurrences(prepared, observations)
	if err != nil || !result.Match || result.RecordedCount != 3 || result.PreparedCount != 3 ||
		len(result.OnlyRecorded) != 0 || len(result.OnlyPrepared) != 0 {
		t.Fatalf("identical occurrence window disagrees: %#v %v", result, err)
	}
	extra := start.AddDate(0, 0, 1).Add(time.Minute)
	observations.Occurrences[1] = extra
	result, err = compareCalendarOccurrences(prepared, observations)
	if err != nil || result.Match || !reflect.DeepEqual(result.OnlyRecorded, []time.Time{extra}) ||
		!reflect.DeepEqual(result.OnlyPrepared, []time.Time{start.AddDate(0, 0, 1)}) {
		t.Fatalf("equal counts concealed mismatched instants: %#v %v", result, err)
	}
}

func TestCompareMigrationCalendarOccurrencesRefusesUnboundOrIncompleteInputs(t *testing.T) {
	start := time.Date(2027, 1, 1, 7, 0, 0, 0, time.UTC)
	prepared := preparedSFTPGoCalendar{
		SourceSHA256: "source-digest", SourceSchedule: "/event_rules/0/conditions/schedules/0",
		Selection: workflow.ScheduleSelection{Calendar: calendar.Selection{
			Zone: "UTC", Start: start, End: start.AddDate(0, 0, 1), Times: []string{"07:00:00"},
			Weekdays: []int{0, 1, 2, 3, 4, 5, 6}, Gap: "skip", Fold: "first",
		}},
	}
	observations := migrationCalendarObservations{
		Schema: 1, SourceSHA256: prepared.SourceSHA256, SourceSchedule: prepared.SourceSchedule,
		Start: start, End: prepared.Selection.Calendar.End,
		Occurrences: []time.Time{start},
	}
	for _, tt := range []struct {
		name   string
		change func(*migrationCalendarObservations)
	}{
		{"wrong-schema", func(obs *migrationCalendarObservations) { obs.Schema++ }},
		{"wrong-source-digest", func(obs *migrationCalendarObservations) { obs.SourceSHA256 = "different" }},
		{"wrong-schedule-row", func(obs *migrationCalendarObservations) { obs.SourceSchedule += "0" }},
		{"wrong-window", func(obs *migrationCalendarObservations) { obs.End = obs.End.Add(time.Minute) }},
		{"missing-array", func(obs *migrationCalendarObservations) { obs.Occurrences = nil }},
		{"duplicate", func(obs *migrationCalendarObservations) { obs.Occurrences = []time.Time{start, start} }},
		{"unsorted", func(obs *migrationCalendarObservations) { obs.Occurrences = []time.Time{start.Add(time.Minute), start} }},
		{"exclusive-end", func(obs *migrationCalendarObservations) { obs.Occurrences = []time.Time{obs.End} }},
		{"fractional-second", func(obs *migrationCalendarObservations) { obs.Occurrences = []time.Time{start.Add(time.Nanosecond)} }},
		{"timezone-offset", func(obs *migrationCalendarObservations) {
			obs.Occurrences = []time.Time{start.In(time.FixedZone("other", 3600))}
		}},
		{"too-many-source-occurrences", func(obs *migrationCalendarObservations) {
			obs.Occurrences = make([]time.Time, maxMigrationCalendarOccurrences+1)
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			changed := observations
			tt.change(&changed)
			if result, err := compareCalendarOccurrences(prepared, changed); err == nil || result != nil {
				t.Fatalf("invalid occurrence record produced a comparison: %#v", result)
			}
		})
	}
	prepared.Selection.Calendar.End = start.AddDate(0, 0, maxMigrationCalendarOccurrences+1)
	observations.End = prepared.Selection.Calendar.End
	observations.Occurrences = []time.Time{}
	if result, err := compareCalendarOccurrences(prepared, observations); err == nil || result != nil {
		t.Fatalf("truncated prepared occurrences acquired a comparison: %#v", result)
	}
}
