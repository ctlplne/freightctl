package main

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/freightctl/internal/calendar"
	"github.com/ctlplne/freightctl/internal/migration"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func TestPrepareSFTPGoCalendarReusesOrdinarySchedule(t *testing.T) {
	plan, err := migration.PlanSFTPGo([]byte(`{
  "version":17,
  "event_actions":[{"name":"source-backup","type":4}],
  "event_rules":[{"status":0,"trigger":3,
    "conditions":{"schedules":[
      {"hour":"07","day_of_month":"*","month":"*","day_of_week":"2"},
      {"hour":"3-6","day_of_month":"*","month":"*","day_of_week":"*"}
    ]},"actions":[{"name":"source-backup","order":1}]
  }]
}`))
	if err != nil {
		t.Fatal(err)
	}
	request := sftpgoCalendarRequest{
		SourceSHA256: plan.SourceSHA256, SourceSchedule: "/event_rules/0/conditions/schedules/0",
		Selection: workflow.ScheduleSelection{
			Name: "Operator-reviewed destination calendar",
			Workflow: workflow.Reference{
				ID: "7ae7d6fc-2944-45de-a40e-4ddd50a0b822", Version: 1, Hash: strings.Repeat("c", 64),
			},
			Source: workflow.ScheduleSourceSelection{Directory: "/inbox", Pattern: "*.csv"},
			Calendar: calendar.Selection{
				Start: time.Date(2027, time.January, 1, 0, 0, 0, 0, time.UTC),
				End:   time.Date(2027, time.February, 1, 0, 0, 0, 0, time.UTC),
				Gap:   "skip", Fold: "first",
			},
			ExpectedAuthority: 1, Missed: "skip", CatchUp: 1, MaxActive: 1, MaxFiles: 8, Deadline: 900, Grace: 60,
		},
	}
	result, err := prepareSFTPGoCalendar(plan, request)
	if err != nil {
		t.Fatal(err)
	}
	if result.SourceSHA256 != plan.SourceSHA256 || result.SourceSchedule != request.SourceSchedule ||
		result.SourceRuleState != "disabled" || result.RuleDisposition != "unsupported" {
		t.Fatalf("lost source binding or unresolved sibling schedule: %#v", result)
	}
	if result.Selection.Name != request.Selection.Name || result.Selection.Workflow != request.Selection.Workflow ||
		result.Selection.Source != request.Selection.Source || result.Selection.ExpectedAuthority != request.Selection.ExpectedAuthority {
		t.Fatalf("operator-selected authority or destination changed: %#v", result.Selection)
	}
	wire, err := json.Marshal(result.Selection)
	if err != nil {
		t.Fatal(err)
	}
	var ordinary workflow.ScheduleSelection
	if err := workflow.Decode(wire, &ordinary); err != nil || !reflect.DeepEqual(ordinary, result.Selection) {
		t.Fatalf("ordinary schedule request could not decode the prepared selection: %v", err)
	}
	definition, err := calendar.Snapshot(ordinary.Calendar)
	if err != nil {
		t.Fatal(err)
	}
	calendarPlan, err := calendar.Compile(definition)
	if err != nil {
		t.Fatal(err)
	}
	got, err := calendarPlan.Preview(definition.Start.Add(-time.Second), 10)
	if err != nil || len(got) != 4 || got[0].At.Format(time.RFC3339) != "2027-01-05T07:00:00Z" ||
		got[3].At.Format(time.RFC3339) != "2027-01-26T07:00:00Z" {
		t.Fatalf("ordinary calendar evaluated the wrong occurrences: %#v, %v", got, err)
	}
	for _, tt := range []struct {
		name   string
		change func(*sftpgoCalendarRequest)
	}{
		{"source-digest", func(r *sftpgoCalendarRequest) { r.SourceSHA256 = strings.Repeat("a", 64) }},
		{"unknown-source-schedule", func(r *sftpgoCalendarRequest) { r.SourceSchedule += "0" }},
		{"unsupported-sibling", func(r *sftpgoCalendarRequest) { r.SourceSchedule = "/event_rules/0/conditions/schedules/1" }},
		{"supplied-zone", func(r *sftpgoCalendarRequest) { r.Selection.Calendar.Zone = "UTC" }},
		{"supplied-holiday", func(r *sftpgoCalendarRequest) { r.Selection.Calendar.Holidays = []string{"2027-01-05"} }},
		{"invalid-authority-revision", func(r *sftpgoCalendarRequest) { r.Selection.ExpectedAuthority = 0 }},
		{"invalid-calendar-bounds", func(r *sftpgoCalendarRequest) { r.Selection.Calendar.End = r.Selection.Calendar.Start }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			modified := request
			tt.change(&modified)
			if result, err := prepareSFTPGoCalendar(plan, modified); err == nil || result.SourceSHA256 != "" {
				t.Fatalf("invalid request acquired a selection: %#v", result)
			}
		})
	}
	invalid := request
	invalid.Selection.Source.Directory = "/one/../another"
	if _, err := prepareSFTPGoCalendar(plan, invalid); !errors.Is(err, workflow.ErrInput) {
		t.Fatalf("ordinary directory validation was bypassed: %v", err)
	}
	plan.Rules[0].Disposition = "blocked"
	if result, err := prepareSFTPGoCalendar(plan, request); err == nil || result.SourceSHA256 != "" {
		t.Fatalf("unresolved rule acquired a selection: %#v", result)
	}
}
