package workflow

import (
	"encoding/json"
	"github.com/ctlplne/freightctl/internal/calendar"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestScheduleGoBrowserCanonicalCalendarAndDestinationSnapshot(t *testing.T) {
	data, e := os.ReadFile("../../web/tests/fixtures/schedules.json")
	if e != nil {
		t.Fatal(e)
	}
	var f map[string]struct {
		Selection ScheduleSelection `json:"selection"`
		Preview   SchedulePreview   `json:"preview"`
	}
	if json.Unmarshal(data, &f) != nil || len(f) != 2 {
		t.Fatal("fixture")
	}
	for name, v := range f {
		t.Run(name, func(t *testing.T) {
			_, hash, e := digest(v.Preview.Definition)
			if e != nil || hash != v.Preview.Hash || v.Preview.ExternalContact || !v.Preview.ApprovalRequired || !reflect.DeepEqual(v.Preview.Effects, v.Preview.Definition.Effects) {
				t.Fatal("canonical review", hash, e)
			}
			d := v.Preview.Definition
			if d.Workflow != v.Selection.Workflow || d.Source.ScheduleSourceSelection != v.Selection.Source || d.Authority != v.Selection.ExpectedAuthority {
				t.Fatal("selection")
			}
			p, e := calendar.Compile(d.Calendar)
			if e != nil {
				t.Fatal(e)
			}
			up, e := p.Preview(d.Calendar.Start.Add(-time.Nanosecond), 12)
			if e != nil || !reflect.DeepEqual(up, v.Preview.Upcoming) || len(up) != 2 || up[1].At.Sub(up[0].At) != time.Hour {
				t.Fatal("frozen fold", up, e)
			}
		})
	}
}
func TestScheduleMissedRulesKeepGraceLatestAndBoundedCursorMeaning(t *testing.T) {
	at := func(s string) time.Time {
		v, e := time.Parse(time.RFC3339, s)
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	s := calendar.Selection{Zone: "UTC", Start: at("2026-10-30T00:00:00Z"), End: at("2026-11-02T00:00:00Z"), Times: []string{"07:00:00", "08:00:00", "09:00:00"}, Weekdays: []int{0, 1, 2, 3, 4, 5, 6}, Holidays: []string{}, Gap: "skip", Fold: "both"}
	f, e := calendar.Snapshot(s)
	if e != nil {
		t.Fatal(e)
	}
	p, _ := calendar.Compile(f)
	cursor := at("2026-10-30T07:00:00Z")
	d := ScheduleDefinition{Calendar: f, Grace: 30}
	d.Missed = "skip"
	chosen, skip := scheduleMissed(p, &d, cursor, cursor.Add(20*time.Second))
	if skip != nil || chosen == nil || !chosen.Equal(cursor) {
		t.Fatal("normal polling jitter skipped due work", chosen, skip)
	}
	chosen, skip = scheduleMissed(p, &d, cursor, cursor.Add(31*time.Second))
	if chosen == nil || !chosen.Equal(at("2026-10-30T08:00:00Z")) || skip == nil || !skip.Equal(*chosen) {
		t.Fatal("late skip window", chosen, skip)
	}
	d.Missed = "latest"
	chosen, skip = scheduleMissed(p, &d, cursor, at("2026-10-30T09:00:20Z"))
	if chosen == nil || !chosen.Equal(at("2026-10-30T09:00:00Z")) || skip == nil || !skip.Equal(*chosen) {
		t.Fatal("latest exact due", chosen, skip)
	}
	d.Missed = "all"
	chosen, skip = scheduleMissed(p, &d, cursor, at("2026-10-30T09:00:20Z"))
	if chosen == nil || !chosen.Equal(cursor) || skip != nil {
		t.Fatal("catchup skipped cursor", chosen, skip)
	}
}
