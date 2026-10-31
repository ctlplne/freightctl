package calendar

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func instant(s string) time.Time {
	t, e := time.Parse(time.RFC3339, s)
	if e != nil {
		panic(e)
	}
	return t
}
func selection(zone, start, end, clock, fold string) Selection {
	return Selection{Zone: zone, Start: instant(start), End: instant(end), Times: []string{clock}, Weekdays: []int{0, 1, 2, 3, 4, 5, 6}, Holidays: []string{}, Gap: "skip", Fold: fold}
}
func occurrences(t *testing.T, s Selection) []Occurrence {
	t.Helper()
	d, e := Snapshot(s)
	if e != nil {
		t.Fatal(e)
	}
	p, e := Compile(d)
	if e != nil {
		t.Fatal(e)
	}
	v, e := p.Preview(s.Start.Add(-time.Nanosecond), 100)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func ats(v []Occurrence) []string {
	out := []string{}
	for _, x := range v {
		out = append(out, x.At.Format(time.RFC3339))
	}
	return out
}
func TestGapSkipsMissingCivilTimeWithoutMovingIt(t *testing.T) {
	s := selection("America/New_York", "2024-03-09T00:00:00Z", "2024-03-12T00:00:00Z", "02:30:00", "both")
	got := ats(occurrences(t, s))
	want := []string{"2024-03-09T07:30:00Z", "2024-03-11T06:30:00Z"}
	if !reflect.DeepEqual(got, want) {
		t.Fatal(got)
	}
}
func TestFoldPoliciesBindEitherOrBothUTCInstants(t *testing.T) {
	for _, fold := range []string{"first", "second", "both"} {
		t.Run(fold, func(t *testing.T) {
			s := selection("America/New_York", "2024-11-03T00:00:00Z", "2024-11-04T00:00:00Z", "01:30:00", fold)
			want := []string{"2024-11-03T05:30:00Z", "2024-11-03T06:30:00Z"}
			if fold == "first" {
				want = want[:1]
			} else if fold == "second" {
				want = want[1:]
			}
			if got := ats(occurrences(t, s)); !reflect.DeepEqual(got, want) {
				t.Fatal(got)
			}
		})
	}
}
func TestNonHourFoldAndCalendarDates(t *testing.T) {
	s := selection("Australia/Lord_Howe", "2024-04-06T00:00:00Z", "2024-04-08T00:00:00Z", "01:45:00", "both")
	v := occurrences(t, s)
	var fold []Occurrence
	for _, x := range v {
		if x.Local == "2024-04-07T01:45:00" {
			fold = append(fold, x)
		}
	}
	if len(fold) != 2 || fold[1].At.Sub(fold[0].At) != 30*time.Minute {
		t.Fatal(v)
	}
	s = selection("UTC", "2026-10-30T00:00:00Z", "2026-11-06T00:00:00Z", "07:00:00", "first")
	s.Weekdays = []int{1, 2, 3, 4, 5}
	s.Holidays = []string{"2026-11-02"}
	want := []string{"2026-10-30T07:00:00Z", "2026-11-03T07:00:00Z", "2026-11-04T07:00:00Z", "2026-11-05T07:00:00Z"}
	if got := ats(occurrences(t, s)); !reflect.DeepEqual(got, want) {
		t.Fatal(got)
	}
}
func TestPreviousNextRoundTripsAndExactHorizon(t *testing.T) {
	s := selection("America/New_York", "2024-11-03T05:30:00Z", "2024-11-03T06:30:01Z", "01:30:00", "both")
	d, e := Snapshot(s)
	if e != nil {
		t.Fatal(e)
	}
	p, _ := Compile(d)
	first := p.Next(s.Start.Add(-time.Nanosecond))
	second := p.Next(*first)
	if first == nil || second == nil || !first.Equal(s.Start) || !second.Equal(s.End.Add(-time.Second)) || p.Next(*second) != nil {
		t.Fatal(first, second)
	}
	if prev := p.Previous(second.Add(time.Nanosecond)); prev == nil || !prev.Equal(*second) {
		t.Fatal(prev)
	}
	if prev := p.Previous(*second); prev == nil || !prev.Equal(*first) {
		t.Fatal(prev)
	}
	if p.Previous(*first) != nil {
		t.Fatal("before horizon")
	}
}
func TestSnapshotIsReplayableAndPlanOwnsItsFrozenRules(t *testing.T) {
	s := selection("Pacific/Apia", "2011-12-28T00:00:00Z", "2012-01-02T00:00:00Z", "12:00:00", "both")
	d, e := Snapshot(s)
	if e != nil {
		t.Fatal(e)
	}
	encoded, _ := json.Marshal(d)
	var restored Definition
	if json.Unmarshal(encoded, &restored) != nil {
		t.Fatal("decode")
	}
	p, e := Compile(restored)
	if e != nil {
		t.Fatal(e)
	}
	before, _ := p.Preview(s.Start.Add(-time.Nanosecond), 100)
	for _, x := range before {
		if x.Local[:10] == "2011-12-30" {
			t.Fatal("invented skipped civil date", x)
		}
	}
	restored.Rules[0].Offset = 0
	restored.Times[0] = "00:00:00"
	restored.Holidays = append(restored.Holidays, "2011-12-29")
	after, _ := p.Preview(s.Start.Add(-time.Nanosecond), 100)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("caller mutated compiled rules")
	}
}
func TestInvalidAndOversizedCalendarsRefuseWithoutTruncation(t *testing.T) {
	valid := selection("UTC", "2026-10-30T00:00:00Z", "2026-11-06T00:00:00Z", "07:00:00", "first")
	for _, mutate := range []func(*Selection){func(s *Selection) { s.Zone = "Local" }, func(s *Selection) { s.Zone = "../etc/passwd" }, func(s *Selection) { s.Zone = "Unregistered/Zone" }, func(s *Selection) { s.End = s.Start }, func(s *Selection) { s.End = s.Start.Add(MaxHorizon + time.Second) }, func(s *Selection) { s.Start = s.Start.Add(time.Nanosecond) }, func(s *Selection) { s.Times = []string{"7:00:00"} }, func(s *Selection) { s.Times = []string{"07:00:00", "07:00:00"} }, func(s *Selection) { s.Weekdays = []int{1, 1} }, func(s *Selection) { s.Weekdays = []int{7} }, func(s *Selection) { s.Holidays = []string{"2026-02-30"} }, func(s *Selection) { s.Gap = "guess" }, func(s *Selection) { s.Fold = "guess" }} {
		b, _ := json.Marshal(valid)
		var s Selection
		json.Unmarshal(b, &s)
		mutate(&s)
		if _, e := Snapshot(s); e == nil {
			t.Fatal("invalid accepted", s)
		}
	}
	d, _ := Snapshot(valid)
	d.Rules[0].Until = d.Rules[0].Until.Add(time.Second)
	if _, e := Compile(d); e == nil {
		t.Fatal("rule coverage hole/overlap")
	}
}
