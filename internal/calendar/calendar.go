// Package calendar evaluates reviewed civil-time schedules without consulting
// a mutable host clock or time-zone database during execution. Snapshot records
// the selected zone's actual UTC offset intervals in the immutable definition.
package calendar

import (
	"errors"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"
	_ "time/tzdata"
	"unicode"
)

var ErrInput = errors.New("invalid bounded calendar")
var zoneName = regexp.MustCompile(`^[A-Za-z0-9_+/-]{1,100}$`)

const MaxHorizon = 5 * 366 * 24 * time.Hour

type Selection struct {
	Zone     string    `json:"time_zone"`
	Start    time.Time `json:"starts_at"`
	End      time.Time `json:"ends_at"`
	Times    []string  `json:"local_times"`
	Weekdays []int     `json:"weekdays"`
	Holidays []string  `json:"holidays"`
	Gap      string    `json:"gap_policy"`
	Fold     string    `json:"fold_policy"`
}
type Rule struct {
	From   time.Time `json:"from"`
	Until  time.Time `json:"until"`
	Offset int       `json:"offset_seconds"`
	Name   string    `json:"abbreviation"`
}
type Definition struct {
	Selection
	Rules []Rule `json:"offset_rules"`
}
type Occurrence struct {
	At     time.Time `json:"at"`
	Local  string    `json:"local_time"`
	Offset int       `json:"offset_seconds"`
	Name   string    `json:"abbreviation"`
}

func Normalize(s Selection) (Selection, error) {
	if !zoneName.MatchString(s.Zone) || s.Zone == "Local" || strings.Contains(s.Zone, "..") || strings.HasPrefix(s.Zone, "/") || s.Start.IsZero() || s.End.IsZero() || s.Start.UTC().Add(-48*time.Hour).Year() < 1 || s.End.UTC().Add(48*time.Hour).Year() > 9999 || s.Start.Nanosecond() != 0 || s.End.Nanosecond() != 0 || !s.End.After(s.Start) || s.End.Sub(s.Start) > MaxHorizon || len(s.Times) < 1 || len(s.Times) > 96 || len(s.Weekdays) < 1 || len(s.Weekdays) > 7 || len(s.Holidays) > 512 || s.Gap != "skip" || (s.Fold != "first" && s.Fold != "second" && s.Fold != "both") {
		return s, ErrInput
	}
	s.Start, s.End = s.Start.UTC(), s.End.UTC()
	s.Times = append([]string{}, s.Times...)
	s.Weekdays = append([]int{}, s.Weekdays...)
	s.Holidays = append([]string{}, s.Holidays...)
	sort.Strings(s.Times)
	sort.Ints(s.Weekdays)
	sort.Strings(s.Holidays)
	for i, v := range s.Times {
		t, e := time.Parse("15:04:05", v)
		if e != nil || t.Format("15:04:05") != v || (i > 0 && s.Times[i-1] == v) {
			return s, ErrInput
		}
	}
	for i, v := range s.Weekdays {
		if v < 0 || v > 6 || (i > 0 && s.Weekdays[i-1] == v) {
			return s, ErrInput
		}
	}
	for i, v := range s.Holidays {
		t, e := time.Parse("2006-01-02", v)
		if e != nil || t.Format("2006-01-02") != v || (i > 0 && s.Holidays[i-1] == v) {
			return s, ErrInput
		}
	}
	return s, nil
}

// Snapshot makes host-zone changes incapable of moving already approved work.
// A new law/rule set requires a new preview and approval, never a silent rebind.
func Snapshot(s Selection) (Definition, error) {
	s, err := Normalize(s)
	if err != nil {
		return Definition{}, err
	}
	location, err := time.LoadLocation(s.Zone)
	if err != nil {
		return Definition{}, ErrInput
	}
	d := Definition{Selection: s, Rules: []Rule{}}
	end := s.End.Add(48 * time.Hour)
	for from := s.Start.Add(-48 * time.Hour); from.Before(end); {
		at := from.In(location)
		name, offset := at.Zone()
		_, until := at.ZoneBounds()
		if until.IsZero() || until.After(end) {
			until = end
		}
		until = until.UTC()
		if !until.After(from) || len(d.Rules) >= 64 {
			return Definition{}, ErrInput
		}
		d.Rules = append(d.Rules, Rule{From: from.UTC(), Until: until, Offset: offset, Name: name})
		from = until
	}
	if _, err := Compile(d); err != nil {
		return Definition{}, err
	}
	return d, nil
}

type Plan struct {
	d        Definition
	clocks   []int
	offsets  []int
	weekdays map[time.Weekday]bool
	holidays map[string]bool
}

func Compile(d Definition) (*Plan, error) {
	n, err := Normalize(d.Selection)
	if err != nil || !reflect.DeepEqual(n, d.Selection) || len(d.Rules) < 1 || len(d.Rules) > 64 || !d.Rules[0].From.Equal(d.Start.Add(-48*time.Hour)) || !d.Rules[len(d.Rules)-1].Until.Equal(d.End.Add(48*time.Hour)) {
		return nil, ErrInput
	}
	d.Selection = n
	d.Rules = append([]Rule{}, d.Rules...)
	p := &Plan{d: d, weekdays: map[time.Weekday]bool{}, holidays: map[string]bool{}}
	offsets := map[int]bool{}
	for i, r := range d.Rules {
		if !r.Until.After(r.From) || r.From.Nanosecond() != 0 || r.Until.Nanosecond() != 0 || r.Offset < -86400 || r.Offset > 86400 || len(r.Name) == 0 || len(r.Name) > 32 || (i > 0 && !r.From.Equal(d.Rules[i-1].Until)) {
			return nil, ErrInput
		}
		for _, c := range r.Name {
			if unicode.IsControl(c) {
				return nil, ErrInput
			}
		}
		offsets[r.Offset] = true
	}
	for v := range offsets {
		p.offsets = append(p.offsets, v)
	}
	sort.Ints(p.offsets)
	for _, v := range d.Times {
		t, _ := time.Parse("15:04:05", v)
		p.clocks = append(p.clocks, t.Hour()*3600+t.Minute()*60+t.Second())
	}
	for _, v := range d.Weekdays {
		p.weekdays[time.Weekday(v)] = true
	}
	for _, v := range d.Holidays {
		p.holidays[v] = true
	}
	return p, nil
}

func (p *Plan) rule(at time.Time) *Rule {
	i := sort.Search(len(p.d.Rules), func(i int) bool { return p.d.Rules[i].Until.After(at) })
	if i == len(p.d.Rules) || at.Before(p.d.Rules[i].From) {
		return nil
	}
	return &p.d.Rules[i]
}
func (p *Plan) Describe(at time.Time) (Occurrence, error) {
	r := p.rule(at)
	if r == nil {
		return Occurrence{}, ErrInput
	}
	return Occurrence{At: at.UTC(), Local: at.UTC().Add(time.Duration(r.Offset) * time.Second).Format("2006-01-02T15:04:05"), Offset: r.Offset, Name: r.Name}, nil
}
func (p *Plan) day(day time.Time) []time.Time {
	if !p.weekdays[day.Weekday()] || p.holidays[day.Format("2006-01-02")] {
		return nil
	}
	var out []time.Time
	for _, seconds := range p.clocks {
		wall := day.Add(time.Duration(seconds) * time.Second)
		var candidates []time.Time
		for _, offset := range p.offsets {
			at := wall.Add(-time.Duration(offset) * time.Second)
			if r := p.rule(at); r != nil && r.Offset == offset {
				candidates = append(candidates, at)
			}
		}
		sort.Slice(candidates, func(i, j int) bool { return candidates[i].Before(candidates[j]) })
		if len(candidates) > 1 {
			if p.d.Fold == "first" {
				candidates = candidates[:1]
			} else if p.d.Fold == "second" {
				candidates = candidates[len(candidates)-1:]
			}
		}
		out = append(out, candidates...)
	}
	return out
}
func midnight(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// search checks civil dates, not elapsed 24-hour additions in a local zone.
// The extra two dates on either side handle even a full-day offset change.
func (p *Plan) search(at time.Time, direction int) *time.Time {
	if (direction > 0 && !at.Before(p.d.End)) || (direction < 0 && at.Before(p.d.Start)) {
		return nil
	}
	anchor := at
	if direction > 0 && at.Before(p.d.Start) {
		anchor = p.d.Start
	}
	if direction < 0 && !at.Before(p.d.End) {
		anchor = p.d.End
	}
	day := midnight(anchor).AddDate(0, 0, -2*direction)
	var best *time.Time
	for count := 0; count < 5*366+8; count++ {
		if (direction > 0 && day.After(p.d.End.Add(48*time.Hour))) || (direction < 0 && day.Before(p.d.Start.Add(-48*time.Hour))) {
			break
		}
		for _, candidate := range p.day(day) {
			if candidate.Before(p.d.Start) || !candidate.Before(p.d.End) || (direction > 0 && !candidate.After(at)) || (direction < 0 && !candidate.Before(at)) {
				continue
			}
			if best == nil || (direction > 0 && candidate.Before(*best)) || (direction < 0 && candidate.After(*best)) {
				v := candidate
				best = &v
			}
		}
		if best != nil && ((direction > 0 && day.After(best.Add(48*time.Hour))) || (direction < 0 && day.Before(best.Add(-48*time.Hour)))) {
			break
		}
		day = day.AddDate(0, 0, direction)
	}
	return best
}
func (p *Plan) Next(after time.Time) *time.Time      { return p.search(after, 1) }
func (p *Plan) Previous(before time.Time) *time.Time { return p.search(before, -1) }
func (p *Plan) Preview(after time.Time, limit int) ([]Occurrence, error) {
	if limit < 1 || limit > 100 {
		return nil, ErrInput
	}
	out := []Occurrence{}
	for len(out) < limit {
		at := p.Next(after)
		if at == nil {
			break
		}
		d, err := p.Describe(*at)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
		after = *at
	}
	return out, nil
}
