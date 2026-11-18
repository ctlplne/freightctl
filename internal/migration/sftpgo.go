// Package migration reads source configurations and describes work for an operator to review.
package migration

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	secure "github.com/ctlplne/freightctl/internal/crypto"
)

const (
	MaxSFTPGoDumpBytes    = 8 << 20
	sftpgoScheduleTrigger = 3
	maxSourceDepth        = 32
	maxSourceTokens       = 300_000
)

var (
	errSFTPGoDump   = errors.New("invalid or oversized SFTPGo JSON dump")
	errSFTPGoSchema = errors.New("expected SFTPGo Community dump format 17 with recognized sections")
	sftpgoSections  = [...]string{"users", "groups", "folders", "admins", "api_keys", "shares", "event_actions", "event_rules", "roles", "ip_lists", "configs"}
)

type SFTPGoPlan struct {
	SchemaVersion int                  `json:"schema_version"`
	SourceProfile string               `json:"source_profile"`
	SourceSHA256  string               `json:"source_sha256"`
	Inventory     []SFTPGoInventory    `json:"inventory"`
	Actions       []SFTPGoActionPlan   `json:"actions"`
	Rules         []SFTPGoRulePlan     `json:"rules"`
	AccessRecords []SFTPGoAccessRecord `json:"access_records"`
}

type SFTPGoInventory struct {
	Source  string `json:"source"`
	State   string `json:"state"`
	Records int    `json:"records"`
}

type SFTPGoActionPlan struct {
	Source      string `json:"source"`
	Type        int    `json:"action_type"`
	Disposition string `json:"disposition"`
	Reason      string `json:"reason"`
}

type SFTPGoRulePlan struct {
	Source      string                   `json:"source"`
	Trigger     int                      `json:"trigger_type"`
	SourceState string                   `json:"source_state"`
	Disposition string                   `json:"disposition"`
	Reason      string                   `json:"reason"`
	Actions     []SFTPGoActionDependency `json:"action_dependencies"`
	Schedules   []SFTPGoSchedulePlan     `json:"schedules"`
}

type SFTPGoActionDependency struct {
	Source      string `json:"source"`
	Target      string `json:"target,omitempty"`
	Order       int    `json:"order"`
	Failure     bool   `json:"is_failure_action"`
	StopOnError bool   `json:"stop_on_failure"`
	Synchronous bool   `json:"execute_sync"`
	Disposition string `json:"disposition"`
	Reason      string `json:"reason"`
}

type SFTPGoSchedulePlan struct {
	Source      string            `json:"source"`
	Disposition string            `json:"disposition"`
	Reason      string            `json:"reason"`
	Calendar    *CalendarFragment `json:"calendar_fragment,omitempty"`
}

// CalendarFragment supplies the matching fields of calendar.Selection.
// The destination's approved workflow and calendar bounds come from review.
type CalendarFragment struct {
	Zone     string   `json:"time_zone"`
	Times    []string `json:"local_times"`
	Weekdays []int    `json:"weekdays"`
}

type sftpgoAction struct {
	Name string `json:"name"`
	Type int    `json:"type"`
}

type sftpgoActionLink struct {
	Name    string `json:"name"`
	Order   int    `json:"order"`
	Options struct {
		Failure     bool `json:"is_failure_action"`
		StopOnError bool `json:"stop_on_failure"`
		Synchronous bool `json:"execute_sync"`
	} `json:"relation_options"`
}

type sftpgoSchedule struct {
	Hour       string `json:"hour"`
	DayOfWeek  string `json:"day_of_week"`
	DayOfMonth string `json:"day_of_month"`
	Month      string `json:"month"`
}

type sftpgoRule struct {
	Status     *int `json:"status"`
	Trigger    int  `json:"trigger"`
	Conditions struct {
		Schedules []*sftpgoSchedule `json:"schedules"`
	} `json:"conditions"`
	Actions []*sftpgoActionLink `json:"actions"`
}

// PlanSFTPGo only returns generated source pointers, typed numeric/boolean
// metadata, and reconstructed calendar fields. Names are joined in memory.
func PlanSFTPGo(data []byte) (SFTPGoPlan, error) {
	inventory, err := inspectSFTPGoDump(data)
	if err != nil {
		return SFTPGoPlan{}, err
	}
	var source struct {
		sftpgoAccessDump
		Actions []sftpgoAction `json:"event_actions"`
		Rules   []sftpgoRule   `json:"event_rules"`
	}
	if json.Unmarshal(data, &source) != nil {
		return SFTPGoPlan{}, errSFTPGoDump
	}
	plan := SFTPGoPlan{
		SchemaVersion: 1,
		SourceProfile: "sftpgo-community-dump-v17",
		SourceSHA256:  secure.Digest(data),
		Inventory:     inventory,
		Actions:       make([]SFTPGoActionPlan, 0, len(source.Actions)),
		Rules:         make([]SFTPGoRulePlan, 0, len(source.Rules)),
		AccessRecords: planSFTPGoAccess(source.sftpgoAccessDump),
	}
	actionTargets := make(sourceNames, len(source.Actions))
	for i, action := range source.Actions {
		row := SFTPGoActionPlan{
			Source: fmt.Sprintf("/event_actions/%d", i), Type: action.Type,
			Disposition: "needs_input", Reason: "review_action_effect_and_authority",
		}
		if action.Name == "" || action.Type < 1 || action.Type > 15 || action.Type == 10 {
			row.Disposition, row.Reason = "blocked", "invalid_action_identity_or_type"
		}
		target := row.Source
		if row.Disposition == "blocked" {
			target = ""
		}
		actionTargets.add(action.Name, target)
		plan.Actions = append(plan.Actions, row)
	}
	for i, rule := range source.Rules {
		plan.Rules = append(plan.Rules, planSFTPGoRule(i, rule, actionTargets))
	}
	return plan, nil
}

// Scan every section before typed decoding. This checks omitted/empty sections
// independently and bounds the parser even for fields the report never reads.
func inspectSFTPGoDump(data []byte) ([]SFTPGoInventory, error) {
	if len(data) == 0 || len(data) > MaxSFTPGoDumpBytes || !utf8.Valid(data) {
		return nil, errSFTPGoDump
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	budget := maxSourceTokens
	root, err := inspectToken(decoder, &budget)
	if err != nil || root != json.Delim('{') {
		return nil, errSFTPGoDump
	}
	inventory := make([]SFTPGoInventory, len(sftpgoSections))
	index := make(map[string]int, len(sftpgoSections))
	for i, name := range sftpgoSections {
		index[name] = i
		inventory[i] = SFTPGoInventory{Source: "/" + name, State: "missing"}
	}
	seenVersion := false
	for decoder.More() {
		key, err := inspectToken(decoder, &budget)
		name, ok := key.(string)
		if err != nil || !ok {
			return nil, errSFTPGoDump
		}
		if name == "version" {
			token, err := inspectToken(decoder, &budget)
			if err != nil || seenVersion {
				return nil, errSFTPGoDump
			}
			if token != json.Number("17") {
				return nil, errSFTPGoSchema
			}
			seenVersion = true
			continue
		}
		i, known := index[name]
		if !known {
			return nil, errSFTPGoSchema
		}
		if inventory[i].State != "missing" {
			return nil, errSFTPGoDump
		}
		if err := inspectSFTPGoSection(decoder, &inventory[i], &budget); err != nil {
			return nil, err
		}
	}
	end, err := inspectToken(decoder, &budget)
	if err != nil || end != json.Delim('}') {
		return nil, errSFTPGoDump
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errSFTPGoDump
	}
	if !seenVersion {
		return nil, errSFTPGoSchema
	}
	return inventory, nil
}

func inspectToken(decoder *json.Decoder, budget *int) (json.Token, error) {
	if *budget == 0 {
		return nil, errSFTPGoDump
	}
	*budget = *budget - 1
	return decoder.Token()
}

func inspectSFTPGoSection(decoder *json.Decoder, section *SFTPGoInventory, budget *int) error {
	start, err := inspectToken(decoder, budget)
	if err != nil {
		return errSFTPGoDump
	}
	if start == nil {
		section.State = "null"
		return nil
	}
	section.State = "present"
	if section.Source == "/configs" {
		if start != json.Delim('{') {
			return errSFTPGoDump
		}
		section.Records = 1
		return inspectSFTPGoValue(decoder, start, budget, 2, false)
	}
	if start != json.Delim('[') {
		return errSFTPGoDump
	}
	switch section.Source {
	case "/event_rules", "/event_actions", "/users", "/admins", "/groups", "/folders", "/roles":
		return inspectSFTPGoRows(decoder, section, budget, true)
	default:
		return inspectSFTPGoRows(decoder, section, budget, false)
	}
}

func inspectSFTPGoRows(decoder *json.Decoder, section *SFTPGoInventory, budget *int, typed bool) error {
	for decoder.More() {
		row, err := inspectToken(decoder, budget)
		if err != nil || row != json.Delim('{') {
			return errSFTPGoDump
		}
		section.Records++
		if err := inspectSFTPGoValue(decoder, row, budget, 3, typed); err != nil {
			return err
		}
	}
	end, err := inspectToken(decoder, budget)
	if err != nil || end != json.Delim(']') {
		return errSFTPGoDump
	}
	return nil
}

func inspectSFTPGoValue(decoder *json.Decoder, start json.Token, budget *int, depth int, typed bool) error {
	if depth > maxSourceDepth {
		return errSFTPGoDump
	}
	switch start {
	case json.Delim('{'):
		seen := map[string]bool{}
		for decoder.More() {
			key, err := inspectToken(decoder, budget)
			name, ok := key.(string)
			if err != nil || !ok || seen[name] || (typed && isSFTPGoFieldAlias(name)) {
				return errSFTPGoDump
			}
			seen[name] = true
			childTyped := false
			switch name {
			case "actions", "conditions", "schedules", "relation_options", "groups", "virtual_folders":
				childTyped = typed
			}
			value, err := inspectToken(decoder, budget)
			if err != nil || inspectSFTPGoValue(decoder, value, budget, depth+1, childTyped) != nil {
				return errSFTPGoDump
			}
		}
		end, err := inspectToken(decoder, budget)
		if err != nil || end != json.Delim('}') {
			return errSFTPGoDump
		}
	case json.Delim('['):
		for decoder.More() {
			value, err := inspectToken(decoder, budget)
			if err != nil || inspectSFTPGoValue(decoder, value, budget, depth+1, typed) != nil {
				return errSFTPGoDump
			}
		}
		end, err := inspectToken(decoder, budget)
		if err != nil || end != json.Delim(']') {
			return errSFTPGoDump
		}
	}
	return nil
}

// encoding/json also accepts case-insensitive struct keys. Only the exact
// spelling can supply a field used in the report. Free-form option keys remain
// opaque and may use any spelling.
func isSFTPGoFieldAlias(name string) bool {
	for _, field := range [...]string{
		"name", "type", "status", "trigger", "conditions", "schedules", "actions",
		"order", "relation_options", "is_failure_action", "stop_on_failure", "execute_sync",
		"hour", "day_of_week", "day_of_month", "month",
		"username", "role", "groups", "virtual_folders",
	} {
		if name != field && strings.EqualFold(name, field) {
			return true
		}
	}
	return false
}

func planSFTPGoRule(index int, rule sftpgoRule, actionTargets sourceNames) SFTPGoRulePlan {
	row := SFTPGoRulePlan{
		Source: fmt.Sprintf("/event_rules/%d", index), Trigger: rule.Trigger,
		SourceState: sftpgoStatus(rule.Status), Disposition: "needs_input", Reason: "review_rule_conditions_and_destination_workflow",
		Actions:   make([]SFTPGoActionDependency, 0, len(rule.Actions)),
		Schedules: make([]SFTPGoSchedulePlan, 0, len(rule.Conditions.Schedules)),
	}
	if rule.Trigger != sftpgoScheduleTrigger {
		row.Disposition, row.Reason = "unsupported", "source_trigger_has_no_mapping"
	}
	if row.SourceState == "unknown" || len(rule.Actions) == 0 || (rule.Trigger == sftpgoScheduleTrigger && len(rule.Conditions.Schedules) == 0) {
		row.Disposition, row.Reason = "blocked", "missing_or_invalid_rule_input"
	}
	for i, action := range rule.Actions {
		dependency := SFTPGoActionDependency{
			Source:      fmt.Sprintf("%s/actions/%d", row.Source, i),
			Disposition: "blocked", Reason: "action_reference_unresolved",
		}
		if action != nil {
			dependency.Order = action.Order
			dependency.Failure = action.Options.Failure
			dependency.StopOnError = action.Options.StopOnError
			dependency.Synchronous = action.Options.Synchronous
			dependency.Target = actionTargets[action.Name]
			if dependency.Target != "" {
				dependency.Disposition, dependency.Reason = "needs_input", "review_action_effect_and_authority"
			}
		}
		if dependency.Disposition == "blocked" && row.Disposition != "blocked" {
			row.Disposition, row.Reason = "blocked", "unresolved_action_dependency"
		}
		row.Actions = append(row.Actions, dependency)
	}
	for i, schedule := range rule.Conditions.Schedules {
		s := SFTPGoSchedulePlan{
			Source:      fmt.Sprintf("%s/conditions/schedules/%d", row.Source, i),
			Disposition: "unsupported", Reason: "source_calendar_has_no_mapping",
		}
		if rule.Trigger == sftpgoScheduleTrigger {
			s.Calendar = sftpgoCalendar(schedule)
			if s.Calendar != nil {
				s.Disposition, s.Reason = "needs_input", "review_calendar_bounds_and_missed_runs"
			}
		}
		if s.Disposition == "unsupported" && row.Disposition == "needs_input" {
			row.Disposition, row.Reason = "unsupported", "one_or_more_schedules_have_no_mapping"
		}
		row.Schedules = append(row.Schedules, s)
	}
	return row
}

func sftpgoStatus(status *int) string {
	if status != nil {
		switch *status {
		case 0:
			return "disabled"
		case 1:
			return "enabled"
		}
	}
	return "unknown"
}

func sftpgoCalendar(schedule *sftpgoSchedule) *CalendarFragment {
	if schedule == nil || schedule.DayOfMonth != "*" || schedule.Month != "*" {
		return nil
	}
	hour, err := strconv.Atoi(schedule.Hour)
	if err != nil || hour < 0 || hour > 23 || (schedule.Hour != strconv.Itoa(hour) && schedule.Hour != fmt.Sprintf("%02d", hour)) {
		return nil
	}
	days := []int{0, 1, 2, 3, 4, 5, 6}
	if schedule.DayOfWeek != "*" {
		weekday := schedule.DayOfWeek
		if len(weekday) != 1 || weekday[0] < '0' || weekday[0] > '6' {
			return nil
		}
		days = []int{int(weekday[0] - '0')}
	}
	return &CalendarFragment{Zone: "UTC", Times: []string{fmt.Sprintf("%02d:00:00", hour)}, Weekdays: days}
}
