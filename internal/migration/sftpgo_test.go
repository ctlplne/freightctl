package migration

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/ctlplne/freightctl/internal/calendar"
	secure "github.com/ctlplne/freightctl/internal/crypto"
)

func TestPlanSFTPGoInventoryDependenciesAndCalendar(t *testing.T) {
	data := []byte(`{
  "version":17,
  "users":[{"username":"private-user-marker","password":"private-password-marker"}],
  "groups":[],
  "folders":null,
  "configs":{"smtp":{"password":"private-smtp-marker","Name":"private-custom-field"}},
  "event_actions":[
    {"name":"private-first-action","type":4,"options":{"description":"private-option-marker"}},
    {"name":"private-recovery-action","type":3,"options":{"recipient":"private-recipient-marker"}}
  ],
  "event_rules":[
    {"name":"private-complete-rule","status":1,"trigger":3,
     "conditions":{"options":{"names":[{"pattern":"private-filter-marker"}]},"schedules":[
       {"hour":"00","day_of_month":"*","month":"*","day_of_week":"*"},
       {"hour":"19","day_of_month":"*","month":"*","day_of_week":"3"}
     ]},
     "actions":[
       {"name":"private-recovery-action","order":3,"relation_options":{"is_failure_action":true}},
       {"name":"private-first-action","relation_options":{"stop_on_failure":true}}
     ]},
    {"status":0,"trigger":3,"conditions":{"schedules":[
       {"hour":"4-8","day_of_month":"*","month":"*","day_of_week":"*"}
     ]},"actions":[{"name":"private-first-action","order":1}]},
    {"status":1,"trigger":1,"actions":[{"name":"private-first-action","order":1,"relation_options":{"execute_sync":true}}]}
  ]
}`)
	plan, err := PlanSFTPGo(data)
	if err != nil {
		t.Fatal(err)
	}
	if plan.SourceSHA256 != secure.Digest(data) || plan.SchemaVersion != 1 {
		t.Fatalf("source binding = %s, schema %d", plan.SourceSHA256, plan.SchemaVersion)
	}
	inventory := map[string]SFTPGoInventory{}
	for _, row := range plan.Inventory {
		inventory[row.Source] = row
	}
	for _, expected := range []SFTPGoInventory{
		{Source: "/users", State: "present", Records: 1},
		{Source: "/groups", State: "present", Records: 0},
		{Source: "/folders", State: "null"},
		{Source: "/admins", State: "missing"},
		{Source: "/configs", State: "present", Records: 1},
		{Source: "/event_rules", State: "present", Records: 3},
	} {
		if inventory[expected.Source] != expected {
			t.Errorf("inventory %s = %#v, want %#v", expected.Source, inventory[expected.Source], expected)
		}
	}
	first := plan.Rules[0]
	if first.Source != "/event_rules/0" || first.Disposition != "needs_input" || first.SourceState != "enabled" {
		t.Fatalf("first rule = %#v", first)
	}
	recovery, primary := first.Actions[0], first.Actions[1]
	if recovery.Source != "/event_rules/0/actions/0" || recovery.Target != "/event_actions/1" ||
		recovery.Order != 3 || !recovery.Failure || recovery.Disposition != "needs_input" ||
		primary.Target != "/event_actions/0" || primary.Order != 0 || !primary.StopOnError || primary.Disposition != "needs_input" {
		t.Fatalf("action graph = %#v", first.Actions)
	}
	if first.Schedules[0].Source != "/event_rules/0/conditions/schedules/0" ||
		!reflect.DeepEqual(first.Schedules[0].Calendar, &CalendarFragment{"UTC", []string{"00:00:00"}, []int{0, 1, 2, 3, 4, 5, 6}}) ||
		!reflect.DeepEqual(first.Schedules[1].Calendar, &CalendarFragment{"UTC", []string{"19:00:00"}, []int{3}}) {
		t.Fatalf("schedules = %#v", first.Schedules)
	}
	// The report fragment fits the real calendar fields after review supplies bounds.
	var selection calendar.Selection
	fragment, err := json.Marshal(first.Schedules[1].Calendar)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(fragment, &selection); err != nil {
		t.Fatal(err)
	}
	if selection.Zone != "UTC" || !reflect.DeepEqual(selection.Times, []string{"19:00:00"}) || !reflect.DeepEqual(selection.Weekdays, []int{3}) {
		t.Fatalf("calendar selection = %#v", selection)
	}
	if _, err := calendar.Normalize(selection); !errors.Is(err, calendar.ErrInput) {
		t.Fatalf("partial calendar is independently runnable: %v", err)
	}
	if rule := plan.Rules[1]; rule.SourceState != "disabled" || rule.Disposition != "unsupported" || rule.Schedules[0].Calendar != nil {
		t.Fatalf("unsupported schedule = %#v", rule)
	}
	if rule := plan.Rules[2]; rule.Disposition != "unsupported" || !rule.Actions[0].Synchronous {
		t.Fatalf("unsupported trigger = %#v", rule)
	}
	encoded, err := json.Marshal(plan)
	if err != nil || bytes.Contains(encoded, []byte("private-")) {
		t.Fatalf("private data was emitted or JSON encoding failed: %v", err)
	}
}

func TestPlanSFTPGoKeepsUnresolvedActionLinks(t *testing.T) {
	data := []byte(`{
  "version":17,
  "event_actions":[{"name":"duplicate","type":1},{"name":"duplicate","type":2},{"name":"invalid","type":10}],
  "event_rules":[{"status":1,"trigger":3,
    "conditions":{"schedules":[{"hour":"5","day_of_month":"*","month":"*","day_of_week":"0"}]},
    "actions":[{"name":"missing","order":1},{"name":"duplicate","order":2},{"name":"invalid","order":3},null]
  }]
}`)
	plan, err := PlanSFTPGo(data)
	if err != nil {
		t.Fatal(err)
	}
	rule := plan.Rules[0]
	if rule.Disposition != "blocked" || rule.Schedules[0].Calendar == nil || len(rule.Actions) != 4 {
		t.Fatalf("rule obscures unresolved work: %#v", rule)
	}
	for _, link := range rule.Actions {
		if link.Disposition != "blocked" || link.Target != "" {
			t.Errorf("unresolved link has a target: %#v", link)
		}
	}
}

func TestPlanSFTPGoRejectsInvalidOrUnboundedDumps(t *testing.T) {
	for _, tc := range []struct {
		name string
		data string
		err  error
	}{
		{"wrong-version", `{"version":16}`, errSFTPGoSchema},
		{"unknown-section", `{"version":17,"private-section":{}}`, errSFTPGoSchema},
		{"missing-version", `{"event_rules":[]}`, errSFTPGoSchema},
		{"duplicate-section", `{"version":17,"users":[],"users":null}`, errSFTPGoDump},
		{"duplicate-version", `{"version":17,"version":17}`, errSFTPGoDump},
		{"duplicate-nested-field", `{"version":17,"users":[{"password":"private-marker","password":""}]}`, errSFTPGoDump},
		{"case-alias", `{"version":17,"event_actions":[{"name":"a","TYPE":1}]}`, errSFTPGoDump},
		{"unicode-case-alias", `{"version":17,"event_rules":[{"ſtatus":1}]}`, errSFTPGoDump},
		{"second-value", `{"version":17}{}`, errSFTPGoDump},
		{"scalar-row", `{"version":17,"users":[null]}`, errSFTPGoDump},
		{"invalid-typed-field", `{"version":17,"event_actions":[{"name":"a","type":"private-marker"}]}`, errSFTPGoDump},
		{"excess-depth", `{"version":17,"configs":{"nested":` + strings.Repeat("[", maxSourceDepth) + "0" + strings.Repeat("]", maxSourceDepth) + "}}", errSFTPGoDump},
		{"excess-tokens", `{"version":17,"configs":{"nested":[` + strings.Repeat("0,", maxSourceTokens) + "0]}}", errSFTPGoDump},
		{"excess-bytes", strings.Repeat(" ", MaxSFTPGoDumpBytes+1), errSFTPGoDump},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan, err := PlanSFTPGo([]byte(tc.data))
			if !errors.Is(err, tc.err) || plan.SchemaVersion != 0 || strings.Contains(err.Error(), "private-") {
				t.Fatalf("unexpected outcome with private data suppressed: %v", err)
			}
		})
	}
}
