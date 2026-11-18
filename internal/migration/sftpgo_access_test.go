package migration

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestPlanSFTPGoAccessKeepsScopeAndExactReferences(t *testing.T) {
	data := []byte(`{
  "version":17,
  "folders":[{"name":"private-root","mapped_path":"/private-os-root"}],
  "roles":[{"name":"private-role"}],
  "groups":[{"name":"private-group","virtual_folders":[{"name":"private-root","virtual_path":"/private-mount"}]}],
  "users":[{"username":"private-user","status":0,"role":"private-role","password":"private-hash",
    "groups":[{"name":"private-group","type":3}],"virtual_folders":[{"name":"private-root"}]}],
  "admins":[{"username":"private-user","status":1,"role":"private-role",
    "groups":[{"name":"private-group","options":{"add_to_users_as":1}}]}]
}`)
	plan, err := PlanSFTPGo(data)
	if err != nil {
		t.Fatal(err)
	}
	dependencies := map[string][][4]string{}
	for _, row := range plan.AccessRecords {
		if row.Disposition != "needs_input" || row.Dependencies == nil {
			t.Fatalf("unexpected access record %#v", row)
		}
		dependencies[row.Source] = [][4]string{}
		for _, edge := range row.Dependencies {
			if edge.Disposition != "needs_input" {
				t.Fatalf("unexpected access edge %#v", edge)
			}
			dependencies[row.Source] = append(dependencies[row.Source], [4]string{edge.Source, edge.Target, edge.Kind, edge.Membership})
		}
	}
	want := map[string][][4]string{
		"/folders/0": {},
		"/roles/0":   {},
		"/groups/0":  {{"/groups/0/virtual_folders/0", "/folders/0", "virtual_folder", ""}},
		"/users/0": {
			{"/users/0/role", "/roles/0", "role", ""},
			{"/users/0/groups/0", "/groups/0", "group_membership", "membership_only"},
			{"/users/0/virtual_folders/0", "/folders/0", "virtual_folder", ""},
		},
		"/admins/0": {
			{"/admins/0/role", "/roles/0", "role", ""},
			{"/admins/0/groups/0", "/groups/0", "managed_group", ""},
		},
	}
	if !reflect.DeepEqual(dependencies, want) || plan.AccessRecords[3].SourceState != "disabled" || plan.AccessRecords[4].SourceState != "enabled" {
		t.Fatalf("access graph = %#v", plan.AccessRecords)
	}
	encoded, err := json.Marshal(plan)
	if err != nil || strings.Contains(string(encoded), "private-") {
		t.Fatal("access graph emitted private names, paths or credential data")
	}
}

func TestPlanSFTPGoAccessLeavesUnresolvedAndAmbiguousRecordsBlocked(t *testing.T) {
	data := []byte(`{
  "version":17,
  "folders":[{"name":"same"},{"name":"same"}],
  "groups":[{"name":"linked","virtual_folders":[{"name":"same"}]}],
  "roles":null,
  "users":[{"username":"one","role":"missing","status":1,
    "groups":[{"name":"linked","type":0},null]}],
  "admins":[{"username":"undeclared-state"}]
}`)
	plan, err := PlanSFTPGo(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.AccessRecords) != 5 {
		t.Fatalf("unexpected access record count %d", len(plan.AccessRecords))
	}
	for _, row := range plan.AccessRecords {
		if row.Disposition != "blocked" {
			t.Fatalf("source problem was hidden %#v", row)
		}
		for _, edge := range row.Dependencies {
			if edge.Disposition != "blocked" || (edge.Kind != "group_membership" && edge.Target != "") {
				t.Fatalf("bad edge was treated as resolved %#v", edge)
			}
		}
	}
	user := plan.AccessRecords[3]
	if user.Dependencies[1].Target != "/groups/0" || user.Dependencies[1].Membership != "" ||
		user.Dependencies[1].Reason != "unknown_group_membership_type" {
		t.Fatalf("unknown membership silently acquired a meaning %#v", user.Dependencies[1])
	}
}

func TestPlanSFTPGoAccessShowsKeyAndShareScopeWithoutCreditingSecrets(t *testing.T) {
	data := []byte(`{
  "version":17,
  "users":[{"username":"private-user","status":1}],
  "admins":[{"username":"private-admin","status":1}],
  "api_keys":[
    {"name":"private-name","id":"private-id","scope":2,"user":"private-user","key":"private-key"},
    {"scope":1,"admin":"private-admin"},
    {"scope":2},
    {"scope":1},
    {"scope":2,"admin":"private-admin"},
    {"scope":1,"admin":"absent"},
    {"scope":9,"user":"private-user"}
  ],
  "shares":[
    {"id":"private-link","username":"private-user","scope":3,"paths":["/private-share"],"password":"private-share-password"},
    {"scope":1,"username":"absent"},
    {"scope":9,"username":"private-user"}
  ]
}`)
	plan, err := PlanSFTPGo(data)
	if err != nil {
		t.Fatal(err)
	}
	expected := []struct {
		scope, disposition, target string
	}{
		{"user", "needs_input", "/users/0"},
		{"admin", "needs_input", "/admins/0"},
		{"all_users", "unsupported", ""},
		{"all_admins", "unsupported", ""},
		{"user", "blocked", ""},
		{"admin", "blocked", ""},
		{"", "blocked", ""},
		{"read_write", "needs_input", "/users/0"},
		{"read", "blocked", ""},
		{"", "blocked", "/users/0"},
	}
	if len(plan.AccessRecords) != len(expected)+2 {
		t.Fatalf("access records = %d", len(plan.AccessRecords))
	}
	for i, row := range plan.AccessRecords[2:] {
		target := ""
		if len(row.Dependencies) != 0 {
			target = row.Dependencies[0].Target
		}
		want := expected[i]
		if row.SourceScope != want.scope || row.Disposition != want.disposition || target != want.target {
			t.Errorf("unexpected scope or dependency %#v", row)
		}
	}
	if len(plan.AccessRecords[4].Dependencies) != 0 || len(plan.AccessRecords[5].Dependencies) != 0 {
		t.Fatal("unbound credential acquired a destination identity")
	}
	encoded, err := json.Marshal(plan)
	if err != nil || strings.Contains(string(encoded), "private-") {
		t.Fatal("key or share information escaped the protected source")
	}
}
