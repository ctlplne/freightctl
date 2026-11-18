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
