//go:build integration

package api

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/freightctl/internal/checks"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

func jsonRecordsSameJSON(a, b []byte) bool {
	var left, right any
	x, y := json.NewDecoder(bytes.NewReader(a)), json.NewDecoder(bytes.NewReader(b))
	x.UseNumber()
	y.UseNumber()
	return x.Decode(&left) == nil && y.Decode(&right) == nil && reflect.DeepEqual(left, right)
}

// Uses the ordinary verified HTTPS server and non-owner PostgreSQL role. The
// parser's unit cases cannot establish these custody and permission outcomes.
func TestJSONRecordsHTTPSCookieBearerHeldChecksAndSeparateRelease(t *testing.T) {
	service, scope, admin, server := browserAPI(t, 10*time.Minute)
	t.Cleanup(func() { _ = service.Disk.Close() })
	cookie, csrf := loginBrowser(t, server, scope, admin)
	prefix := "/v1/tenants/" + scope.Tenant + "/partners/" + scope.Partner
	policy := checks.Policy{Schema: 2, Kind: "json_records", Columns: []checks.Column{
		{Name: "account", Type: "text", Required: true},
		{Name: "amount", Type: "decimal", Required: true, Precision: 12, Scale: 2},
		{Name: "day", Type: "date", Required: true},
	}}
	request := exchangeAPIJSON(t, checks.PolicyRequest{Definition: policy})
	mutating := func(key string) map[string]string {
		return map[string]string{"Origin": server.URL, "X-CSRF-Token": csrf, "Idempotency-Key": key}
	}
	// No missing-CSRF registration may consume the original command key.
	exchangeAPIRequest(t, server, "POST", prefix+"/intake-policy", cookie, map[string]string{"Origin": server.URL, "Idempotency-Key": "json-policy"}, request, 403)
	_, raw := exchangeAPIRequest(t, server, "POST", prefix+"/intake-policy", cookie, mutating("json-policy"), request, 200)
	var saved checks.Result
	var configured store.Configuration
	if json.Unmarshal(raw, &saved) != nil || saved.Replayed || json.Unmarshal(saved.Resource, &configured) != nil {
		t.Fatal("invalid policy registration receipt")
	}
	normalized, err := checks.Normalize(policy)
	if err != nil || configured.Hash != secure.Digest(exchangeAPIJSON(t, normalized)) {
		t.Fatal("HTTPS policy differs from the reviewed Go definition", err)
	}
	bearer := map[string]string{"Authorization": "Bearer " + string(admin.Bytes), "Idempotency-Key": "json-policy"}
	_, raw = exchangeAPIRequest(t, server, "POST", prefix+"/intake-policy", nil, bearer, request, 200)
	var replay checks.Result
	if json.Unmarshal(raw, &replay) != nil || !replay.Replayed || !jsonRecordsSameJSON(saved.Resource, replay.Resource) {
		t.Fatal("cookie and bearer lost the original policy receipt")
	}
	readOnly, _ := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "list"})
	for _, fixture := range []struct{ name, body, code string }{
		{"valid", `[{"account":"0001","amount":1.01,"day":"2026-10-28"}]`, "valid_json_records"},
		{"duplicate", `[{"account":"0001","account":"0002","amount":1.01,"day":"2026-10-28"}]`, "duplicate_field"},
		{"unknown", `[{"account":"0001","amount":1.01,"day":"2026-10-28","execute":"private sentinel"}]`, "unknown_field"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			headers := mutating("json-upload-" + fixture.name)
			headers["X-File-Size"], headers["X-Content-SHA256"] = strconv.Itoa(len(fixture.body)), secure.Digest([]byte(fixture.body))
			path := prefix + "/namespace/file?path=/" + fixture.name + ".json"
			_, raw := exchangeAPIRequest(t, server, "PUT", path, cookie, headers, []byte(fixture.body), 201)
			var accepted struct {
				File       store.File `json:"file"`
				Acceptance string     `json:"acceptance"`
			}
			if json.Unmarshal(raw, &accepted) != nil || accepted.Acceptance != "durable-held-pending-checks-and-release" || accepted.File.Policy != store.JSONRecordsIntakePrefix+configured.Hash {
				t.Fatal("JSON upload did not retain its exact held identity")
			}
			fileURL := prefix + "/files/" + accepted.File.ID
			for _, method := range []string{"GET", "HEAD"} {
				exchangeAPIRequest(t, server, method, fileURL, cookie, nil, nil, 409)
			}
			checkURL := prefix + "/checks/" + accepted.File.ID
			_, raw = exchangeAPIRequest(t, server, "POST", checkURL+"/run", cookie, mutating("json-run-"+fixture.name), nil, 200)
			var first checks.Result
			if json.Unmarshal(raw, &first) != nil || first.Replayed {
				t.Fatal("first check receipt")
			}
			_, raw = exchangeAPIRequest(t, server, "POST", checkURL+"/run", nil, map[string]string{"Authorization": bearer["Authorization"], "Idempotency-Key": "json-run-" + fixture.name}, nil, 200)
			if json.Unmarshal(raw, &replay) != nil || !replay.Replayed || !jsonRecordsSameJSON(first.Resource, replay.Resource) {
				t.Fatal("original check retry ran another parser attempt")
			}
			_, raw = exchangeAPIRequest(t, server, "GET", checkURL, cookie, nil, nil, 200)
			var view checks.View
			var report checks.Report
			if json.Unmarshal(raw, &view) != nil || view.Check == nil || !view.Current || view.Check.Attempts != 1 || json.Unmarshal(view.Check.Report, &report) != nil || report.Engine != "freightctl-json-records-v1" || report.Code != fixture.code || report.FileID != accepted.File.ID || report.PolicyHash != configured.Hash || report.SHA256 != accepted.File.SHA256 {
				t.Fatal("HTTPS check report lost its format or immutable bindings")
			}
			if bytes.Contains(raw, []byte("private sentinel")) || bytes.Contains(raw, []byte(`"0001"`)) {
				t.Fatal("check evidence disclosed raw record values")
			}
			decision := checks.ReleaseDecision{SHA256: accepted.File.SHA256, PolicyHash: configured.Hash, ReportHash: view.Check.ReportHash, Revision: view.Check.Revision}
			exchangeAPIRequest(t, server, "POST", checkURL+"/release", nil, map[string]string{"Authorization": "Bearer " + string(readOnly.Bytes), "Idempotency-Key": "readonly-release"}, exchangeAPIJSON(t, decision), 403)
			if fixture.code != "valid_json_records" {
				if view.Check.State != "rejected" {
					t.Fatal("invalid records were not rejected")
				}
				exchangeAPIRequest(t, server, "POST", checkURL+"/release", cookie, mutating("reject-release-"+fixture.name), exchangeAPIJSON(t, decision), 409)
				exchangeAPIRequest(t, server, "GET", fileURL, cookie, nil, nil, 409)
				return
			}
			if view.Check.State != "passed" || report.Rows != 1 || report.Bytes != accepted.File.Size {
				t.Fatal("successful JSON check has wrong counters")
			}
			exchangeAPIRequest(t, server, "GET", fileURL, cookie, nil, nil, 409)
			wrong := decision
			wrong.SHA256 = strings.Repeat("0", 64)
			exchangeAPIRequest(t, server, "POST", checkURL+"/release", cookie, mutating("wrong-json-release"), exchangeAPIJSON(t, wrong), 409)
			_, released := exchangeAPIRequest(t, server, "POST", checkURL+"/release", cookie, mutating("json-release"), exchangeAPIJSON(t, decision), 200)
			var original checks.Result
			if json.Unmarshal(released, &original) != nil || original.Replayed {
				t.Fatal("first release receipt")
			}
			_, raw = exchangeAPIRequest(t, server, "POST", checkURL+"/release", nil, map[string]string{"Authorization": bearer["Authorization"], "Idempotency-Key": "json-release"}, exchangeAPIJSON(t, decision), 200)
			if json.Unmarshal(raw, &replay) != nil || !replay.Replayed || !jsonRecordsSameJSON(original.Resource, replay.Resource) {
				t.Fatal("release replay changed original evidence")
			}
			response, got := exchangeAPIRequest(t, server, "GET", path, nil, bearer, nil, 200)
			if !bytes.Equal(got, []byte(fixture.body)) || secure.Digest(got) != accepted.File.SHA256 || response.Header.Get("X-File-Revision-ID") != accepted.File.ID {
				t.Fatal("independent HTTPS observer received another revision")
			}
		})
	}
}
