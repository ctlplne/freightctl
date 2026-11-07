//go:build integration

package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/ctlplne/freightctl/internal/checks"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestWebDAVConditionalReplacementPinsIdentityRaceAndHeldRelease(t *testing.T) {
	service, scope, admin, server := browserAPI(t, time.Minute)
	cookie, csrf := loginBrowser(t, server, scope, admin)
	prefix := "/v1/tenants/" + scope.Tenant + "/partners/" + scope.Partner
	path := prefix + "/dav/replace.dat"
	auth := map[string]string{"Authorization": "Bearer " + string(admin.Bytes)}
	type receipt struct {
		File       store.File `json:"file"`
		Replayed   bool       `json:"replayed"`
		Acceptance string     `json:"acceptance"`
		Namespace  string     `json:"namespace_state"`
	}
	put := func(path, key, tag string, data []byte, status int) (receipt, *http.Response) {
		t.Helper()
		h := map[string]string{"Authorization": auth["Authorization"], "Idempotency-Key": key, "X-Content-SHA256": secure.Digest(data)}
		if tag == "*" {
			h["If-None-Match"] = "*"
		} else {
			h["If-Match"] = tag
		}
		rawResponse, raw := exchangeAPIRequest(t, server, "PUT", path, nil, h, data, status)
		var r receipt
		if status < 300 && json.Unmarshal(raw, &r) != nil {
			t.Fatal("invalid conditional write receipt")
		}
		return r, rawResponse
	}
	before := []byte("immutable original custody\n")
	original, created := put(path, "dav-replace-initial", "*", before, 201)
	tag := created.Header.Get("ETag")
	writer, _ := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"write"})
	for _, credential := range []string{string(writer.Bytes)} {
		h := map[string]string{"Authorization": "Bearer " + credential, "If-Match": tag, "Idempotency-Key": "dav-replace-write-only", "X-Content-SHA256": secure.Digest(before)}
		exchangeAPIRequest(t, server, "PUT", path, nil, h, before, 403)
	}
	readOnly, _ := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "list"})
	h := map[string]string{"Authorization": "Bearer " + string(readOnly.Bytes), "If-Match": tag, "Idempotency-Key": "dav-replace-read-only", "X-Content-SHA256": secure.Digest(before)}
	exchangeAPIRequest(t, server, "PUT", path, nil, h, before, 403)
	// Equal content under a different custody identity must not satisfy the tag.
	wrong := original.File
	wrong.ID = secure.NewID()
	put(path, "dav-replace-equal-content-wrong-id", artifactRevisionETag(&wrong), before, 412)
	put(prefix+"/dav/missing.dat", "dav-replace-missing", tag, before, 412)
	// Real transactions contend for the same exact old revision. Only one wins.
	type outcome struct {
		status int
		body   []byte
		err    error
	}
	results := make(chan outcome, 2)
	inputs := [][]byte{[]byte("first exact replacement\n"), []byte("second exact replacement\n")}
	for index, input := range inputs {
		go func(index int, input []byte) {
			r, err := http.NewRequestWithContext(t.Context(), "PUT", server.URL+path, bytes.NewReader(input))
			if err != nil {
				results <- outcome{err: err}
				return
			}
			for k, v := range map[string]string{"Authorization": auth["Authorization"], "If-Match": tag, "Idempotency-Key": "dav-replace-race-" + strconv.Itoa(index), "X-Content-SHA256": secure.Digest(input)} {
				r.Header.Set(k, v)
			}
			response, err := server.Client().Do(r)
			if err != nil {
				results <- outcome{err: err}
				return
			}
			defer response.Body.Close()
			var rcp receipt
			if response.StatusCode == 200 {
				err = json.NewDecoder(response.Body).Decode(&rcp)
			}
			results <- outcome{status: response.StatusCode, body: []byte(rcp.File.SHA256), err: err}
		}(index, input)
	}
	winners, refusals := 0, 0
	var winnerHash string
	for range 2 {
		r := <-results
		if r.err != nil {
			t.Fatal("conditional replacement transport failed")
		}
		switch r.status {
		case 200:
			winners++
			winnerHash = string(r.body)
		case 412:
			refusals++
		default:
			t.Fatalf("unexpected replacement race status=%d", r.status)
		}
	}
	if winners != 1 || refusals != 1 {
		t.Fatal("replacement race did not have one exact winner")
	}
	_, readback := exchangeAPIRequest(t, server, "GET", path, nil, auth, nil, 200)
	if secure.Digest(readback) != winnerHash {
		t.Fatal("replacement winner differs from actual namespace bytes")
	}
	current, err := service.StatPath(t.Context(), scope, "/replace.dat")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.PathCommand(t.Context(), scope, "dav-direct-wrong-old-identity", store.PathCommand{Operation: "publish", Path: "/replace.dat", FileID: original.File.ID, Replace: true, ExpectedRevision: &current.Revision, ExpectedFileID: wrong.ID}); !errors.Is(err, store.ErrRevision) {
		t.Fatal("ordinary namespace command ignored exact old identity", err)
	}
	for _, key := range []string{"dav-replace-race-0", "dav-replace-race-1"} {
		put(path, key, tag, inputs[int(key[len(key)-1]-'0')], 412)
	}
	_, oldBytes := exchangeAPIRequest(t, server, "GET", prefix+"/files/"+original.File.ID, nil, auth, nil, 200)
	if !bytes.Equal(oldBytes, before) {
		t.Fatal("replacement destroyed original immutable custody")
	}
	// A held replacement must preserve the old mapping and exact pending guard.
	heldPath := prefix + "/dav/held-replacement.csv"
	base, _ := put(heldPath, "dav-held-base", "*", before, 201)
	positivePath := prefix + "/dav/positive-replacement.csv"
	positiveBase, _ := put(positivePath, "dav-positive-base", "*", before, 201)
	checking := &checks.Service{Custody: service}
	if _, err := checking.Register(t.Context(), scope, "dav-replace-policy", checks.PolicyRequest{Definition: checks.Policy{Schema: 1, Kind: "csv", Columns: []checks.Column{{Name: "record", Type: "text", Required: true}}}}); err != nil {
		t.Fatal(err)
	}
	heldBytes := []byte("record\nnew checked value\n")
	positive, positiveResponse := put(positivePath, "dav-positive-replace", artifactRevisionETag(&positiveBase.File), heldBytes, 202)
	if positiveResponse.Header.Get("ETag") != "" {
		t.Fatal("held positive replacement invented a validator")
	}
	if _, err := checking.Run(t.Context(), scope, positive.File.ID, "dav-positive-check"); err != nil {
		t.Fatal(err)
	}
	positiveCheck, err := checking.Get(t.Context(), scope, positive.File.ID)
	if err != nil || positiveCheck.Check.State != "passed" {
		t.Fatal("positive replacement checks not passed", err)
	}
	if _, err = checking.Release(t.Context(), scope, positive.File.ID, "dav-positive-release", checks.ReleaseDecision{SHA256: positive.File.SHA256, PolicyHash: positiveCheck.Check.PolicyHash, ReportHash: positiveCheck.Check.ReportHash, Revision: positiveCheck.Check.Revision}); err != nil {
		t.Fatal(err)
	}
	_, positiveRead := exchangeAPIRequest(t, server, "GET", positivePath, nil, auth, nil, 200)
	if !bytes.Equal(positiveRead, heldBytes) {
		t.Fatal("separate checked release did not publish exact replacement")
	}
	held, heldResponse := put(heldPath, "dav-held-replace", artifactRevisionETag(&base.File), heldBytes, 202)
	if held.Replayed || held.Namespace != "not-published-at-acceptance" || held.Acceptance != "durable-held-pending-checks-and-release" || heldResponse.Header.Get("ETag") != "" {
		t.Fatal("held replacement invented current publication")
	}
	recovered, recoveredResponse := put(heldPath, "dav-held-replace", artifactRevisionETag(&base.File), heldBytes, 200)
	if !recovered.Replayed || recovered.File.ID != held.File.ID || recovered.Namespace != "not-asserted-original-receipt" || recoveredResponse.Header.Get("ETag") != "" {
		t.Fatal("held retry changed its original receipt")
	}
	_, readback = exchangeAPIRequest(t, server, "GET", heldPath, nil, auth, nil, 200)
	if !bytes.Equal(readback, before) {
		t.Fatal("unreleased replacement changed the namespace")
	}
	if _, err := checking.Run(t.Context(), scope, held.File.ID, "dav-replace-check"); err != nil {
		t.Fatal(err)
	}
	checked, err := checking.Get(t.Context(), scope, held.File.ID)
	if err != nil || checked.Check.State != "passed" {
		t.Fatal("replacement did not pass exact checks", err)
	}
	// Replace the old mapping with a different file while held; even a copied
	// namespace revision must not let the saved pending command overwrite it.
	entry, err := service.StatPath(t.Context(), scope, "/held-replacement.csv")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.PathCommand(t.Context(), scope, "dav-held-remove", store.PathCommand{Operation: "remove", Path: "/held-replacement.csv", ExpectedRevision: &entry.Revision}); err != nil {
		t.Fatal(err)
	}
	if _, err = service.PathCommand(t.Context(), scope, "dav-held-other-publish", store.PathCommand{Operation: "publish", Path: "/held-replacement.csv", FileID: original.File.ID}); err != nil {
		t.Fatal(err)
	}
	changed, err := service.StatPath(t.Context(), scope, "/held-replacement.csv")
	if err != nil || changed.Revision != entry.Revision || changed.FileID == base.File.ID {
		t.Fatal("fixture did not reproduce equal namespace revision under another file identity", err)
	}
	if _, err = checking.Release(t.Context(), scope, held.File.ID, "dav-replace-stale-release", checks.ReleaseDecision{SHA256: held.File.SHA256, PolicyHash: checked.Check.PolicyHash, ReportHash: checked.Check.ReportHash, Revision: checked.Check.Revision}); !errors.Is(err, store.ErrRevision) {
		t.Fatal("changed mapping accepted stale held replacement", err)
	}
	_, readback = exchangeAPIRequest(t, server, "GET", heldPath, nil, auth, nil, 200)
	if !bytes.Equal(readback, before) {
		t.Fatal("failed stale release changed current bytes")
	}
	policy, err := checking.Policy(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = checking.Revoke(t.Context(), scope, "dav-replace-policy-revoke", checks.PolicyDecision{Hash: policy.Hash, Version: policy.Version, Revision: policy.Revision}); err != nil {
		t.Fatal(err)
	}
	put(positivePath, "dav-replace-stale-current-policy", artifactRevisionETag(&positive.File), heldBytes, 409)
	tx, err := service.DB.Begin(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Tx.Rollback(t.Context())
	var files, publications, intents, runs int
	if err = tx.Tx.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM files),(SELECT count(*) FROM events WHERE kind='PathPublished'),(SELECT count(*) FROM delivery_intents),(SELECT count(*) FROM workflow_runs)`).Scan(&files, &publications, &intents, &runs); err != nil || files != 6 || publications != 6 || intents != 0 || runs != 0 {
		t.Fatalf("replacement lost exact custody/publication or gained effects;files=%d;publications=%d;intents=%d;runs=%d;error=%v", files, publications, intents, runs, err)
	}
}
