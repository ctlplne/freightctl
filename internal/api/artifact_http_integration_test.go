//go:build integration

package api

import (
	"bytes"
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/ctlplne/freightctl/internal/checks"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestArtifactHTTPNamespaceValidatorReplacementAndCurrentIntake(t *testing.T) {
	service, scope, admin, server := browserAPI(t, time.Minute)
	cookie, csrf := loginBrowser(t, server, scope, admin)
	prefix := "/v1/tenants/" + scope.Tenant + "/partners/" + scope.Partner
	data := []byte("first immutable namespace revision")
	headers := map[string]string{"Authorization": "Bearer " + string(admin.Bytes), "Idempotency-Key": "validator-source", "X-File-Size": strconv.Itoa(len(data)), "X-Content-SHA256": secure.Digest(data)}
	path := prefix + "/namespace/file?path=/validator.dat"
	_, raw := exchangeAPIRequest(t, server, "PUT", path, nil, headers, data, 201)
	var accepted struct {
		File store.File `json:"file"`
	}
	if json.Unmarshal(raw, &accepted) != nil || accepted.File.SHA256 != secure.Digest(data) {
		t.Fatal("ordinary namespace acceptance differs")
	}
	_, raw = exchangeAPIRequest(t, server, "GET", prefix+"/namespace/stat?path=/validator.dat", cookie, nil, nil, 200)
	var entry store.PathEntry
	if json.Unmarshal(raw, &entry) != nil || entry.FileID != accepted.File.ID {
		t.Fatal("ordinary exact replacement revision missing")
	}
	// The default published0640 mode grants partner-group read. Make this
	// negative-authority fixture owner-only through the ordinary versioned API;
	// an explicitly authorized group reader must not be called unauthorized.
	privateMode := uint32(0600)
	previousRevision := entry.Revision
	exchangeAPIRequest(t, server, "POST", prefix+"/namespace/commands", cookie, map[string]string{"Origin": server.URL, "X-CSRF-Token": csrf, "Idempotency-Key": "validator-owner-only"}, exchangeAPIJSON(t, store.PathCommand{Operation: "setstat", Path: "/validator.dat", ExpectedRevision: &entry.Revision, Mode: &privateMode}), 200)
	_, raw = exchangeAPIRequest(t, server, "GET", prefix+"/namespace/stat?path=/validator.dat", cookie, nil, nil, 200)
	if json.Unmarshal(raw, &entry) != nil || entry.FileID != accepted.File.ID || entry.Mode != privateMode || entry.Revision != previousRevision+1 {
		t.Fatal("owner-only fixture was not recorded")
	}
	var etag string
	for _, target := range []string{path, prefix + "/files/" + accepted.File.ID} {
		response, head := exchangeAPIRequest(t, server, "HEAD", target, cookie, nil, nil, 200)
		if len(head) != 0 || response.Header.Get("ETag") == "" || response.Header.Get("Content-Length") != strconv.Itoa(len(data)) || response.Header.Get("X-File-Revision-ID") != accepted.File.ID {
			t.Fatal("authorized HEAD did not bind exact immutable bytes")
		}
		if etag != "" && etag != response.Header.Get("ETag") {
			t.Fatal("path/file views differ for the same immutable revision")
		}
		etag = response.Header.Get("ETag")
		response, partial := exchangeAPIRequest(t, server, "GET", target, nil, map[string]string{"Authorization": headers["Authorization"], "Range": "bytes=6-", "If-Range": etag}, nil, 206)
		if !bytes.Equal(partial, data[6:]) || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("ordinary exact validator changed resumed bytes")
		}
		response, _ = exchangeAPIRequest(t, server, "GET", target, cookie, map[string]string{"Range": "bytes=999999-"}, nil, 416)
		if response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("actual range refusal lost private cache policy")
		}
	}
	other, _ := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "list"})
	response, _ := exchangeAPIRequest(t, server, "GET", prefix+"/files/"+accepted.File.ID, cookie, map[string]string{"Authorization": "Bearer " + string(other.Bytes), "If-None-Match": etag, "If-Range": etag, "Range": "bytes=6-"}, nil, 404)
	if response.Header.Get("ETag") != "" {
		t.Fatal("validator or cookie rescued unauthorized explicit bearer")
	}
	changed := []byte("second immutable namespace revision")
	headers["If-Match-Revision"] = strconv.FormatInt(entry.Revision, 10)
	headers["Idempotency-Key"] = "validator-replacement"
	headers["X-File-Size"] = strconv.Itoa(len(changed))
	headers["X-Content-SHA256"] = secure.Digest(changed)
	exchangeAPIRequest(t, server, "PUT", path, nil, headers, changed, 201)
	response, full := exchangeAPIRequest(t, server, "GET", path, cookie, map[string]string{"Range": "bytes=6-", "If-Range": etag}, nil, 200)
	if !bytes.Equal(full, changed) || response.Header.Get("ETag") == etag || response.Header.Get("Content-Range") != "" {
		t.Fatal("replaced namespace path permitted mixed revision resume")
	}
	checking := &checks.Service{Custody: service}
	registered, err := checking.Register(t.Context(), scope, "validator-current-intake", checks.PolicyRequest{Definition: checks.Policy{Schema: 1, Kind: "csv", Columns: []checks.Column{{Name: "record", Type: "text", Required: true}}}})
	if err != nil {
		t.Fatal(err)
	}
	var policy store.Configuration
	if json.Unmarshal(registered.Resource, &policy) != nil {
		t.Fatal("controlled policy receipt")
	}
	// Policy registration does not retroactively change integrity-only receipts.
	// Publish an actually checked/released revision, then revoke its exact policy.
	_, raw = exchangeAPIRequest(t, server, "GET", prefix+"/namespace/stat?path=/validator.dat", cookie, nil, nil, 200)
	if json.Unmarshal(raw, &entry) != nil {
		t.Fatal("current replacement revision")
	}
	controlledBytes := []byte("record\nreleased controlled revision\n")
	headers["If-Match-Revision"] = strconv.FormatInt(entry.Revision, 10)
	headers["Idempotency-Key"] = "validator-controlled-replacement"
	headers["X-File-Size"] = strconv.Itoa(len(controlledBytes))
	headers["X-Content-SHA256"] = secure.Digest(controlledBytes)
	_, raw = exchangeAPIRequest(t, server, "PUT", path, nil, headers, controlledBytes, 201)
	var controlled struct {
		File store.File `json:"file"`
	}
	if json.Unmarshal(raw, &controlled) != nil || controlled.File.ID == accepted.File.ID || controlled.File.Policy != "intake-csv-v1:"+policy.Hash {
		t.Fatal("controlled revision did not bind exact intake")
	}
	if _, err = checking.Run(t.Context(), scope, controlled.File.ID, "validator-controlled-check"); err != nil {
		t.Fatal(err)
	}
	checked, err := checking.Get(t.Context(), scope, controlled.File.ID)
	if err != nil || checked.Check.State != "passed" {
		t.Fatal("controlled revision did not pass checks", err)
	}
	if _, err = checking.Release(t.Context(), scope, controlled.File.ID, "validator-controlled-release", checks.ReleaseDecision{SHA256: controlled.File.SHA256, PolicyHash: checked.Check.PolicyHash, ReportHash: checked.Check.ReportHash, Revision: checked.Check.Revision}); err != nil {
		t.Fatal(err)
	}
	response, full = exchangeAPIRequest(t, server, "GET", path, cookie, nil, nil, 200)
	current := response.Header.Get("ETag")
	if current == "" || !bytes.Equal(full, controlledBytes) || response.Header.Get("X-File-Revision-ID") != controlled.File.ID {
		t.Fatal("released validator did not bind the controlled revision")
	}
	if _, err = checking.Revoke(t.Context(), scope, "validator-revoke-exact-policy", checks.PolicyDecision{Hash: policy.Hash, Version: policy.Version, Revision: policy.Revision}); err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{"GET", "HEAD"} {
		response, _ := exchangeAPIRequest(t, server, method, path, cookie, map[string]string{"Range": "bytes=6-", "If-Range": current, "If-None-Match": current}, nil, 409)
		if response.Header.Get("ETag") != "" || response.Header.Get("Content-Range") != "" {
			t.Fatal("validator bypassed current intake authority")
		}
	}
}
