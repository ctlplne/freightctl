//go:build integration

package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/freightctl/internal/checks"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestWebDAVFileCopyRequiresReadWriteVerifiedCustodyAndIndependentMappings(t *testing.T) {
	service, scope, admin, server := browserAPI(t, time.Minute)
	cookie, csrf := loginBrowser(t, server, scope, admin)
	prefix := "/v1/tenants/" + scope.Tenant + "/partners/" + scope.Partner
	create := func(key, path string, data []byte) store.File {
		t.Helper()
		_, raw := exchangeAPIRequest(t, server, "PUT", prefix+"/namespace/file?path="+url.QueryEscape(path), nil, map[string]string{"Authorization": "Bearer " + string(admin.Bytes), "Idempotency-Key": key, "X-File-Size": strconv.Itoa(len(data)), "X-Content-SHA256": secure.Digest(data)}, data, 201)
		var accepted struct {
			File store.File `json:"file"`
		}
		if json.Unmarshal(raw, &accepted) != nil || accepted.File.SHA256 != secure.Digest(data) {
			t.Fatal("ordinary copy source differs")
		}
		return accepted.File
	}
	data := []byte("independent virtual resources;one immutable custody revision\n")
	file := create("dav-copy-source", "/source.dat", data)
	create("dav-copy-existing", "/existing.dat", []byte("existing destination survives"))
	operator, participant := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "list", "write"})
	reader, _ := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "list"})
	manager, _ := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "list", "manage_paths"})
	writer, _ := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"write", "list"})
	operatorHeaders := map[string]string{"Authorization": "Bearer " + string(operator.Bytes)}
	source, target := prefix+"/dav/source.dat", prefix+"/dav/copied.dat"
	response, body := exchangeAPIRequest(t, server, "GET", source, nil, operatorHeaders, nil, 200)
	tag := response.Header.Get("ETag")
	if !bytes.Equal(body, data) || tag != artifactRevisionETag(&file) {
		t.Fatal("copy source review differs")
	}
	entry, err := service.StatPath(t.Context(), scope, "/source.dat")
	if err != nil {
		t.Fatal(err)
	}
	headers := func(key, revision, destination string, token *secure.Secret) map[string]string {
		return map[string]string{"Authorization": "Bearer " + string(token.Bytes), "Idempotency-Key": key, "If-Match": revision, "Overwrite": "F", "Destination": destination}
	}
	for _, credential := range []*secure.Secret{reader, manager, writer} {
		exchangeAPIRequest(t, server, "COPY", source, nil, headers("dav-copy-denied", tag, target, credential), nil, 403)
	}
	operatorScope := store.Scope{Tenant: scope.Tenant, Partner: scope.Partner, TokenHash: secure.Digest(operator.Bytes)}
	limited := &custody.Service{DB: service.DB, Disk: service.Disk, NamespaceMaxEntries: 1}
	if _, err := limited.CopyFileIfCurrent(t.Context(), operatorScope, "dav-copy-limited", "/source.dat", "/limited.dat", file.ID, file.SHA256); !errors.Is(err, store.ErrLimit) {
		t.Fatal("copy bypassed ordinary namespace capacity", err)
	}
	missingDisk := &custody.Service{DB: service.DB, NamespaceMaxEntries: 1000}
	if _, err := missingDisk.CopyFileIfCurrent(t.Context(), operatorScope, "dav-copy-no-verification", "/source.dat", "/unverified.dat", file.ID, file.SHA256); !errors.Is(err, store.ErrState) {
		t.Fatal("copy published without custody verification", err)
	}
	exchangeAPIRequest(t, server, "COPY", source, nil, headers("dav-copy-existing-refused", tag, prefix+"/dav/existing.dat", operator), nil, 412)
	exchangeAPIRequest(t, server, "COPY", source, nil, headers("dav-copy-parent-refused", tag, prefix+"/dav/missing/file.dat", operator), nil, 409)
	command := headers("dav-copy-original", tag, server.URL+target, operator)
	response, raw := exchangeAPIRequest(t, server, "COPY", source, nil, command, nil, 201)
	var copied struct {
		Result    store.PathResult `json:"result"`
		Namespace string           `json:"namespace_state"`
	}
	if json.Unmarshal(raw, &copied) != nil || copied.Result.Replayed || copied.Result.Entry.ID == entry.ID || copied.Result.Entry.FileID != file.ID || copied.Result.Entry.Owner != participant.Actor || copied.Result.Entry.Mode != 0640 || copied.Namespace != "copied-at-commit" || response.Header.Get("Location") != target {
		t.Fatal("copy lost independent mapping,ordinary ownership or exact immutable custody")
	}
	for _, path := range []string{source, target} {
		response, body = exchangeAPIRequest(t, server, "GET", path, nil, operatorHeaders, nil, 200)
		if !bytes.Equal(body, data) || response.Header.Get("ETag") != tag || response.Header.Get("X-File-Revision-ID") != file.ID {
			t.Fatal("independent source/destination readback differs")
		}
	}
	exchangeAPIRequest(t, server, "COPY", source, nil, headers("dav-copy-another-key", tag, target, operator), nil, 412)
	exchangeAPIRequest(t, server, "COPY", source, nil, command, nil, 412)
	if _, err := service.PathCommand(t.Context(), scope, "dav-copy-remove-target", store.PathCommand{Operation: "remove", Path: "/copied.dat", ExpectedRevision: &copied.Result.Entry.Revision}); err != nil {
		t.Fatal(err)
	}
	response, raw = exchangeAPIRequest(t, server, "COPY", source, nil, command, nil, 200)
	if json.Unmarshal(raw, &copied) != nil || !copied.Result.Replayed || copied.Namespace != "not-asserted-original-receipt" || response.Header.Get("Location") != "" {
		t.Fatal("historical copy receipt asserted a new mapping")
	}
	exchangeAPIRequest(t, server, "GET", target, nil, operatorHeaders, nil, 404)
	// The ordinary typed API (also used by the namespace JSON CLI) uses the
	// same read/write,verified bytes,source revision and publication transaction.
	typedHeaders := map[string]string{"Authorization": "Bearer " + string(operator.Bytes), "Idempotency-Key": "typed-copy-independent", "Content-Type": "application/json"}
	typed := store.PathCommand{Operation: "copy", Path: "/source.dat", Target: "/independent.dat", FileID: file.ID, ExpectedRevision: &entry.Revision}
	_, raw = exchangeAPIRequest(t, server, "POST", prefix+"/namespace/commands", nil, typedHeaders, exchangeAPIJSON(t, typed), 200)
	var independent store.PathResult
	if json.Unmarshal(raw, &independent) != nil || independent.Replayed || independent.Entry.FileID != file.ID || independent.Entry.ID == entry.ID {
		t.Fatal("typed copy lost its distinct mapping")
	}
	mode := uint32(0000)
	private, err := service.PathCommand(t.Context(), scope, "dav-copy-source-private", store.PathCommand{Operation: "setstat", Path: "/source.dat", ExpectedRevision: &entry.Revision, Mode: &mode})
	if err != nil {
		t.Fatal(err)
	}
	wrongRevision := int64(999)
	typed.Target, typed.ExpectedRevision = "/unreadable-copy.dat", &wrongRevision
	typedHeaders["Idempotency-Key"] = "typed-copy-unreadable"
	// The file remains readable through independent.dat. That does not grant
	// authority for the declared private source or reveal its revision condition.
	exchangeAPIRequest(t, server, "POST", prefix+"/namespace/commands", nil, typedHeaders, exchangeAPIJSON(t, typed), 403)
	exchangeAPIRequest(t, server, "COPY", source, nil, headers("dav-copy-private", tag, prefix+"/dav/private-copy.dat", operator), nil, 403)
	mode = 0640
	restored, err := service.PathCommand(t.Context(), scope, "dav-copy-source-mode-restore", store.PathCommand{Operation: "setstat", Path: "/source.dat", ExpectedRevision: &private.Entry.Revision, Mode: &mode})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.PathCommand(t.Context(), scope, "dav-copy-source-replace", store.PathCommand{Operation: "remove", Path: "/source.dat", ExpectedRevision: &restored.Entry.Revision}); err != nil {
		t.Fatal(err)
	}
	replacement := create("dav-copy-new-source", "/source.dat", data)
	if replacement.ID == file.ID || replacement.SHA256 != file.SHA256 {
		t.Fatal("replacement is not an equal-content distinct revision")
	}
	exchangeAPIRequest(t, server, "COPY", source, nil, command, nil, 412)
	exchangeAPIRequest(t, server, "COPY", source, nil, headers("dav-copy-original", artifactRevisionETag(&replacement), target, operator), nil, 409)
	response, body = exchangeAPIRequest(t, server, "GET", prefix+"/dav/independent.dat", nil, operatorHeaders, nil, 200)
	if !bytes.Equal(body, data) || response.Header.Get("X-File-Revision-ID") != file.ID {
		t.Fatal("source replacement changed the copied resource")
	}
	if _, err := service.PathCommand(t.Context(), scope, "dav-copy-dir", store.PathCommand{Operation: "mkdir", Path: "/directory"}); err != nil {
		t.Fatal(err)
	}
	response, _ = exchangeAPIRequest(t, server, "COPY", prefix+"/dav/directory", nil, headers("dav-copy-dir-refused", tag, prefix+"/dav/another-dir", operator), nil, 405)
	if !strings.Contains(response.Header.Get("Allow"), "MOVE") {
		t.Fatal("declared namespace-conditioned collection MOVE missing")
	}
	for _, method := range []string{"COPY", "DELETE"} {
		if !strings.Contains(response.Header.Get("Allow"), method) {
			t.Fatal("directory lost its namespace-conditioned collection mutation")
		}
	}
	checking := &checks.Service{Custody: service}
	if _, err := checking.Register(t.Context(), scope, "dav-copy-policy", checks.PolicyRequest{Definition: checks.Policy{Schema: 1, Kind: "csv", Columns: []checks.Column{{Name: "record", Type: "text", Required: true}}}}); err != nil {
		t.Fatal(err)
	}
	controlled := create("dav-copy-controlled", "/controlled.csv", []byte("record\nreleased then revoked\n"))
	if _, err := checking.Run(t.Context(), scope, controlled.ID, "dav-copy-check"); err != nil {
		t.Fatal(err)
	}
	checked, err := checking.Get(t.Context(), scope, controlled.ID)
	if err != nil || checked.Check.State != "passed" {
		t.Fatal("controlled copy fixture not passed", err)
	}
	if _, err = checking.Release(t.Context(), scope, controlled.ID, "dav-copy-release", checks.ReleaseDecision{SHA256: controlled.SHA256, PolicyHash: checked.Check.PolicyHash, ReportHash: checked.Check.ReportHash, Revision: checked.Check.Revision}); err != nil {
		t.Fatal(err)
	}
	policy, err := checking.Policy(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = checking.Revoke(t.Context(), scope, "dav-copy-revoke", checks.PolicyDecision{Hash: policy.Hash, Version: policy.Version, Revision: policy.Revision}); err != nil {
		t.Fatal(err)
	}
	exchangeAPIRequest(t, server, "COPY", prefix+"/dav/controlled.csv", nil, headers("dav-copy-revoked", artifactRevisionETag(&controlled), prefix+"/dav/copied-controlled.csv", operator), nil, 409)
	visibility, err := service.DB.Begin(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	var foreignCommands, adminIntents, adminRuns int
	if err = visibility.Tx.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM namespace_commands WHERE actor_id=$1 AND request_key='dav-copy-original'),(SELECT count(*) FROM delivery_intents),(SELECT count(*) FROM workflow_runs)`, participant.Actor).Scan(&foreignCommands, &adminIntents, &adminRuns); err != nil || foreignCommands != 0 || adminIntents != 0 || adminRuns != 0 {
		visibility.Tx.Rollback(t.Context())
		t.Fatalf("administrator scope lost receipt privacy or gained effects;receipts=%d;intents=%d;runs=%d;error=%v", foreignCommands, adminIntents, adminRuns, err)
	}
	if err = visibility.Tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	tx, err := service.DB.Begin(t.Context(), operatorScope)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Tx.Rollback(t.Context())
	var publications, commands, accepted, intents, runs int
	if err = tx.Tx.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM events WHERE kind='PathPublished' AND actor_id=$1),(SELECT count(*) FROM namespace_commands WHERE actor_id=$1 AND request_key='dav-copy-original'),(SELECT count(*) FROM events WHERE kind='FileAccepted' AND actor_id=$1),(SELECT count(*) FROM delivery_intents),(SELECT count(*) FROM workflow_runs)`, participant.Actor).Scan(&publications, &commands, &accepted, &intents, &runs); err != nil || publications != 2 || commands != 1 || accepted != 0 || intents != 0 || runs != 0 {
		t.Fatalf("copy lost exact actor-bound evidence or gained effects;publications=%d;receipts=%d;acceptances=%d;intents=%d;runs=%d;error=%v", publications, commands, accepted, intents, runs, err)
	}
}
