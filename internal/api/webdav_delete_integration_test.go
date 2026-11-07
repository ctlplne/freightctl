//go:build integration

package api

import (
	"bytes"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/freightctl/internal/checks"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestWebDAVFileDeletePinsAuthorityRevisionHistoryAndCurrentIntake(t *testing.T) {
	service, scope, admin, server := browserAPI(t, time.Minute)
	cookie, csrf := loginBrowser(t, server, scope, admin)
	prefix := "/v1/tenants/" + scope.Tenant + "/partners/" + scope.Partner
	adminHeaders := map[string]string{"Authorization": "Bearer " + string(admin.Bytes)}
	create := func(key, path string, data []byte) store.File {
		t.Helper()
		_, raw := exchangeAPIRequest(t, server, "PUT", prefix+"/namespace/file?path="+url.QueryEscape(path), nil, map[string]string{"Authorization": "Bearer " + string(admin.Bytes), "Idempotency-Key": key, "X-File-Size": strconv.Itoa(len(data)), "X-Content-SHA256": secure.Digest(data)}, data, 201)
		var accepted struct {
			File store.File `json:"file"`
		}
		if json.Unmarshal(raw, &accepted) != nil || accepted.File.SHA256 != secure.Digest(data) {
			t.Fatal("ordinary deletion fixture acceptance differs")
		}
		return accepted.File
	}
	data := []byte("immutable custody survives removal of its virtual mapping\n")
	file := create("dav-delete-source", "/remove.dat", data)
	operator, participant := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "list", "manage_paths"})
	reader, _ := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "list"})
	manager, _ := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"list", "manage_paths"})
	operatorHeaders := map[string]string{"Authorization": "Bearer " + string(operator.Bytes)}
	source := prefix + "/dav/remove.dat"
	response, body := exchangeAPIRequest(t, server, "GET", source, nil, operatorHeaders, nil, 200)
	tag := response.Header.Get("ETag")
	if !bytes.Equal(body, data) || tag != artifactRevisionETag(&file) {
		t.Fatal("removal operator did not review the exact current file")
	}
	headers := func(key, revision string, credential *secure.Secret) map[string]string {
		return map[string]string{"Authorization": "Bearer " + string(credential.Bytes), "Idempotency-Key": key, "If-Match": revision}
	}
	for _, credential := range []*secure.Secret{reader, manager} {
		exchangeAPIRequest(t, server, "DELETE", source, nil, headers("dav-delete-denied", tag, credential), nil, 403)
	}
	wrong := file
	wrong.ID = secure.NewID()
	exchangeAPIRequest(t, server, "DELETE", source, nil, headers("dav-delete-stale", artifactRevisionETag(&wrong), operator), nil, 412)
	command := headers("dav-delete-original", tag, operator)
	response, raw := exchangeAPIRequest(t, server, "DELETE", source, nil, command, nil, 204)
	if len(raw) != 0 || response.Header.Get("X-Freightctl-Namespace-State") != "removed-at-commit" || !store.ValidID(response.Header.Get("X-Freightctl-Event-ID")) || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("ETag") != "" || response.Header.Get("X-File-Revision-ID") != "" {
		t.Fatal("removal response invented byte publication or lost its exact outcome")
	}
	for _, method := range []string{"GET", "HEAD", "PROPFIND"} {
		exchangeAPIRequest(t, server, method, source, nil, operatorHeaders, nil, 404)
	}
	_, body = exchangeAPIRequest(t, server, "GET", prefix+"/files/"+file.ID, nil, adminHeaders, nil, 200)
	if !bytes.Equal(body, data) {
		t.Fatal("removing the mapping destroyed immutable custody bytes")
	}
	denied, deniedBody := exchangeAPIRequest(t, server, "GET", prefix+"/files/"+file.ID, nil, operatorHeaders, nil, 404)
	unknown, unknownBody := exchangeAPIRequest(t, server, "GET", prefix+"/files/"+secure.NewID(), nil, operatorHeaders, nil, 404)
	if !bytes.Equal(deniedBody, unknownBody) || denied.Header.Get("ETag") != "" || denied.Header.Get("X-File-Revision-ID") != "" || unknown.Header.Get("ETag") != "" || unknown.Header.Get("X-File-Revision-ID") != "" {
		t.Fatal("inaccessible retained custody differs from an unknown file or reveals byte metadata")
	}
	exchangeAPIRequest(t, server, "DELETE", source, nil, command, nil, 412)
	replacement := create("dav-delete-replacement", "/remove.dat", data)
	if replacement.ID == file.ID || replacement.SHA256 != file.SHA256 {
		t.Fatal("equal-content replacement is not a distinct immutable revision")
	}
	exchangeAPIRequest(t, server, "DELETE", source, nil, command, nil, 412)
	exchangeAPIRequest(t, server, "DELETE", source, nil, headers("dav-delete-original", artifactRevisionETag(&replacement), operator), nil, 409)
	response, _ = exchangeAPIRequest(t, server, "HEAD", source, nil, operatorHeaders, nil, 200)
	if response.Header.Get("X-File-Revision-ID") != replacement.ID {
		t.Fatal("stale conditions or reused command key removed the replacement")
	}
	// Restoring the original immutable file under a fresh ordinary mapping
	// does not let its historical deletion key remove that mapping again.
	_, raw = exchangeAPIRequest(t, server, "GET", prefix+"/namespace/stat?path=/remove.dat", nil, adminHeaders, nil, 200)
	var entry store.PathEntry
	if json.Unmarshal(raw, &entry) != nil {
		t.Fatal("replacement mapping unavailable")
	}
	if _, err := service.PathCommand(t.Context(), scope, "dav-delete-restore-remove", store.PathCommand{Operation: "remove", Path: "/remove.dat", ExpectedRevision: &entry.Revision}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.PathCommand(t.Context(), scope, "dav-delete-restore-publish", store.PathCommand{Operation: "publish", Path: "/remove.dat", FileID: file.ID}); err != nil {
		t.Fatal(err)
	}
	response, raw = exchangeAPIRequest(t, server, "DELETE", source, nil, command, nil, 200)
	var historical struct {
		Result    store.PathResult `json:"result"`
		Namespace string           `json:"namespace_state"`
	}
	if json.Unmarshal(raw, &historical) != nil || !historical.Result.Replayed || historical.Namespace != "not-asserted-original-receipt" || response.Header.Get("X-Freightctl-Namespace-State") != "" {
		t.Fatal("historical receipt asserted a new removal")
	}
	_, body = exchangeAPIRequest(t, server, "GET", source, nil, operatorHeaders, nil, 200)
	if !bytes.Equal(body, data) {
		t.Fatal("original-key recovery removed the restored mapping")
	}
	if _, err := service.PathCommand(t.Context(), scope, "dav-delete-directory", store.PathCommand{Operation: "mkdir", Path: "/directory"}); err != nil {
		t.Fatal(err)
	}
	response, _ = exchangeAPIRequest(t, server, "DELETE", prefix+"/dav/directory", nil, headers("dav-delete-dir-refused", tag, operator), nil, 405)
	if strings.Contains(response.Header.Get("Allow"), "DELETE") || strings.Contains(response.Header.Get("Allow"), "MOVE") {
		t.Fatal("file-only profile advertised a directory mutation")
	}
	checking := &checks.Service{Custody: service}
	if _, err := checking.Register(t.Context(), scope, "dav-delete-policy", checks.PolicyRequest{Definition: checks.Policy{Schema: 1, Kind: "csv", Columns: []checks.Column{{Name: "record", Type: "text", Required: true}}}}); err != nil {
		t.Fatal(err)
	}
	controlled := create("dav-delete-controlled", "/controlled.csv", []byte("record\nreleased then revoked\n"))
	if _, err := checking.Run(t.Context(), scope, controlled.ID, "dav-delete-check"); err != nil {
		t.Fatal(err)
	}
	checked, err := checking.Get(t.Context(), scope, controlled.ID)
	if err != nil || checked.Check.State != "passed" {
		t.Fatal("controlled removal fixture did not pass checks", err)
	}
	if _, err = checking.Release(t.Context(), scope, controlled.ID, "dav-delete-release", checks.ReleaseDecision{SHA256: controlled.SHA256, PolicyHash: checked.Check.PolicyHash, ReportHash: checked.Check.ReportHash, Revision: checked.Check.Revision}); err != nil {
		t.Fatal(err)
	}
	policy, err := checking.Policy(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = checking.Revoke(t.Context(), scope, "dav-delete-revoke", checks.PolicyDecision{Hash: policy.Hash, Version: policy.Version, Revision: policy.Revision}); err != nil {
		t.Fatal(err)
	}
	exchangeAPIRequest(t, server, "DELETE", prefix+"/dav/controlled.csv", nil, headers("dav-delete-revoked", artifactRevisionETag(&controlled), operator), nil, 409)
	visibility, err := service.DB.Begin(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	var foreignCommands, adminIntents, adminRuns int
	if err = visibility.Tx.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM namespace_commands WHERE actor_id=$1 AND request_key='dav-delete-original'),(SELECT count(*) FROM delivery_intents),(SELECT count(*) FROM workflow_runs)`, participant.Actor).Scan(&foreignCommands, &adminIntents, &adminRuns); err != nil || foreignCommands != 0 || adminIntents != 0 || adminRuns != 0 {
		visibility.Tx.Rollback(t.Context())
		t.Fatalf("administrator scope lost receipt privacy or gained effects;receipts=%d;intents=%d;runs=%d;error=%v", foreignCommands, adminIntents, adminRuns, err)
	}
	if err = visibility.Tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	operatorScope := store.Scope{Tenant: scope.Tenant, Partner: scope.Partner, TokenHash: secure.Digest(operator.Bytes)}
	tx, err := service.DB.Begin(t.Context(), operatorScope)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Tx.Rollback(t.Context())
	var removed, commands, intents, runs int
	if err = tx.Tx.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM events WHERE kind='PathRemoved' AND actor_id=$1),(SELECT count(*) FROM namespace_commands WHERE actor_id=$1 AND request_key='dav-delete-original'),(SELECT count(*) FROM delivery_intents),(SELECT count(*) FROM workflow_runs)`, participant.Actor).Scan(&removed, &commands, &intents, &runs); err != nil || removed != 1 || commands != 1 || intents != 0 || runs != 0 {
		t.Fatalf("removal lost exact actor-bound evidence or gained effects;removed=%d;receipts=%d;intents=%d;runs=%d;error=%v", removed, commands, intents, runs, err)
	}
}
