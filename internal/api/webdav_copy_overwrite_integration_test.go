//go:build integration

package api

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/ctlplne/freightctl/internal/checks"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestWebDAVFileCopyOverwriteRequiresManagementVerifiedBytesAndAtomicCapacity(t *testing.T) {
	service, scope, admin, server := browserAPI(t, time.Minute)
	cookie, csrf := loginBrowser(t, server, scope, admin)
	prefix := "/v1/tenants/" + scope.Tenant + "/partners/" + scope.Partner
	create := func(key, path string, data []byte) store.File {
		t.Helper()
		file, _, err := service.AcceptAt(t.Context(), scope, key, int64(len(data)), secure.Digest(data), bytes.NewReader(data), custody.UploadTarget{Path: path})
		if err != nil {
			t.Fatal(err)
		}
		return *file
	}
	sourceBytes := []byte("verified immutable source for explicit copy replacement\n")
	previousBytes := []byte("original independently retained copy target\n")
	source := create("copy-overwrite-source", "/copy-source.dat", sourceBytes)
	previous := create("copy-overwrite-previous", "/copy-previous.dat", previousBytes)
	manager, identity := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "write", "list", "manage_paths"})
	managerScope := store.Scope{Tenant: scope.Tenant, Partner: scope.Partner, TokenHash: secure.Digest(manager.Bytes)}
	seed, err := service.PathCommand(t.Context(), managerScope, "copy-overwrite-own-target", store.PathCommand{Operation: "publish", Path: "/copy-target.dat", FileID: previous.ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.PathCommand(t.Context(), managerScope, "copy-overwrite-own-dir", store.PathCommand{Operation: "mkdir", Path: "/copy-directory"}); err != nil {
		t.Fatal(err)
	}
	headers := func(key, target, mode string, credential *secure.Secret) map[string]string {
		return map[string]string{"Authorization": "Bearer " + string(credential.Bytes), "If-Match": artifactRevisionETag(&source), "Destination": prefix + "/dav" + target, "Overwrite": mode, "Idempotency-Key": key}
	}
	path := prefix + "/dav/copy-source.dat"
	for _, permissions := range [][]string{{"read", "write", "list"}, {"read", "manage_paths", "list"}, {"write", "manage_paths", "list"}, {"read", "list"}} {
		credential, _ := exchangeAPIParticipant(t, server, prefix, cookie, csrf, permissions)
		exchangeAPIRequest(t, server, "COPY", path, nil, headers("copy-overwrite-role-denied", "/copy-target.dat", "T", credential), nil, 403)
	}
	exchangeAPIRequest(t, server, "COPY", path, nil, headers("copy-overwrite-mode-denied", "/copy-previous.dat", "T", manager), nil, 403)
	exchangeAPIRequest(t, server, "COPY", path, nil, headers("copy-overwrite-dir-denied", "/copy-directory", "T", manager), nil, 405)
	exchangeAPIRequest(t, server, "COPY", path, nil, headers("copy-overwrite-false", "/copy-target.dat", "F", manager), nil, 412)
	// Failed verification and a post-removal quota failure must leave the exact
	// old target intact. No receipt or partial mapping is committed.
	disk := service.Disk
	service.Disk = nil
	t.Cleanup(func() { service.Disk = disk })
	exchangeAPIRequest(t, server, "COPY", path, nil, headers("copy-overwrite-no-verification", "/copy-target.dat", "T", manager), nil, 409)
	service.Disk = disk
	limit := service.NamespaceMaxEntries
	t.Cleanup(func() { service.NamespaceMaxEntries = limit })
	service.NamespaceMaxEntries = 1
	exchangeAPIRequest(t, server, "COPY", path, nil, headers("copy-overwrite-capacity", "/copy-target.dat", "T", manager), nil, 507)
	service.NamespaceMaxEntries = limit
	managerAuth := map[string]string{"Authorization": "Bearer " + string(manager.Bytes)}
	response, body := exchangeAPIRequest(t, server, "GET", prefix+"/dav/copy-target.dat", nil, managerAuth, nil, 200)
	if !bytes.Equal(body, previousBytes) || response.Header.Get("X-File-Revision-ID") != previous.ID {
		t.Fatal("refused copy replacement changed old target")
	}
	tx, err := service.DB.Begin(t.Context(), managerScope)
	if err != nil {
		t.Fatal(err)
	}
	var entries int
	if err = tx.Tx.QueryRow(t.Context(), `SELECT count(*) FROM namespace_entries WHERE NOT deleted`).Scan(&entries); err != nil {
		t.Fatal(err)
	}
	if err = tx.Tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	service.NamespaceMaxEntries = entries
	command := headers("copy-overwrite-commit", "/copy-target.dat", "T", manager)
	response, body = exchangeAPIRequest(t, server, "COPY", path, nil, command, nil, 204)
	service.NamespaceMaxEntries = limit
	if len(body) != 0 || response.Header.Get("X-Freightctl-Namespace-State") != "replaced-at-commit" || !store.ValidID(response.Header.Get("X-Freightctl-Event-ID")) || response.Header.Get("ETag") != "" || response.Header.Get("Location") != "" {
		t.Fatal("copy replacement lost exact atomic namespace receipt")
	}
	target, err := service.StatPath(t.Context(), managerScope, "/copy-target.dat")
	if err != nil || target.ID == seed.Entry.ID || target.FileID != source.ID || target.Owner != identity.Actor || target.Mode != 0640 || target.Revision != 1 {
		t.Fatal("copy replacement did not create an independently owned mapping", err)
	}
	for _, name := range []string{"/copy-source.dat", "/copy-target.dat"} {
		response, body = exchangeAPIRequest(t, server, "GET", prefix+"/dav"+name, nil, managerAuth, nil, 200)
		if !bytes.Equal(body, sourceBytes) || response.Header.Get("X-File-Revision-ID") != source.ID {
			t.Fatal("copy replacement independent source/target read differs")
		}
	}
	response, body = exchangeAPIRequest(t, server, "COPY", path, nil, command, nil, 200)
	var history struct {
		Result    store.PathResult `json:"result"`
		Namespace string           `json:"namespace_state"`
	}
	if json.Unmarshal(body, &history) != nil || !history.Result.Replayed || history.Namespace != "not-asserted-original-receipt" || response.Header.Get("Location") != "" {
		t.Fatal("copy replacement repeated its original receipt")
	}
	adminAuth := map[string]string{"Authorization": "Bearer " + string(admin.Bytes)}
	_, body = exchangeAPIRequest(t, server, "GET", prefix+"/files/"+previous.ID, nil, adminAuth, nil, 200)
	if !bytes.Equal(body, previousBytes) {
		t.Fatal("copy replacement destroyed old immutable custody")
	}
	if _, err = service.PathCommand(t.Context(), scope, "copy-overwrite-remove-target", store.PathCommand{Operation: "remove", Path: "/copy-target.dat", ExpectedRevision: &target.Revision}); err != nil {
		t.Fatal(err)
	}
	exchangeAPIRequest(t, server, "COPY", path, nil, headers("copy-overwrite-commit", "/copy-target.dat", "F", manager), nil, 409)
	exchangeAPIRequest(t, server, "GET", prefix+"/dav/copy-target.dat", nil, managerAuth, nil, 404)
	checking := &checks.Service{Custody: service}
	if _, err = checking.Register(t.Context(), scope, "copy-overwrite-policy", checks.PolicyRequest{Definition: checks.Policy{Schema: 1, Kind: "csv", Columns: []checks.Column{{Name: "record", Type: "text", Required: true}}}}); err != nil {
		t.Fatal(err)
	}
	controlled := create("copy-overwrite-controlled", "/copy-controlled.csv", []byte("record\nreleased target\n"))
	if _, err = checking.Run(t.Context(), scope, controlled.ID, "copy-overwrite-check"); err != nil {
		t.Fatal(err)
	}
	checked, err := checking.Get(t.Context(), scope, controlled.ID)
	if err != nil || checked.Check.State != "passed" {
		t.Fatal("controlled copy target check not passed", err)
	}
	if _, err = checking.Release(t.Context(), scope, controlled.ID, "copy-overwrite-release", checks.ReleaseDecision{SHA256: controlled.SHA256, PolicyHash: checked.Check.PolicyHash, ReportHash: checked.Check.ReportHash, Revision: checked.Check.Revision}); err != nil {
		t.Fatal(err)
	}
	policy, err := checking.Policy(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = checking.Revoke(t.Context(), scope, "copy-overwrite-revoke", checks.PolicyDecision{Hash: policy.Hash, Version: policy.Version, Revision: policy.Revision}); err != nil {
		t.Fatal(err)
	}
	exchangeAPIRequest(t, server, "COPY", path, nil, headers("copy-overwrite-revoked-target", "/copy-controlled.csv", "T", admin), nil, 409)
	tx, err = service.DB.Begin(t.Context(), managerScope)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Tx.Rollback(t.Context())
	var publications, removals, commands, acceptances, intents, runs int
	if err = tx.Tx.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM events WHERE kind='PathPublished' AND actor_id=$1),(SELECT count(*) FROM events WHERE kind='PathRemoved' AND actor_id=$1),(SELECT count(*) FROM namespace_commands WHERE request_key='copy-overwrite-commit'),(SELECT count(*) FROM events WHERE kind='FileAccepted' AND actor_id=$1),(SELECT count(*) FROM delivery_intents),(SELECT count(*) FROM workflow_runs)`, identity.Actor).Scan(&publications, &removals, &commands, &acceptances, &intents, &runs); err != nil || publications != 2 || removals != 1 || commands != 1 || acceptances != 0 || intents != 0 || runs != 0 {
		t.Fatalf("copy replacement lost atomic actor evidence or gained effects;publications=%d;removals=%d;receipts=%d;acceptances=%d;intents=%d;runs=%d;error=%v", publications, removals, commands, acceptances, intents, runs, err)
	}
}
