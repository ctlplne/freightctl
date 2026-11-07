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

func TestWebDAVFileMoveOverwriteRequiresTargetAuthorityAndAtomicReceipt(t *testing.T) {
	service, scope, admin, server := browserAPI(t, time.Minute)
	cookie, csrf := loginBrowser(t, server, scope, admin)
	prefix := "/v1/tenants/" + scope.Tenant + "/partners/" + scope.Partner
	create := func(key, path string, data []byte) store.File {
		t.Helper()
		mode := uint32(0660) // Explicit shared write authority;private-target refusal is tested separately.
		file, _, err := service.AcceptAt(t.Context(), scope, key, int64(len(data)), secure.Digest(data), bytes.NewReader(data), custody.UploadTarget{Path: path, Mode: &mode})
		if err != nil {
			t.Fatal(err)
		}
		return *file
	}
	sourceBytes := []byte("exact source for explicit overwrite\n")
	targetBytes := []byte("retained original destination custody\n")
	source := create("move-overwrite-source", "/overwrite-source.dat", sourceBytes)
	oldTarget := create("move-overwrite-old-target", "/old-target.dat", targetBytes)
	absentSource := create("move-overwrite-absent-source", "/absent-source.dat", sourceBytes)
	policySource := create("move-overwrite-policy-source", "/policy-source.dat", sourceBytes)
	operator, identity := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "list", "write", "manage_paths"})
	operatorScope := store.Scope{Tenant: scope.Tenant, Partner: scope.Partner, TokenHash: secure.Digest(operator.Bytes)}
	if _, err := service.PathCommand(t.Context(), operatorScope, "move-overwrite-own-target", store.PathCommand{Operation: "publish", Path: "/overwrite-target.dat", FileID: oldTarget.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.PathCommand(t.Context(), operatorScope, "move-overwrite-own-dir", store.PathCommand{Operation: "mkdir", Path: "/own-directory"}); err != nil {
		t.Fatal(err)
	}
	mode := uint32(0400)
	oldEntry, err := service.StatPath(t.Context(), scope, "/old-target.dat")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.PathCommand(t.Context(), scope, "move-overwrite-protect-old", store.PathCommand{Operation: "setstat", Path: "/old-target.dat", ExpectedRevision: &oldEntry.Revision, Mode: &mode}); err != nil {
		t.Fatal(err)
	}
	headers := func(key, tag, target, overwrite string, credential *secure.Secret) map[string]string {
		return map[string]string{"Authorization": "Bearer " + string(credential.Bytes), "Idempotency-Key": key, "If-Match": tag, "Overwrite": overwrite, "Destination": prefix + "/dav" + target}
	}
	path := prefix + "/dav/overwrite-source.dat"
	tag := artifactRevisionETag(&source)
	reader, _ := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "list"})
	manager, _ := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"manage_paths", "list"})
	for _, credential := range []*secure.Secret{reader, manager} {
		exchangeAPIRequest(t, server, "MOVE", path, nil, headers("move-overwrite-denied", tag, "/overwrite-target.dat", "T", credential), nil, 403)
	}
	exchangeAPIRequest(t, server, "MOVE", path, nil, headers("move-overwrite-mode-denied", tag, "/old-target.dat", "T", operator), nil, 403)
	exchangeAPIRequest(t, server, "MOVE", path, nil, headers("move-overwrite-collection-denied", tag, "/own-directory", "T", operator), nil, 405)
	exchangeAPIRequest(t, server, "MOVE", path, nil, headers("move-overwrite-false", tag, "/overwrite-target.dat", "F", operator), nil, 412)
	moveHeaders := headers("move-overwrite-commit", tag, "/overwrite-target.dat", "T", operator)
	response, body := exchangeAPIRequest(t, server, "MOVE", path, nil, moveHeaders, nil, 204)
	if len(body) != 0 || response.Header.Get("X-Freightctl-Namespace-State") != "replaced-at-commit" || !store.ValidID(response.Header.Get("X-Freightctl-Event-ID")) || response.Header.Get("ETag") != "" || response.Header.Get("Location") != "" {
		t.Fatal("overwrite lost exact mapping outcome or invented a byte validator")
	}
	auth := map[string]string{"Authorization": "Bearer " + string(operator.Bytes)}
	exchangeAPIRequest(t, server, "GET", path, nil, auth, nil, 404)
	response, body = exchangeAPIRequest(t, server, "GET", prefix+"/dav/overwrite-target.dat", nil, auth, nil, 200)
	if !bytes.Equal(body, sourceBytes) || response.Header.Get("X-File-Revision-ID") != source.ID {
		t.Fatal("overwritten destination did not retain exact source custody")
	}
	adminAuth := map[string]string{"Authorization": "Bearer " + string(admin.Bytes)}
	_, body = exchangeAPIRequest(t, server, "GET", prefix+"/files/"+oldTarget.ID, nil, adminAuth, nil, 200)
	if !bytes.Equal(body, targetBytes) {
		t.Fatal("mapping overwrite destroyed original destination custody")
	}
	exchangeAPIRequest(t, server, "MOVE", path, nil, moveHeaders, nil, 412)
	if _, err = service.PathCommand(t.Context(), scope, "move-overwrite-restore-source", store.PathCommand{Operation: "publish", Path: "/overwrite-source.dat", FileID: source.ID}); err != nil {
		t.Fatal(err)
	}
	exchangeAPIRequest(t, server, "MOVE", path, nil, moveHeaders, nil, 409)
	// Explicit overwrite of an absent target still creates one mapping. A later
	// same-key receipt does not move a restored source again or recreate a target.
	absentHeaders := headers("move-overwrite-absent", artifactRevisionETag(&absentSource), "/absent-target.dat", "T", operator)
	response, body = exchangeAPIRequest(t, server, "MOVE", prefix+"/dav/absent-source.dat", nil, absentHeaders, nil, 201)
	if response.Header.Get("Location") != prefix+"/dav/absent-target.dat" {
		t.Fatal("overwrite decision lost new destination Location")
	}
	entry, err := service.StatPath(t.Context(), scope, "/absent-target.dat")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.PathCommand(t.Context(), scope, "move-overwrite-remove-target", store.PathCommand{Operation: "remove", Path: "/absent-target.dat", ExpectedRevision: &entry.Revision}); err != nil {
		t.Fatal(err)
	}
	if _, err = service.PathCommand(t.Context(), scope, "move-overwrite-restore-absent", store.PathCommand{Operation: "publish", Path: "/absent-source.dat", FileID: absentSource.ID}); err != nil {
		t.Fatal(err)
	}
	response, body = exchangeAPIRequest(t, server, "MOVE", prefix+"/dav/absent-source.dat", nil, absentHeaders, nil, 200)
	var historical struct {
		Result    store.PathResult `json:"result"`
		Namespace string           `json:"namespace_state"`
	}
	if json.Unmarshal(body, &historical) != nil || !historical.Result.Replayed || historical.Namespace != "not-asserted-original-receipt" || response.Header.Get("Location") != "" {
		t.Fatal("historical overwrite created a new namespace effect")
	}
	exchangeAPIRequest(t, server, "GET", prefix+"/dav/absent-target.dat", nil, auth, nil, 404)
	exchangeAPIRequest(t, server, "HEAD", prefix+"/dav/absent-source.dat", nil, auth, nil, 200)
	changedFlag := headers("move-overwrite-absent", artifactRevisionETag(&absentSource), "/absent-target.dat", "F", operator)
	exchangeAPIRequest(t, server, "MOVE", prefix+"/dav/absent-source.dat", nil, changedFlag, nil, 409)
	checking := &checks.Service{Custody: service}
	if _, err = checking.Register(t.Context(), scope, "move-overwrite-policy", checks.PolicyRequest{Definition: checks.Policy{Schema: 1, Kind: "csv", Columns: []checks.Column{{Name: "record", Type: "text", Required: true}}}}); err != nil {
		t.Fatal(err)
	}
	controlled := create("move-overwrite-controlled", "/controlled-target.csv", []byte("record\nreleased destination\n"))
	if _, err = checking.Run(t.Context(), scope, controlled.ID, "move-overwrite-check"); err != nil {
		t.Fatal(err)
	}
	checked, err := checking.Get(t.Context(), scope, controlled.ID)
	if err != nil || checked.Check.State != "passed" {
		t.Fatal("controlled target check did not pass", err)
	}
	if _, err = checking.Release(t.Context(), scope, controlled.ID, "move-overwrite-release", checks.ReleaseDecision{SHA256: controlled.SHA256, PolicyHash: checked.Check.PolicyHash, ReportHash: checked.Check.ReportHash, Revision: checked.Check.Revision}); err != nil {
		t.Fatal(err)
	}
	policy, err := checking.Policy(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = checking.Revoke(t.Context(), scope, "move-overwrite-revoke", checks.PolicyDecision{Hash: policy.Hash, Version: policy.Version, Revision: policy.Revision}); err != nil {
		t.Fatal(err)
	}
	exchangeAPIRequest(t, server, "MOVE", prefix+"/dav/policy-source.dat", nil, headers("move-overwrite-target-policy", artifactRevisionETag(&policySource), "/controlled-target.csv", "T", admin), nil, 409)
	tx, err := service.DB.Begin(t.Context(), operatorScope)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Tx.Rollback(t.Context())
	var moved, removed, commands, accepted, intents, runs int
	if err = tx.Tx.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM events WHERE kind='PathMoved' AND actor_id=$1),(SELECT count(*) FROM events WHERE kind='PathRemoved' AND actor_id=$1),(SELECT count(*) FROM namespace_commands WHERE request_key IN ('move-overwrite-commit','move-overwrite-absent')),(SELECT count(*) FROM events WHERE kind='FileAccepted' AND actor_id=$1),(SELECT count(*) FROM delivery_intents),(SELECT count(*) FROM workflow_runs)`, identity.Actor).Scan(&moved, &removed, &commands, &accepted, &intents, &runs); err != nil || moved != 2 || removed != 1 || commands != 2 || accepted != 0 || intents != 0 || runs != 0 {
		t.Fatalf("overwrite lost atomic actor evidence or gained effects;moves=%d;removals=%d;receipts=%d;acceptances=%d;intents=%d;runs=%d;error=%v", moved, removed, commands, accepted, intents, runs, err)
	}
}
