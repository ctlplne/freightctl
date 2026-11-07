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

func TestWebDAVFileMovePinsRevisionPermissionsAndCurrentIntakeWithoutForwarding(t *testing.T) {
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
			t.Fatal("ordinary move source acceptance differs")
		}
		return accepted.File
	}
	data := []byte("same immutable bytes;only namespace authority moves them\n")
	file := create("dav-move-source", "/source.dat", data)
	existing := create("dav-move-existing", "/existing.dat", []byte("existing destination must survive"))
	operator, operatorIdentity := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "list", "manage_paths"})
	reader, _ := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "list"})
	managerOnly, _ := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"list", "manage_paths"})
	auth := map[string]string{"Authorization": "Bearer " + string(operator.Bytes)}
	source := prefix + "/dav/source.dat"
	response, body := exchangeAPIRequest(t, server, "GET", source, nil, auth, nil, 200)
	tag := response.Header.Get("ETag")
	if !bytes.Equal(body, data) || tag != artifactRevisionETag(&file) {
		t.Fatal("move operator did not review the actual authorized revision")
	}
	headers := func(key, revision, target string, credential *secure.Secret) map[string]string {
		return map[string]string{"Authorization": "Bearer " + string(credential.Bytes), "If-Match": revision, "Overwrite": "F", "Idempotency-Key": key, "Destination": target}
	}
	target := prefix + "/dav/new%20name.dat"
	for _, credential := range []*secure.Secret{reader, managerOnly} {
		exchangeAPIRequest(t, server, "MOVE", source, nil, headers("dav-move-denied", tag, target, credential), nil, 403)
	}
	exchangeAPIRequest(t, server, "MOVE", source, nil, headers("dav-move-existing", tag, prefix+"/dav/existing.dat", operator), nil, 412)
	exchangeAPIRequest(t, server, "MOVE", source, nil, headers("dav-move-stale", artifactRevisionETag(&existing), target, operator), nil, 412)
	exchangeAPIRequest(t, server, "MOVE", source, nil, headers("dav-move-parent", tag, prefix+"/dav/missing/child.dat", operator), nil, 409)
	_, body = exchangeAPIRequest(t, server, "GET", prefix+"/dav/existing.dat", nil, auth, nil, 200)
	if secure.Digest(body) != existing.SHA256 {
		t.Fatal("refused move modified an existing destination")
	}
	moveHeaders := headers("dav-move-command", tag, server.URL+target, operator)
	response, raw := exchangeAPIRequest(t, server, "MOVE", source, nil, moveHeaders, nil, 201)
	var moved struct {
		Result    store.PathResult `json:"result"`
		Namespace string           `json:"namespace_state"`
	}
	if json.Unmarshal(raw, &moved) != nil || moved.Result.Replayed || moved.Result.Changed != 1 || moved.Result.Entry.Path != "/new name.dat" || moved.Result.Entry.FileID != file.ID || moved.Namespace != "moved-at-commit" || response.Header.Get("Location") != target {
		t.Fatal("MOVE changed custody identity or lost its exact namespace receipt")
	}
	exchangeAPIRequest(t, server, "GET", source, nil, auth, nil, 404)
	response, body = exchangeAPIRequest(t, server, "GET", target, nil, auth, nil, 200)
	if !bytes.Equal(body, data) || response.Header.Get("X-File-Revision-ID") != file.ID || response.Header.Get("ETag") != tag {
		t.Fatal("moved path did not independently read the same immutable revision")
	}
	exchangeAPIRequest(t, server, "MOVE", source, nil, moveHeaders, nil, 412)
	// Equal bytes accepted later are a distinct immutable revision. An old
	// content digest or command key must not rescue the previous file validator.
	replacement := create("dav-move-replacement", "/source.dat", data)
	if replacement.ID == file.ID || replacement.SHA256 != file.SHA256 {
		t.Fatal("replacement fixture is not an independent equal-content revision")
	}
	exchangeAPIRequest(t, server, "MOVE", source, nil, moveHeaders, nil, 412)
	response, _ = exchangeAPIRequest(t, server, "HEAD", source, nil, auth, nil, 200)
	if response.Header.Get("X-File-Revision-ID") != replacement.ID {
		t.Fatal("stale move consumed the replacement revision")
	}
	exchangeAPIRequest(t, server, "MOVE", source, nil, headers("dav-move-command", artifactRevisionETag(&replacement), server.URL+target, operator), nil, 409)
	if _, err := service.PathCommand(t.Context(), scope, "dav-move-directory", store.PathCommand{Operation: "mkdir", Path: "/directory"}); err != nil {
		t.Fatal(err)
	}
	response, _ = exchangeAPIRequest(t, server, "MOVE", prefix+"/dav/directory", nil, headers("dav-move-dir-refused", tag, prefix+"/dav/other-directory", operator), nil, 405)
	if !strings.Contains(response.Header.Get("Allow"), "MOVE") || !strings.Contains(response.Header.Get("Allow"), "COPY") || !strings.Contains(response.Header.Get("Allow"), "DELETE") {
		t.Fatal("collection profile must advertise namespace-conditioned MOVE/DELETE and COPY")
	}
	checking := &checks.Service{Custody: service}
	if _, err := checking.Register(t.Context(), scope, "dav-move-policy", checks.PolicyRequest{Definition: checks.Policy{Schema: 1, Kind: "csv", Columns: []checks.Column{{Name: "record", Type: "text", Required: true}}}}); err != nil {
		t.Fatal(err)
	}
	controlled := create("dav-move-controlled", "/controlled.csv", []byte("record\nreleased then revoked\n"))
	if _, err := checking.Run(t.Context(), scope, controlled.ID, "dav-move-check"); err != nil {
		t.Fatal(err)
	}
	checked, err := checking.Get(t.Context(), scope, controlled.ID)
	if err != nil || checked.Check.State != "passed" {
		t.Fatal("controlled move fixture did not pass checks", err)
	}
	if _, err = checking.Release(t.Context(), scope, controlled.ID, "dav-move-release", checks.ReleaseDecision{SHA256: controlled.SHA256, PolicyHash: checked.Check.PolicyHash, ReportHash: checked.Check.ReportHash, Revision: checked.Check.Revision}); err != nil {
		t.Fatal(err)
	}
	registered, err := checking.Policy(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = checking.Revoke(t.Context(), scope, "dav-move-revoke", checks.PolicyDecision{Hash: registered.Hash, Version: registered.Version, Revision: registered.Revision}); err != nil {
		t.Fatal(err)
	}
	exchangeAPIRequest(t, server, "MOVE", prefix+"/dav/controlled.csv", nil, headers("dav-move-revoked", artifactRevisionETag(&controlled), prefix+"/dav/moved-controlled.csv", operator), nil, 409)
	tx, err := service.DB.Begin(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Tx.Rollback(t.Context())
	var moves, intents, runs int
	var actor string
	if err = tx.Tx.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM events WHERE kind='PathMoved'),(SELECT count(*) FROM delivery_intents),(SELECT count(*) FROM workflow_runs),(SELECT actor_id::text FROM events WHERE kind='PathMoved')`).Scan(&moves, &intents, &runs, &actor); err != nil || moves != 1 || intents != 0 || runs != 0 || actor != operatorIdentity.Actor {
		t.Fatal("MOVE lost explicit path authority or created duplicate/forwarding/execution effects", err)
	}
}
