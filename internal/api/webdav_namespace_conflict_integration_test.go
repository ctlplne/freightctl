//go:build integration

package api

import (
	"bytes"
	"errors"
	"strconv"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestWebDAVUnsupportedNamespaceConditionsCannotStageOrMutateResources(t *testing.T) {
	service, scope, admin, server := browserAPI(t, time.Minute)
	cookie, csrf := loginBrowser(t, server, scope, admin)
	prefix := "/v1/tenants/" + scope.Tenant + "/partners/" + scope.Partner
	data := []byte("known conditions must not be silently discarded\n")
	mode := uint32(0660)
	file, _, err := service.AcceptAt(t.Context(), scope, "namespace-condition-source", int64(len(data)), secure.Digest(data), bytes.NewReader(data), custody.UploadTarget{Path: "/condition.dat", Mode: &mode})
	if err != nil {
		t.Fatal(err)
	}
	before, err := service.StatPath(t.Context(), scope, "/condition.dat")
	if err != nil {
		t.Fatal(err)
	}
	operator, participant := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "list", "write", "manage_paths"})
	for _, method := range []string{"PUT", "MKCOL", "MOVE", "COPY", "DELETE"} {
		target := prefix + "/dav/condition.dat"
		headers := map[string]string{"Authorization": "Bearer " + string(operator.Bytes), "Idempotency-Key": "unsupported-namespace-" + method, "X-Freightctl-Namespace-Revision": before.ID + ":" + strconv.FormatInt(before.Revision+1, 10)}
		var payload []byte
		if method == "MKCOL" {
			target = prefix + "/dav/condition-folder/"
			headers["If-None-Match"] = "*"
		} else {
			headers["If-Match"] = artifactRevisionETag(file)
		}
		if method == "PUT" {
			payload = []byte("replacement must not reach staging\n")
			headers["X-Content-SHA256"] = secure.Digest(payload)
		}
		if method == "MOVE" || method == "COPY" {
			headers["Overwrite"] = "F"
			headers["Destination"] = server.URL + prefix + "/dav/condition-target.dat"
		}
		exchangeAPIRequest(t, server, method, target, nil, headers, payload, 400)
	}
	after, err := service.StatPath(t.Context(), scope, "/condition.dat")
	if err != nil || *after != *before {
		t.Fatal("unsupported condition changed the source mapping", err)
	}
	for _, path := range []string{"/condition-folder", "/condition-target.dat"} {
		if _, err = service.StatPath(t.Context(), scope, path); !errors.Is(err, store.ErrNotFound) {
			t.Fatal("unsupported condition created a resource", err)
		}
	}
	response, received := exchangeAPIRequest(t, server, "GET", prefix+"/dav/condition.dat", nil, map[string]string{"Authorization": "Bearer " + string(operator.Bytes)}, nil, 200)
	if !bytes.Equal(received, data) || response.Header.Get("X-File-Revision-ID") != file.ID {
		t.Fatal("unsupported condition changed immutable bytes or custody")
	}
	operatorScope := store.Scope{Tenant: scope.Tenant, Partner: scope.Partner, TokenHash: secure.Digest(operator.Bytes)}
	tx, err := service.DB.Begin(t.Context(), operatorScope)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Tx.Rollback(t.Context())
	var commands, transitions, accepts, intents, runs int
	if err = tx.Tx.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM namespace_commands),(SELECT count(*) FROM events WHERE actor_id=$1 AND kind IN ('PathCreated','PathPublished','PathMoved','PathRemoved','PathAttrsChanged')),(SELECT count(*) FROM events WHERE actor_id=$1 AND kind='FileAccepted'),(SELECT count(*) FROM delivery_intents),(SELECT count(*) FROM workflow_runs)`, participant.Actor).Scan(&commands, &transitions, &accepts, &intents, &runs); err != nil || commands != 0 || transitions != 0 || accepts != 0 || intents != 0 || runs != 0 {
		t.Fatal("unsupported condition reached durable acceptance,namespace mutation or execution", commands, transitions, accepts, intents, runs, err)
	}
}
