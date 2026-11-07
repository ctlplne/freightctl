//go:build integration

package api

import (
	"bytes"
	"errors"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestNamespaceCopyCannotReplaceItsOwnSourceThroughAPIOrStore(t *testing.T) {
	service, scope, admin, server := browserAPI(t, time.Minute)
	data := []byte("self-copy must preserve the original mapping\n")
	file, _, err := service.AcceptAt(t.Context(), scope, "self-copy-source", int64(len(data)), secure.Digest(data), bytes.NewReader(data), custody.UploadTarget{Path: "/same.dat"})
	if err != nil {
		t.Fatal(err)
	}
	before, err := service.StatPath(t.Context(), scope, "/same.dat")
	if err != nil {
		t.Fatal(err)
	}
	prefix := "/v1/tenants/" + scope.Tenant + "/partners/" + scope.Partner
	for _, replace := range []bool{false, true} {
		command := store.PathCommand{Operation: "copy", Path: "/same.dat", Target: "/same.dat", FileID: file.ID, ExpectedRevision: &before.Revision, Replace: replace}
		if replace {
			command.TargetRevision = &before.Revision
		}
		headers := map[string]string{"Authorization": "Bearer " + string(admin.Bytes), "Content-Type": "application/json", "Idempotency-Key": "self-copy-refused"}
		exchangeAPIRequest(t, server, "POST", prefix+"/namespace/commands", nil, headers, exchangeAPIJSON(t, command), 403)
		tx, err := service.DB.Begin(t.Context(), scope)
		if err != nil {
			t.Fatal(err)
		}
		_, err = tx.ApplyPathCommand(t.Context(), "self-copy-store-refused", command, 1000)
		if !errors.Is(err, store.ErrForbidden) {
			tx.Tx.Rollback(t.Context())
			t.Fatal("store allowed a copy to replace its own source", err)
		}
		if err = tx.Tx.Rollback(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	after, err := service.StatPath(t.Context(), scope, "/same.dat")
	if err != nil || *after != *before {
		t.Fatal("refused self-copy changed mapping identity,revision or metadata", err)
	}
	_, actual := exchangeAPIRequest(t, server, "GET", prefix+"/dav/same.dat", nil, map[string]string{"Authorization": "Bearer " + string(admin.Bytes)}, nil, 200)
	if !bytes.Equal(actual, data) {
		t.Fatal("refused self-copy changed source bytes")
	}
	tx, err := service.DB.Begin(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Tx.Rollback(t.Context())
	var commands, removed int
	if err = tx.Tx.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM namespace_commands WHERE request_key IN ('self-copy-refused','self-copy-store-refused')),(SELECT count(*) FROM events WHERE kind='PathRemoved')`).Scan(&commands, &removed); err != nil || commands != 0 || removed != 0 {
		t.Fatal("refused self-copy recorded a receipt or removal", err)
	}
}
