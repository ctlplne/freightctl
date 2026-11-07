//go:build integration

package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
)

func qualifyCLIControlBoundaries(t *testing.T, ctx context.Context, service *custody.Service, scope store.Scope, token string, command func(string, string, ...string) ([]byte, error)) {
	t.Helper()
	data := []byte("CLI control aliases cannot change this resource\n")
	file, _, err := service.AcceptAt(ctx, scope, "control-fixture-source", int64(len(data)), secure.Digest(data), bytes.NewReader(data), custody.UploadTarget{Path: "/cli-control-source.dat"})
	if err != nil {
		t.Fatal(err)
	}
	before, err := service.StatPath(ctx, scope, "/cli-control-source.dat")
	if err != nil {
		t.Fatal(err)
	}
	requests := []struct{ name, body, want string }{
		{"namespace", `{"operation":"mkdir","path":"/reviewed","path":"/unreviewed"}`, "invalid namespace command JSON"},
		{"namespace", `{"operation":"mkdir","PATH":"/casefold"}`, "invalid namespace command JSON"},
		{"namespace", fmt.Sprintf(`{"operation":"setstat","path":"/cli-control-source.dat","expected_revision":0,"expected_reviſion":%d,"mode":0}`, before.Revision), "invalid namespace command JSON"},
		{"namespace", "{\"operation\":\"mkdir\",\"path\":\"/a\xff\"}", "invalid namespace command JSON"},
		{"namespace", `null`, "invalid namespace command JSON"},
		{"upload-create", `{"path":"/reviewed-upload","path":"/unreviewed-upload","expected_size":0,"expected_sha256":"` + secure.Digest(nil) + `"}`, "invalid upload request JSON"},
		{"upload-create", `{"path":"/casefold-upload","EXPECTED_SIZE":0,"expected_sha256":"` + secure.Digest(nil) + `"}`, "invalid upload request JSON"},
		{"upload-create", `{"path":"/unicode-upload","expected_size":0,"expected_ſize":1,"expected_sha256":"` + secure.Digest(nil) + `"}`, "invalid upload request JSON"},
		{"upload-create", `null`, "invalid upload request JSON"},
	}
	keys := make([]string, 0, len(requests))
	for i, request := range requests {
		path := filepath.Join(t.TempDir(), "control.json")
		if err = os.WriteFile(path, []byte(request.body), 0600); err != nil {
			t.Fatal(err)
		}
		key := fmt.Sprintf("cli-control-refused-%d", i)
		keys = append(keys, key)
		if _, err = command(token, request.name, "-request-file", path, "-idempotency-key", key); err == nil || err.Error() != request.want {
			t.Fatal("actual CLI did not refuse malformed control at its input boundary", request.name, err)
		}
	}
	after, err := service.StatPath(ctx, scope, before.Path)
	if err != nil || *after != *before || after.FileID != file.ID {
		t.Fatal("malformed CLI control changed its authorized source", err)
	}
	page, err := service.ListUploads(ctx, scope, "", 1)
	if err != nil || len(page.Uploads) != 0 || page.Next != "" || page.BlockedByAccessChange {
		t.Fatal("malformed CLI upload control created an owned session", err)
	}
	tx, err := service.DB.Begin(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Tx.Rollback(ctx)
	var receipts, attrs int
	if err = tx.Tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM namespace_commands WHERE request_key=ANY($1)),(SELECT count(*) FROM events WHERE actor_id=$2 AND kind='PathAttrsChanged')`, keys, tx.Actor).Scan(&receipts, &attrs); err != nil || receipts != 0 || attrs != 0 {
		t.Fatal("malformed CLI control created transitions or command receipts", err)
	}
}
