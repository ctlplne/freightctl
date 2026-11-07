//go:build integration

package api

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
)

func TestTypedControlUnicodeAliasCannotOverrideAFalseNamespacePrecondition(t *testing.T) {
	service, scope, admin, server := browserAPI(t, time.Minute)
	prefix := "/v1/tenants/" + scope.Tenant + "/partners/" + scope.Partner
	data := []byte("typed namespace revision remains exactly reviewed\n")
	file, _, err := service.AcceptAt(t.Context(), scope, "unicode-control-source", int64(len(data)), secure.Digest(data), bytes.NewReader(data), custody.UploadTarget{Path: "/control-existing.dat"})
	if err != nil {
		t.Fatal(err)
	}
	before, err := service.StatPath(t.Context(), scope, "/control-existing.dat")
	if err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`{"operation":"setstat","path":"/control-existing.dat","expected_revision":0,"expected_reviſion":%d,"mode":0}`, before.Revision)
	exchangeAPIRequest(t, server, "POST", prefix+"/namespace/commands", nil, map[string]string{"Authorization": "Bearer " + string(admin.Bytes), "Idempotency-Key": "unicode-control-alias", "Content-Type": "application/json"}, []byte(body), 400)
	after, err := service.StatPath(t.Context(), scope, before.Path)
	if err != nil || *after != *before {
		t.Fatal("Unicode alias changed current mapping,mode or precondition", err)
	}
	tx, err := service.DB.Begin(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	var receipts, attrs int
	err = tx.Tx.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM namespace_commands WHERE request_key='unicode-control-alias'),(SELECT count(*) FROM events WHERE kind='PathAttrsChanged')`).Scan(&receipts, &attrs)
	_ = tx.Tx.Rollback(t.Context())
	if err != nil || receipts != 0 || attrs != 0 {
		t.Fatal("Unicode alias reached namespace transitions or private receipts", err)
	}
	response, actual := exchangeAPIRequest(t, server, "GET", prefix+"/files/"+file.ID, nil, map[string]string{"Authorization": "Bearer " + string(admin.Bytes)}, nil, 200)
	if !bytes.Equal(actual, data) || response.Header.Get("X-File-Revision-ID") != file.ID {
		t.Fatal("refused Unicode control changed immutable custody")
	}
}
