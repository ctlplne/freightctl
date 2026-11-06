package api

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestMCPUploadProjectionSeparatesOriginalReceiptAndCurrentTicket(t *testing.T) {
	scope := store.Scope{Tenant: "11111111-1111-4111-8111-111111111111", Partner: "22222222-2222-4222-8222-222222222222"}
	u := custody.UploadView{ID: "33333333-3333-4333-8333-333333333333", Path: "/new.dat", ExpectedSize: 8, ExpectedSHA256: strings.Repeat("a", 64), Offset: 4, Chunks: 1, State: "open", Revision: 2, EventID: "44444444-4444-4444-8444-444444444444", SFTPPath: "private-transport-sentinel", FTPSPath: "private-transport-sentinel"}
	for _, receipt := range []bool{false, true} {
		result, err := mcpArtifactUpload(scope, u, receipt, receipt)
		if err != nil || result.Upload.Offset != 4 || result.Upload.SHA256 != u.ExpectedSHA256 || result.AppendPath != "/v1/tenants/"+scope.Tenant+"/partners/"+scope.Partner+"/uploads/"+u.ID || result.AppendMethod != "PATCH" || result.MaxChunk != custody.MaxUploadChunk || result.MinNonfinalChunk != custody.MinUploadChunk || result.MaxChunks != 4096 || result.ReceiverPersistence != "unknown" || result.BusinessProcessing != "unknown" || result.Availability != "not-checked" {
			t.Fatal("projection changed byte route/identity or claimed an outcome", err)
		}
		if receipt && (result.Observation != "original-command-receipt" || result.CurrentState != "not-checked" || !result.Replayed) {
			t.Fatal("historical receipt claimed current state")
		}
		if !receipt && (result.Observation != "current-ticket-metadata" || result.CurrentState != "observed-ticket-only" || result.Replayed) {
			t.Fatal("status invented receipt")
		}
		raw, _ := json.Marshal(result)
		for _, forbidden := range []string{"private-transport-sentinel", "Authorization", "Bearer ", "storage_id", "content_base64", "sftp_path", "ftps_path"} {
			if strings.Contains(string(raw), forbidden) {
				t.Fatal("projection disclosed content/transport authority", forbidden)
			}
		}
	}
	for _, change := range []func(*custody.UploadView){func(v *custody.UploadView) { v.Offset = 9 }, func(v *custody.UploadView) { v.Path = "/../escape" }, func(v *custody.UploadView) { v.State = "published" }, func(v *custody.UploadView) { v.FileID = "55555555-5555-4555-8555-555555555555" }, func(v *custody.UploadView) { v.Acceptance = "durable-local-integrity-only" }, func(v *custody.UploadView) { v.State = "completed" }} {
		v := u
		change(&v)
		if _, err := mcpArtifactUpload(scope, v, false, false); !errors.Is(err, store.ErrIsolation) {
			t.Fatal("inconsistent ticket gained outcome", err)
		}
	}
	u.State = "completed"
	u.Offset = u.ExpectedSize
	u.FileID = "55555555-5555-4555-8555-555555555555"
	u.Acceptance = "durable-held-pending-checks-and-release"
	result, err := mcpArtifactUpload(scope, u, true, true)
	if err != nil || result.Upload.FileID != u.FileID || result.Upload.Acceptance != u.Acceptance || result.Availability != "not-checked" {
		t.Fatal("held acceptance became availability", err)
	}
}
