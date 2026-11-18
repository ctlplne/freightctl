//go:build integration

package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/delivery"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestDAVDeliveryFreightctlCustodyOnLoopback(t *testing.T) {
	digest := proveDAVDeliveryFreightctlCustodyPeer(t)
	t.Logf("separate loopback custody instances; source SHA-256 %s; conditional collision preserved", digest)
}

func proveDAVDeliveryFreightctlCustodyPeer(t *testing.T) string {
	t.Helper()
	source, sourceScope, _, _ := browserAPI(t, time.Minute)
	receiver, receiverScope, administrator, server := browserAPI(t, time.Minute)
	if sourceScope.Tenant == receiverScope.Tenant || source.Disk.Identity() == receiver.Disk.Identity() {
		t.Fatal("sender and receiver must have separate custody and identity")
	}
	prefix := "/v1/tenants/" + receiverScope.Tenant + "/partners/" + receiverScope.Partner
	cookie, csrf := loginBrowser(t, server, receiverScope, administrator)
	writer, _ := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"list", "read", "write", "manage_paths"})
	writerScope := receiverScope
	writerScope.TokenHash = secure.Digest(writer.Bytes)
	for _, dir := range []string{"/stage", "/inbox"} {
		if _, err := receiver.PathCommand(t.Context(), writerScope, "mkdir-"+strings.TrimPrefix(dir, "/"), store.PathCommand{Operation: "mkdir", Path: dir}); err != nil {
			t.Fatal("create the receiver's separate directories", err)
		}
	}
	privateMode := uint32(0700)
	stageDirectory, err := receiver.StatPath(t.Context(), writerScope, "/stage")
	if err != nil {
		t.Fatal("inspect the staging directory before changing its mode", err)
	}
	privateStage, err := receiver.PathCommand(t.Context(), writerScope, "private-stage", store.PathCommand{
		Operation: "setstat", Path: "/stage", ExpectedRevision: &stageDirectory.Revision, Mode: &privateMode,
	})
	if err != nil || privateStage.Entry.Mode != privateMode || privateStage.Entry.ID != stageDirectory.ID ||
		privateStage.Entry.Revision != stageDirectory.Revision+1 {
		t.Fatal("bind the exact staging directory to owner-only access", err)
	}
	reader, identity := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"list", "read"})
	_, err = receiver.DB.ChangeAccount(t.Context(), receiverScope, "native-dav-inbox-mount", store.AccountCommand{
		Operation: "update", ID: identity.Actor, ExpectedRevision: 1,
		Policy: &store.AccountPolicy{Label: "DAV inbox reader", Root: "/inbox", Permissions: []string{"list", "read"}},
	})
	if err != nil {
		t.Fatal("bind the recipient to its inbox", err)
	}
	davRoot := prefix + "/dav"
	auth := map[string]string{"Authorization": "Bearer " + string(reader.Bytes)}
	writerAuth := map[string]string{"Authorization": "Bearer " + string(writer.Bytes)}
	data := bytes.Repeat([]byte("durable conditional delivery between two custody instances\n"), 1000)
	digest := secure.Digest(data)
	file, _, err := source.Accept(t.Context(), sourceScope, "native-dav-input", int64(len(data)), digest, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	ca, err := secure.NativeProofCertificatePEM(server.Certificate().Raw)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	caRef, tokenRef := filepath.Join(dir, "peer-ca.pem"), filepath.Join(dir, "peer-token")
	for ref, body := range map[string][]byte{caRef: ca, tokenRef: writer.Bytes} {
		if err = os.WriteFile(ref, body, 0600); err != nil {
			t.Fatal("protect receiver reference", err)
		}
	}
	definition := delivery.DAVDefinition{
		Destination: secure.HTTPSReadDestination{
			Address: strings.TrimPrefix(server.URL, "https://"), ServerName: "example.com",
			CAFile: caRef, CASHA256: secure.Digest(ca), TokenFile: tokenRef, TokenSHA256: writerScope.TokenHash,
		},
		StagingDirectory: davRoot + "/stage",
		ReceiverContract: store.DAVReceiverContract{
			Schema: 1, DocumentSHA256: secure.Digest([]byte("freightctl native custody receiver conditional DAV fixture")),
			StagingVisibility: "receiver-private", Put: "exclusive-create", Move: "source-etag-no-overwrite",
			Duplicates: "receiver-deduplicates-delivery-id", Receipt: "exact-readback",
		},
	}
	sender := &delivery.Service{Custody: source}
	queue := func(key string) *store.Delivery {
		t.Helper()
		created, err := sender.Create(t.Context(), sourceScope, key+"-create", delivery.Request{
			FileID: file.ID, Directory: davRoot + "/inbox", Filename: "input.dat", DAV: &definition,
		})
		if err != nil {
			t.Fatal(err)
		}
		draft := created.Delivery
		queued, err := sender.Command(t.Context(), sourceScope, draft.ID, key+"-approve", "approve", draft.DefinitionHash, draft.Revision)
		if err != nil {
			t.Fatal(err)
		}
		return queued.Delivery
	}
	complete := queue("custody-peer")
	worked, err := sender.Work(t.Context(), sourceScope, complete.ID)
	if err != nil || worked.State != "succeeded" || worked.Fence != 1 || worked.Attempts != 1 {
		t.Fatal("ordinary delivery did not finish one conditional attempt", err)
	}
	var receipt map[string]any
	if json.Unmarshal(worked.Observation, &receipt) != nil || receipt["sha256"] != digest ||
		receipt["move_acknowledged"] != true || receipt["business_acceptance"] != "unknown" || receipt["file_fsync_acknowledged"] != false {
		t.Fatal("sender receipt lost exact bytes or overstated acceptance")
	}
	response, got := exchangeAPIRequest(t, server, http.MethodGet, davRoot+"/"+complete.ID+"-input.dat", nil, auth, nil, 200)
	if !bytes.Equal(got, data) || response.Header.Get("X-File-Revision-ID") == "" {
		t.Fatal("independent read principal failed to observe the exact receiver revision")
	}
	exchangeAPIRequest(t, server, http.MethodGet, davRoot+"/stage/.freightctl-"+complete.ID+".partial", nil, writerAuth, nil, 404)

	collision := queue("custody-collision")
	old := []byte("independent prior final bytes")
	finalName := collision.ID + "-input.dat"
	if _, _, err = receiver.AcceptAt(t.Context(), writerScope, "native-dav-existing-final", int64(len(old)), secure.Digest(old), bytes.NewReader(old), custody.UploadTarget{Path: "/inbox/" + finalName}); err != nil {
		t.Fatal(err)
	}
	ambiguous, err := sender.Work(t.Context(), sourceScope, collision.ID)
	if err != nil || ambiguous.State != "ambiguous" || ambiguous.Fence != 1 || ambiguous.Attempts != 1 {
		t.Fatal("non-overwrite refusal lost the uncertain stage effect", err)
	}
	if json.Unmarshal(ambiguous.Observation, &receipt) != nil || receipt["code"] != "dav_move_outcome_uncertain" {
		t.Fatal("refusal did not reach the guarded MOVE")
	}
	attempt, err := sender.Work(t.Context(), sourceScope, collision.ID)
	if !errors.Is(err, store.ErrState) || attempt != nil {
		t.Fatal("ambiguous collision became writable again", err)
	}
	observed, err := sender.Reconcile(t.Context(), sourceScope, collision.ID)
	if err != nil || observed.State != "ambiguous" || observed.Attempts != 1 || observed.Fence != 1 {
		t.Fatal("different final bytes falsely reconciled", err)
	}
	_, got = exchangeAPIRequest(t, server, http.MethodGet, davRoot+"/"+finalName, nil, auth, nil, 200)
	if !bytes.Equal(got, old) {
		t.Fatal("conditional MOVE replaced the original destination")
	}
	stage := davRoot + "/stage/.freightctl-" + collision.ID + ".partial"
	exchangeAPIRequest(t, server, http.MethodGet, stage, nil, auth, nil, 404)
	_, got = exchangeAPIRequest(t, server, http.MethodGet, stage, nil, writerAuth, nil, 200)
	if !bytes.Equal(got, data) {
		t.Fatal("refused move changed the intact private stage")
	}
	return digest
}
