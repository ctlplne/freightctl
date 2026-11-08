//go:build integration && davpeer

package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/delivery"
	"github.com/ctlplne/freightctl/internal/store"
)

// Actual PostgreSQL and worker with a TLS protocol stand-in that drops the
// MOVE reply after retaining exact final bytes. This is not a vendor claim.
func TestDAVDeliveryNativeLostMoveReplyReconcilesReadOnly(t *testing.T) {
	peer := loadNativeDAVStockPeer(t)
	consumer, scope, _, _ := browserAPI(t, 10*time.Minute)
	data := bytes.Repeat([]byte("actual uncertain DAV publication;no automatic resend\n"), 1000)
	file, _, err := consumer.Accept(t.Context(), scope, "dav-recovery-source", int64(len(data)), secure.Digest(data), bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	private := t.TempDir()
	tokenRef := filepath.Join(private, "receiver.token")
	if err = secure.WriteToken(tokenRef); err != nil {
		t.Fatal(err)
	}
	credential, err := secure.ReadSecret(tokenRef, 64)
	if err != nil {
		t.Fatal(err)
	}
	defer credential.Close()
	var intent atomic.Pointer[store.Delivery]
	var mu sync.Mutex
	files := map[string][]byte{}
	writes, reads := 0, 0
	etag := `"stage-` + secure.Digest(data) + `"`
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d := intent.Load()
		if d == nil || r.Header.Get("Authorization") != "Bearer "+string(credential.Bytes) || r.TLS == nil || r.TLS.Version != 0x0304 {
			w.WriteHeader(403)
			return
		}
		stage, final := "/stage/.freightctl-"+d.ID+".partial", "/inbox/"+d.ID+"-input.dat"
		mu.Lock()
		defer mu.Unlock()
		switch r.Method {
		case "PUT":
			tx, e := consumer.DB.Begin(r.Context(), scope)
			if e != nil {
				t.Error("independent intent observation unavailable")
				w.WriteHeader(500)
				return
			}
			observed, e := tx.Delivery(r.Context(), d.ID, false)
			tx.Tx.Rollback(r.Context())
			if e != nil || observed.State != "publishing" || observed.Attempts != 1 || observed.Fence != 1 {
				t.Error("stage bytes left before durable publishing intent/fence")
				w.WriteHeader(500)
				return
			}
			if r.URL.Path != stage || r.Header.Get("If-None-Match") != "*" || files[stage] != nil {
				w.WriteHeader(412)
				return
			}
			body, e := io.ReadAll(io.LimitReader(r.Body, int64(len(data))+1))
			if e != nil || !bytes.Equal(body, data) {
				w.WriteHeader(400)
				return
			}
			files[stage] = body
			writes++
			w.WriteHeader(201)
		case "GET":
			reads++
			body, ok := files[r.URL.Path]
			if !ok {
				w.WriteHeader(404)
				return
			}
			w.Header().Set("ETag", etag)
			w.Write(body)
		case "MOVE":
			u, e := url.Parse(r.Header.Get("Destination"))
			if e != nil || u.Scheme != "https" || u.Host != r.Host || u.Path != final || r.URL.Path != stage || r.Header.Get("If-Match") != etag || r.Header.Get("Overwrite") != "F" || files[stage] == nil || files[final] != nil {
				w.WriteHeader(412)
				return
			}
			files[final] = files[stage]
			delete(files, stage)
			writes++
			connection, _, e := w.(http.Hijacker).Hijack()
			if e != nil {
				t.Error("actual response loss fixture failed")
				return
			}
			connection.Close()
		default:
			w.WriteHeader(405)
		}
	}))
	defer server.Close()
	ca, err := secure.NativeProofCertificatePEM(server.Certificate().Raw)
	if err != nil {
		t.Fatal(err)
	}
	caRef := filepath.Join(private, "receiver-ca.pem")
	if err = os.WriteFile(caRef, ca, 0600); err != nil {
		t.Fatal(err)
	}
	definition := delivery.DAVDefinition{Destination: secure.HTTPSReadDestination{Address: strings.TrimPrefix(server.URL, "https://"), ServerName: "example.com", CAFile: caRef, CASHA256: secure.Digest(ca), TokenFile: tokenRef, TokenSHA256: secure.Digest(credential.Bytes)}, StagingDirectory: "/stage", ReceiverContract: store.DAVReceiverContract{Schema: 1, DocumentSHA256: secure.Digest([]byte("test-only stand-in private-stage/exclusive-create/source-ETag-no-overwrite/delivery-ID-deduplication/exact-readback contract")), StagingVisibility: "receiver-private", Put: "exclusive-create", Move: "source-etag-no-overwrite", Duplicates: "receiver-deduplicates-delivery-id", Receipt: "exact-readback"}}
	sender := &delivery.Service{Custody: consumer}
	created, err := sender.Create(t.Context(), scope, "dav-recovery-create", delivery.Request{FileID: file.ID, Directory: "/inbox", Filename: "input.dat", DAV: &definition})
	if err != nil {
		t.Fatal(err)
	}
	intent.Store(created.Delivery)
	queued, err := sender.Command(t.Context(), scope, created.Delivery.ID, "dav-recovery-queue", "approve", created.Delivery.DefinitionHash, created.Delivery.Revision)
	if err != nil {
		t.Fatal(err)
	}
	worked, err := sender.Work(t.Context(), scope, queued.Delivery.ID)
	if err != nil || worked.State != "ambiguous" || worked.Attempts != 1 || worked.Fence != 1 {
		t.Fatal("lost actual MOVE reply did not preserve one ambiguous attempt", err)
	}
	again, err := sender.Work(t.Context(), scope, worked.ID)
	if err != nil || again.State != "ambiguous" || again.Attempts != 1 || again.Fence != 1 {
		t.Fatal("ambiguous publication automatically restarted", err)
	}
	reconciled, err := sender.Reconcile(t.Context(), scope, worked.ID)
	if err != nil || reconciled.State != "succeeded" || reconciled.Attempts != 1 || reconciled.Fence != 1 {
		t.Fatal("exact read-only reconciliation failed", err)
	}
	var receipt map[string]any
	if json.Unmarshal(reconciled.Observation, &receipt) != nil || receipt["reconciled"] != true || receipt["move_acknowledged"] != false || receipt["upload_completion_acknowledged"] != false || receipt["business_acceptance"] != "unknown" || receipt["file_fsync_acknowledged"] != false {
		t.Fatal("reconciliation invented lost acknowledgements or acceptance")
	}
	mu.Lock()
	defer mu.Unlock()
	if writes != 2 || reads != 2 || len(files) != 1 || !bytes.Equal(files["/inbox/"+worked.ID+"-input.dat"], data) {
		t.Fatal("reconciliation repeated effects or changed exact receiver bytes")
	}
	t.Logf("actual PostgreSQL/TLS stand-in loss/recovery candidate=%s;content-SHA256=%s;attempt=1;fence=1;writes=2;read-only-reconciliation=true;independent-vendor-qualification=false", peer.Commit, secure.Digest(data))
}
