//go:build integration

package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestTusCoreHTTPSUsesCurrentAuthorityStrictOffsetsAndSeparateAcceptance(t *testing.T) {
	_, scope, admin, server := browserAPI(t, time.Minute)
	cookie, csrf := loginBrowser(t, server, scope, admin)
	prefix := "/v1/tenants/" + scope.Tenant + "/partners/" + scope.Partner
	other, _ := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "write", "list"})
	data := bytes.Repeat([]byte("x"), 2*int(custody.MinUploadChunk)+3)
	mode := uint32(0600)
	_, raw := exchangeAPIRequest(t, server, "POST", prefix+"/uploads", cookie, map[string]string{"Origin": server.URL, "X-CSRF-Token": csrf, "Idempotency-Key": "tus-existing-ticket"}, exchangeAPIJSON(t, custody.CreateUpload{Path: "/tus-owned.dat", Size: int64(len(data)), SHA256: secure.Digest(data), Mode: &mode}), 201)
	var ticket custody.UploadResult
	if json.Unmarshal(raw, &ticket) != nil {
		t.Fatal("ticket response")
	}
	path := prefix + "/tus/uploads/" + ticket.Upload.ID
	base := map[string]string{"Authorization": "Bearer " + string(admin.Bytes), "Tus-Resumable": "1.0.0"}
	response, _ := exchangeAPIRequest(t, server, "HEAD", path, nil, base, nil, 200)
	if response.Header.Get("Upload-Offset") != "0" || response.Header.Get("Upload-Length") != strconv.Itoa(len(data)) || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Tus-Extension") != "" {
		t.Fatal("tus HEAD changed progress or advertised unimplemented extensions")
	}
	exchangeAPIRequest(t, server, "HEAD", path, nil, map[string]string{"Authorization": "Bearer " + string(other.Bytes), "Tus-Resumable": "1.0.0"}, nil, 404)
	chunk := data[:custody.MinUploadChunk]
	appendHeaders := map[string]string{"Authorization": base["Authorization"], "Tus-Resumable": "1.0.0", "Content-Type": "application/offset+octet-stream", "Upload-Offset": "0"}
	response, _ = exchangeAPIRequest(t, server, "PATCH", path, nil, appendHeaders, chunk, 204)
	if response.Header.Get("Upload-Offset") != strconv.Itoa(len(chunk)) || response.Header.Get("X-Freightctl-Acceptance") != "durable-checkpoint-only" {
		t.Fatal("checkpoint claimed whole-file acceptance")
	}
	exchangeAPIRequest(t, server, "PATCH", path, nil, appendHeaders, chunk, 409)
	// The effective method reaches ordinary browser authentication before its
	// mutation/CSRF decision,even if the transport verb is GET.
	override := map[string]string{"Tus-Resumable": "1.0.0", "Content-Type": "application/offset+octet-stream", "Upload-Offset": strconv.Itoa(len(chunk)), "X-HTTP-Method-Override": "PATCH", "Origin": server.URL}
	exchangeAPIRequest(t, server, "GET", path, cookie, override, chunk, 403)
	override["X-CSRF-Token"] = csrf
	// Use actual unknown-length HTTP framing here;the fixed custody chunk bound
	// still applies. The stock Node client may send this framing too.
	request, err := http.NewRequest("GET", server.URL+path, io.NopCloser(bytes.NewReader(chunk)))
	if err != nil {
		t.Fatal(err)
	}
	request.ContentLength = -1
	request.AddCookie(cookie)
	for key, value := range override {
		request.Header.Set(key, value)
	}
	response, err = server.Client().Do(request)
	if err != nil {
		t.Fatal("chunked HTTPS request failed")
	}
	response.Body.Close()
	if response.StatusCode != 204 {
		t.Fatal("chunked method override did not checkpoint", response.StatusCode)
	}
	if response.Header.Get("Upload-Offset") != strconv.Itoa(2*len(chunk)) {
		t.Fatal("method override changed committed offset")
	}
	appendHeaders["Upload-Offset"] = strconv.Itoa(2 * len(chunk))
	exchangeAPIRequest(t, server, "PATCH", path, nil, appendHeaders, data[2*len(chunk):], 204)
	_, raw = exchangeAPIRequest(t, server, "GET", prefix+"/uploads/"+ticket.Upload.ID, nil, map[string]string{"Authorization": base["Authorization"]}, nil, 200)
	var full custody.UploadView
	if json.Unmarshal(raw, &full) != nil || full.State != "open" || full.Offset != int64(len(data)) || full.Chunks != 3 || full.FileID != "" {
		t.Fatal("checkpoint completion published unverified artifact bytes")
	}
	_, raw = exchangeAPIRequest(t, server, "POST", prefix+"/uploads/"+ticket.Upload.ID+"/complete", cookie, map[string]string{"Origin": server.URL, "X-CSRF-Token": csrf, "Idempotency-Key": "ordinary-tus-complete"}, nil, 200)
	var accepted custody.UploadResult
	if json.Unmarshal(raw, &accepted) != nil || accepted.File == nil || accepted.File.SHA256 != ticket.Upload.ExpectedSHA256 || accepted.Upload.Offset != int64(len(data)) {
		t.Fatal("ordinary completion changed whole-file identity")
	}
	_, got := exchangeAPIRequest(t, server, "GET", prefix+"/files/"+accepted.File.ID, nil, map[string]string{"Authorization": base["Authorization"]}, nil, 200)
	if !bytes.Equal(got, data) {
		t.Fatal("independent HTTPS receiver observed different bytes")
	}
	response, _ = exchangeAPIRequest(t, server, "HEAD", path, nil, base, nil, 200)
	if response.Header.Get("Upload-Offset") != strconv.Itoa(len(data)) || response.Header.Get("X-Freightctl-File-Revision") != accepted.File.ID || response.Header.Get("X-Freightctl-Acceptance") != "durable-local-integrity-only" {
		t.Fatal("completed HEAD lost original custody receipt meaning")
	}
}

func TestTusCoreHTTPSCredentialExpiryAndRevocationCannotResumeOrPublish(t *testing.T) {
	service, scope, admin, server := browserAPI(t, time.Minute)
	cookie, csrf := loginBrowser(t, server, scope, admin)
	prefix := "/v1/tenants/" + scope.Tenant + "/partners/" + scope.Partner
	for _, expiry := range []bool{false, true} {
		name := "revoked"
		if expiry {
			name = "expired"
		}
		t.Run(name, func(t *testing.T) {
			credentialPath := filepath.Join(t.TempDir(), "credential")
			if err := secure.WriteToken(credentialPath); err != nil {
				t.Fatal(err)
			}
			token, err := secure.ReadSecret(credentialPath, 64)
			if err != nil {
				t.Fatal(err)
			}
			defer token.Close()
			actor := secure.NewID()
			policy := &store.AccountPolicy{Label: "tus lifecycle participant", Root: "/", Permissions: []string{"read", "write", "list"}}
			var deadline time.Time
			if expiry {
				transaction, err := service.DB.Begin(t.Context(), scope)
				if err != nil {
					t.Fatal(err)
				}
				now, clockErr := transaction.DatabaseTime(t.Context())
				transaction.Tx.Rollback(t.Context())
				if clockErr != nil {
					t.Fatal(clockErr)
				}
				deadline = now.Add(10 * time.Second).Truncate(time.Microsecond)
				policy.ExpiresAt = &deadline
			}
			command := store.AccountCommand{Operation: "create", ID: actor, CredentialHash: secure.Digest(token.Bytes), Policy: policy}
			managementHeaders := map[string]string{"Origin": server.URL, "X-CSRF-Token": csrf, "Idempotency-Key": "tus-actor-" + actor}
			exchangeAPIRequest(t, server, "POST", prefix+"/accounts/commands", cookie, managementHeaders, exchangeAPIJSON(t, command), 200)
			data := bytes.Repeat([]byte("e"), int(custody.MinUploadChunk)+3)
			bearer := "Bearer " + string(token.Bytes)
			_, raw := exchangeAPIRequest(t, server, "POST", prefix+"/uploads", nil, map[string]string{"Authorization": bearer, "Idempotency-Key": "lifecycle-ticket"}, exchangeAPIJSON(t, custody.CreateUpload{Path: "/tus-" + name + ".dat", Size: int64(len(data)), SHA256: secure.Digest(data)}), 201)
			var ticket custody.UploadResult
			if json.Unmarshal(raw, &ticket) != nil || !store.ValidID(ticket.Upload.ID) {
				t.Fatal("lifecycle ticket response")
			}
			path := prefix + "/tus/uploads/" + ticket.Upload.ID
			headers := map[string]string{"Authorization": bearer, "Tus-Resumable": "1.0.0", "Content-Type": "application/offset+octet-stream", "Upload-Offset": "0"}
			exchangeAPIRequest(t, server, "PATCH", path, nil, headers, data[:custody.MinUploadChunk], 204)
			if expiry {
				// Observe the real database clock;do not synthesize an expired
				// response or edit the credential/upload behind ordinary services.
				for {
					transaction, err := service.DB.Begin(t.Context(), scope)
					if err != nil {
						t.Fatal(err)
					}
					now, clockErr := transaction.DatabaseTime(t.Context())
					transaction.Tx.Rollback(t.Context())
					if clockErr != nil {
						t.Fatal(clockErr)
					}
					if !now.Before(deadline) {
						break
					}
					time.Sleep(min(100*time.Millisecond, deadline.Sub(now)))
				}
			} else {
				managementHeaders["Idempotency-Key"] = "tus-revoke-" + actor
				exchangeAPIRequest(t, server, "POST", prefix+"/accounts/commands", cookie, managementHeaders, exchangeAPIJSON(t, store.AccountCommand{Operation: "revoke", ID: actor, ExpectedRevision: 1}), 200)
			}
			headers["Upload-Offset"] = strconv.FormatInt(custody.MinUploadChunk, 10)
			// A still-valid root browser cookie must not rescue an invalid
			// explicit bearer credential or inherit this actor's ticket.
			exchangeAPIRequest(t, server, "HEAD", path, cookie, headers, nil, 401)
			exchangeAPIRequest(t, server, "PATCH", path, cookie, headers, data[custody.MinUploadChunk:], 401)
			exchangeAPIRequest(t, server, "POST", prefix+"/uploads/"+ticket.Upload.ID+"/complete", cookie, map[string]string{"Authorization": bearer, "Idempotency-Key": "cannot-complete"}, nil, 401)
			transaction, err := service.DB.Begin(t.Context(), scope)
			if err != nil {
				t.Fatal(err)
			}
			defer transaction.Tx.Rollback(t.Context())
			var offset int64
			var chunks, accepted int
			var state string
			if err = transaction.Tx.QueryRow(t.Context(), `SELECT committed_offset,chunk_count,state,(SELECT count(*) FROM files f JOIN events e ON (e.tenant_id,e.partner_id,e.event_id)=(f.tenant_id,f.partner_id,f.accepted_event_id) WHERE e.actor_id=$2) FROM upload_sessions WHERE upload_id=$1 AND actor_id=$2 AND file_id IS NULL`, ticket.Upload.ID, actor).Scan(&offset, &chunks, &state, &accepted); err != nil || offset != custody.MinUploadChunk || chunks != 1 || state != "open" || accepted != 0 {
				t.Fatal("denied lifecycle request changed checkpoints or accepted bytes", err)
			}
		})
	}
}
