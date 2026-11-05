//go:build integration

package api

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func TestOnwardHTTPSUsesOrdinaryReviewAtomicStartAndPrivateReceipt(t *testing.T) {
	service, scope, credential, server := browserAPI(t, 600*time.Second)
	cookie, csrf := loginBrowser(t, server, scope, credential)
	prefix := "/v1/tenants/" + scope.Tenant + "/partners/" + scope.Partner
	directory := t.TempDir()
	host, hostPub := filepath.Join(directory, "host"), filepath.Join(directory, "host.pub")
	key, keyPub := filepath.Join(directory, "key"), filepath.Join(directory, "key.pub")
	if err := secure.GenerateSSHHostIdentity(host, hostPub); err != nil {
		t.Fatal(err)
	}
	if err := secure.GenerateSSHHostIdentity(key, keyPub); err != nil {
		t.Fatal(err)
	}
	wf := &workflow.Service{Custody: service}
	registered, err := wf.RegisterConnection(t.Context(), scope, "onward-api-connection", workflow.ConnectionRequest{Address: "127.0.0.1:9", User: "receiver", Directory: "/inbox", HostPublicFile: hostPub, KeyFile: key, KeyPublicFile: keyPub})
	if err != nil {
		t.Fatal(err)
	}
	var connection workflow.ConnectionView
	if json.Unmarshal(registered.Resource, &connection) != nil {
		t.Fatal("connection response")
	}
	headers := map[string]string{"Origin": server.URL, "X-CSRF-Token": csrf, "Idempotency-Key": "onward-api-draft"}
	draft := workflow.DraftRequest{Definition: workflow.Definition{Schema: 1, Name: "Reviewed onward API", Steps: []workflow.Step{{ID: "send", Kind: "sftp.deliver", Connection: workflow.Reference{ID: connection.ID, Version: connection.Version, Hash: connection.Hash}, Filename: "onward.bin"}}}}
	_, raw := exchangeAPIRequest(t, server, "POST", prefix+"/workflows/drafts", cookie, headers, exchangeAPIJSON(t, draft), 200)
	var result workflow.Result
	var config store.Configuration
	if json.Unmarshal(raw, &result) != nil || json.Unmarshal(result.Resource, &config) != nil {
		t.Fatal("draft response")
	}
	headers["Idempotency-Key"] = "onward-api-approve"
	exchangeAPIRequest(t, server, "POST", prefix+"/workflows/"+config.ID+"/1/approve", cookie, headers, exchangeAPIJSON(t, workflow.Decision{Hash: config.Hash, Revision: config.Revision}), 200)
	payload := []byte("approved onward bytes\n")
	file, _, err := service.Accept(t.Context(), scope, "onward-api-source", int64(len(payload)), secure.Digest(payload), bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	request := workflow.OnwardRequest{Schema: 1, Profile: workflow.OnwardProfile, Workflow: workflow.Reference{ID: config.ID, Version: config.Version, Hash: config.Hash}, Artifact: store.ExchangeArtifact{ID: file.ID, Size: file.Size, SHA256: file.SHA256, Policy: file.Policy}}
	_, raw = exchangeAPIRequest(t, server, "POST", prefix+"/onward/previews", cookie, headers, exchangeAPIJSON(t, request), 200)
	var review workflow.OnwardReview
	if json.Unmarshal(raw, &review) != nil || review.ExternalContact || len(review.Effects) != 1 || review.ReceiverPersistence != "unknown" {
		t.Fatal("review response overstated effects")
	}
	original := workflow.OnwardStart{Request: request, ReviewHash: review.ReviewHash}
	wrong := original
	wrong.ReviewHash = strings.Repeat("f", 64)
	if wrong.ReviewHash == original.ReviewHash {
		wrong.ReviewHash = strings.Repeat("e", 64)
	}
	headers["Idempotency-Key"] = "onward-api-original"
	exchangeAPIRequest(t, server, "POST", prefix+"/onward/runs", cookie, headers, exchangeAPIJSON(t, wrong), 409)
	_, first := exchangeAPIRequest(t, server, "POST", prefix+"/onward/runs", cookie, headers, exchangeAPIJSON(t, original), 200)
	if json.Unmarshal(first, &result) != nil || result.Replayed {
		t.Fatal("first result")
	}
	accepted := string(result.Resource)
	_, raw = exchangeAPIRequest(t, server, "POST", prefix+"/onward/receipts", cookie, headers, exchangeAPIJSON(t, workflow.OnwardLookup{Start: original, ReceiptKey: "onward-api-original"}), 200)
	if json.Unmarshal(raw, &result) != nil || !result.Replayed || string(result.Resource) != accepted {
		t.Fatal("receipt lookup changed original run")
	}
	_, raw = exchangeAPIRequest(t, server, "POST", prefix+"/onward/runs", cookie, headers, exchangeAPIJSON(t, original), 200)
	if json.Unmarshal(raw, &result) != nil || !result.Replayed || string(result.Resource) != accepted {
		t.Fatal("exact start retry staged new work")
	}
	var runs, intents int
	tx, err := service.DB.Begin(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Tx.Rollback(t.Context())
	if err = tx.Tx.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM workflow_runs),(SELECT count(*) FROM delivery_intents)`).Scan(&runs, &intents); err != nil || runs != 1 || intents != 1 {
		t.Fatal("HTTP retries changed atomic run/intent counts")
	}
}
