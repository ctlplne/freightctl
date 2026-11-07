//go:build integration

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

type exchangeProcessFixture struct {
	DB             *store.Store
	Administrator  store.Scope
	DSN            string
	Storage        string
	SenderToken    string
	RecipientToken string
	OtherToken     string
	AdminToken     string
	SenderActor    string
	Recipient      string
	Request        store.ExchangeRequest
	Payload        []byte
}

// Native CI only: real executable,PG,storage,TLS and stock curl. The one-purpose
// proxy drops a real committed response;it cannot manufacture an app receipt.
func qualifyExchangeProcessRecovery(t *testing.T, ctx context.Context, f exchangeProcessFixture) {
	t.Helper()
	work := filepath.Join(t.TempDir(), "freightctl-exchange-recovery")
	if err := os.Mkdir(work, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(work, "freightctl")
	loggedCommand := func(name string, args ...string) {
		t.Helper()
		log, err := os.OpenFile(filepath.Join(work, name+".log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.CommandContext(ctx, args[0], args[1:]...)
		cmd.Dir = root
		cmd.Stdout = log
		cmd.Stderr = log
		err = cmd.Run()
		closeErr := log.Close()
		if err != nil || closeErr != nil {
			t.Fatal("native command failed;protected log retained", name, err, closeErr)
		}
	}
	loggedCommand("build", "sh", "scripts/go.sh", "build", "-trimpath", "-buildvcs=false", "-o", binary, "./cmd/freightctl")
	binaryBytes, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	binaryHash := secure.Digest(binaryBytes)
	binaryBytes = nil
	git := exec.CommandContext(ctx, "git", "rev-parse", "HEAD")
	git.Dir = root
	commitBytes, err := git.Output()
	sourceCommit := strings.TrimSpace(string(commitBytes))
	if err != nil || len(sourceCommit) != 40 {
		t.Fatal("native source commit identity missing", err)
	}
	cert, key := filepath.Join(work, "localhost.crt"), filepath.Join(work, "localhost.key")
	loggedCommand("certificate", binary, "dev-cert", "--cert", cert, "--key", key)
	clientTLS, serverTLS, err := secure.NativeProofTLS(cert, key)
	if err != nil {
		t.Fatal("native TLS proof configuration", err)
	}
	client := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: clientTLS, DisableKeepAlives: true}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	origin := "https://" + address
	prefix := "/v1/tenants/" + f.Administrator.Tenant + "/partners/" + f.Administrator.Partner
	credential := func(ref string) *secure.Secret {
		t.Helper()
		s, err := secure.ReadSecret(ref, 64)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(s.Close)
		return s
	}
	sender, receiver, unrelated, owner := credential(f.SenderToken), credential(f.RecipientToken), credential(f.OtherToken), credential(f.AdminToken)
	call := func(method, base, route, key string, token *secure.Secret, body []byte, headers map[string]string) (*http.Response, error) {
		r, err := http.NewRequestWithContext(ctx, method, base+prefix+route, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		r.Header.Set("Authorization", "Bearer "+string(token.Bytes))
		if key != "" {
			r.Header.Set("Idempotency-Key", key)
		}
		if len(body) > 0 {
			r.Header.Set("Content-Type", "application/json")
		}
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		return client.Do(r)
	}
	read := func(r *http.Response, err error, expected int) []byte {
		t.Helper()
		if err != nil {
			t.Fatal("actual HTTPS control failed", err)
		}
		defer r.Body.Close()
		b, err := io.ReadAll(io.LimitReader(r.Body, (32<<10)+1))
		if err != nil || len(b) > 32<<10 || r.StatusCode != expected {
			t.Fatal("actual HTTPS status/bound failed", r.StatusCode, expected, err)
		}
		return b
	}
	control := func(method, route, key string, token *secure.Secret, body []byte, expected int) []byte {
		t.Helper()
		r, err := call(method, origin, route, key, token, body, nil)
		return read(r, err, expected)
	}
	encode := func(v any) []byte {
		t.Helper()
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	var child *exec.Cmd
	var childLog *os.File
	var pids []int
	kills := 0
	t.Cleanup(func() {
		if child != nil && child.Process != nil {
			child.Process.Kill()
			child.Wait()
		}
		if childLog != nil {
			childLog.Close()
		}
	})
	start := func() {
		t.Helper()
		if child != nil {
			t.Fatal("refusing to replace live task-owned daemon")
		}
		var err error
		childLog, err = os.OpenFile(filepath.Join(work, "daemon-"+strconv.Itoa(len(pids))+".log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		child = exec.CommandContext(ctx, binary, "serve", "--dsn-file", f.DSN, "--storage", f.Storage, "--listen", address, "--cert", cert, "--key", key, "--max-file-bytes", "1048576", "--max-stored-bytes", "16777216", "--exchange-max-lifetime", "1h", "--exchange-max-endpoints", "16")
		child.Stdout = childLog
		child.Stderr = childLog
		if err = child.Start(); err != nil {
			t.Fatal("native daemon start", err)
		}
		pids = append(pids, child.Process.Pid)
		deadline := time.Now().Add(15 * time.Second)
		for {
			r, err := call("GET", origin, "/identity", "", sender, nil, nil)
			if err == nil {
				read(r, nil, 200)
				return
			}
			if time.Now().After(deadline) || ctx.Err() != nil {
				t.Fatal("actual daemon unavailable;protected log retained")
			}
			time.Sleep(25 * time.Millisecond)
		}
	}
	kill := func() {
		t.Helper()
		if child == nil || child.Process.Kill() != nil {
			t.Fatal("exact task-owned daemon kill failed")
		}
		if err := child.Wait(); err == nil {
			t.Fatal("kill did not terminate process")
		}
		child = nil
		kills++
		if err := childLog.Close(); err != nil {
			t.Fatal(err)
		}
		childLog = nil
	}
	countIntents := func() int {
		t.Helper()
		tx, err := f.DB.Begin(ctx, f.Administrator)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Tx.Rollback(ctx)
		var n int
		if err = tx.Tx.QueryRow(ctx, `SELECT count(*) FROM delivery_intents`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	intentsBefore := countIntents()
	start()
	r, err := call("POST", origin, "/files", "process-source", sender, f.Payload, map[string]string{"Content-Type": "application/octet-stream", "X-File-Size": strconv.Itoa(len(f.Payload)), "X-Content-SHA256": secure.Digest(f.Payload)})
	var accepted struct {
		File       store.File `json:"file"`
		Acceptance string     `json:"acceptance"`
	}
	if json.Unmarshal(read(r, err, 201), &accepted) != nil || !store.ValidID(accepted.File.ID) || accepted.File.Size != int64(len(f.Payload)) || accepted.File.SHA256 != secure.Digest(f.Payload) || accepted.Acceptance != "durable-local-integrity-only" {
		t.Fatal("actual durable acceptance changed bytes")
	}
	storeIdentity, err := os.ReadFile(filepath.Join(f.Storage, ".freightctl-storage-id"))
	if err != nil {
		t.Fatal(err)
	}
	kill()
	start()
	var source store.ExchangeArtifact
	if json.Unmarshal(control("GET", "/exchange-sources/"+accepted.File.ID, "", sender, nil, 200), &source) != nil || source.ID != accepted.File.ID || source.SHA256 != accepted.File.SHA256 {
		t.Fatal("acknowledged source lost after process death")
	}
	request := f.Request
	request.Artifact = store.ExchangeArtifact{ID: accepted.File.ID, Size: accepted.File.Size, SHA256: accepted.File.SHA256, Policy: accepted.File.Policy}
	request.ExpiresAt = time.Now().UTC().Add(10 * time.Minute).Truncate(time.Microsecond)
	limits := store.ExchangeLimits{MaxArtifactBytes: 1 << 20, MaxLifetime: time.Hour, MaxSenders: 16}
	_, expectedHash, err := store.CanonicalExchangeRequest(request, limits)
	if err != nil {
		t.Fatal("invalid frozen process recovery request", err)
	}
	target, _ := url.Parse(origin)
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = &http.Transport{TLSClientConfig: clientTLS, DisableKeepAlives: true}
	type upstreamReceipt struct {
		Result store.ArtifactExchangeResult
		Err    error
	}
	observed := make(chan upstreamReceipt, 1)
	drop := errors.New("task-owned committed-response fault")
	proxy.ModifyResponse = func(response *http.Response) error {
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, (32<<10)+1))
		var receipt store.ArtifactExchangeResult
		if err != nil || response.StatusCode != 201 || len(body) > 32<<10 || json.Unmarshal(body, &receipt) != nil || receipt.Replayed || !store.ValidID(receipt.Exchange.ID) {
			observed <- upstreamReceipt{Err: errors.New("no confirmed new upstream offer")}
		} else {
			observed <- upstreamReceipt{Result: receipt}
		}
		return drop
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, err error) {
		if errors.Is(err, drop) {
			if h, ok := w.(http.Hijacker); ok {
				if conn, _, err := h.Hijack(); err == nil {
					conn.Close()
					return
				}
			}
		}
		http.Error(w, "task-owned transport failure", 502)
	}
	fault := httptest.NewUnstartedServer(proxy)
	fault.TLS = serverTLS
	fault.StartTLS()
	defer fault.Close()
	r, err = call("POST", fault.URL, "/exchanges", "process-original-offer", sender, encode(request), nil)
	if r != nil {
		r.Body.Close()
	}
	if err == nil {
		t.Fatal("committed response reached client despite transport fault")
	}
	var original store.ArtifactExchangeResult
	select {
	case upstream := <-observed:
		if upstream.Err != nil {
			t.Fatal(upstream.Err)
		}
		original = upstream.Result
	case <-ctx.Done():
		t.Fatal("no upstream receipt at response-loss boundary")
	}
	_, observedHash, err := store.CanonicalExchangeRequest(original.Exchange.Request, limits)
	if err != nil || original.Exchange.RequestHash != expectedHash || observedHash != expectedHash || original.Exchange.Sender != f.SenderActor || original.Exchange.Recipient != f.Recipient {
		t.Fatal("upstream changed artifact,request or participants")
	}
	kill()
	start()
	var recovered store.ArtifactExchangeResult
	if json.Unmarshal(control("POST", "/exchanges", "process-original-offer", sender, encode(request), 200), &recovered) != nil || !recovered.Replayed || recovered.Exchange.ID != original.Exchange.ID || recovered.Exchange.EventID != original.Exchange.EventID || recovered.Exchange.RequestHash != original.Exchange.RequestHash {
		t.Fatal("restart changed original offer receipt")
	}
	changed := request
	changed.Artifact.Size++
	control("POST", "/exchanges", "process-original-offer", sender, encode(changed), 409)
	var page store.ArtifactExchangePage
	if json.Unmarshal(control("GET", "/exchange-endpoints/"+request.Endpoint.ID+"/incoming", "", receiver, nil, 200), &page) != nil || len(page.Exchanges) != 1 || page.Exchanges[0].ID != original.Exchange.ID {
		t.Fatal("restart discovery changed identity")
	}
	control("GET", "/exchanges/"+original.Exchange.ID, "", unrelated, nil, 404)
	header := filepath.Join(work, "receiver.headers")
	if err = os.WriteFile(header, append(append([]byte("Authorization: Bearer "), receiver.Bytes...), '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(work, "received.bin")
	curl := exec.CommandContext(ctx, "curl", "--silent", "--show-error", "--noproxy", "*", "--cacert", cert, "--max-time", "15", "--header", "@"+header, "--output", output, "--write-out", "%{http_code}", origin+prefix+"/exchanges/"+original.Exchange.ID+"/file")
	status, err := curl.Output()
	if err != nil || string(status) != "200" {
		t.Fatal("stock curl retrieval failed", err)
	}
	actual, err := os.ReadFile(output)
	if err != nil || !bytes.Equal(actual, f.Payload) || secure.Digest(actual) != accepted.File.SHA256 {
		t.Fatal("independent stock receiver bytes differ", err)
	}
	control("POST", "/exchanges", "receive-is-not-forwarding", receiver, encode(request), 403)
	account, err := f.DB.Account(ctx, f.Administrator, f.Recipient)
	if err != nil {
		t.Fatal(err)
	}
	policy := account.AccountPolicy
	policy.Permissions = []string{"list"}
	control("POST", "/accounts/commands", "process-revoke-read", owner, encode(store.AccountCommand{Operation: "update", ID: f.Recipient, ExpectedRevision: account.Revision, Policy: &policy}), 200)
	kill()
	start()
	control("GET", "/exchanges/"+original.Exchange.ID, "", receiver, nil, 403)
	control("GET", "/exchanges/"+original.Exchange.ID+"/file", "", receiver, nil, 403)
	if json.Unmarshal(control("POST", "/exchanges", "process-original-offer", sender, encode(request), 200), &recovered) != nil || !recovered.Replayed || recovered.Exchange.ID != original.Exchange.ID {
		t.Fatal("revocation erased sender original receipt")
	}
	currentStoreIdentity, err := os.ReadFile(filepath.Join(f.Storage, ".freightctl-storage-id"))
	if err != nil || !bytes.Equal(currentStoreIdentity, storeIdentity) || countIntents() != intentsBefore {
		t.Fatal("restart changed custody identity or created onward work")
	}
	tx, err := f.DB.Begin(ctx, f.Administrator)
	if err != nil {
		t.Fatal(err)
	}
	var offers, commands, files int
	const cardinality = `SELECT (SELECT count(*) FROM artifact_exchanges WHERE request_hash=$1),(SELECT count(*) FROM artifact_exchange_commands WHERE request_key='process-original-offer' AND exchange_id=$2),(SELECT count(*) FROM files WHERE file_id=$3)`
	err = tx.Tx.QueryRow(ctx, cardinality, original.Exchange.RequestHash, original.Exchange.ID, accepted.File.ID).Scan(&offers, &commands, &files)
	tx.Tx.Rollback(ctx)
	if err != nil || offers != 0 || commands != 0 || files != 1 {
		t.Fatal("administrator bypassed actor-private exchange journals", err)
	}
	// Count private offers/commands as the actual sender. Root metadata access
	// does not supply another actor's exchange-journal authority.
	senderCredential, err := secure.ReadSecret(f.SenderToken, 64)
	if err != nil {
		t.Fatal("restart sender observation credential unavailable")
	}
	senderScope := store.Scope{Tenant: f.Administrator.Tenant, Partner: f.Administrator.Partner, TokenHash: secure.Digest(senderCredential.Bytes)}
	senderCredential.Close()
	tx, err = f.DB.Begin(ctx, senderScope)
	if err != nil {
		t.Fatal(err)
	}
	if tx.Actor != f.SenderActor {
		tx.Tx.Rollback(ctx)
		t.Fatal("restart observer changed the actual sender")
	}
	err = tx.Tx.QueryRow(ctx, cardinality, original.Exchange.RequestHash, original.Exchange.ID, accepted.File.ID).Scan(&offers, &commands, &files)
	tx.Tx.Rollback(ctx)
	if err != nil || offers != 1 || commands != 1 || files != 1 || kills != 3 || len(pids) != 4 {
		t.Fatal("native restart acceptance/offer/receipt cardinality", err, offers, commands, files, kills, len(pids))
	}
	for i := 1; i < len(pids); i++ {
		if pids[i] == pids[i-1] {
			t.Fatal("daemon process instance did not change")
		}
	}
	evidence := map[string]any{"kind": "native-artifact-exchange-process-recovery", "state": "passed", "binary_sha256": binaryHash, "artifact_sha256": accepted.File.SHA256, "size_bytes": len(f.Payload), "file_id": accepted.File.ID, "exchange_id": original.Exchange.ID, "request_hash": original.Exchange.RequestHash, "starts": len(pids), "process_kills": kills, "committed_response_dropped": true, "original_receipt_recovered": true, "independent_receiver": "stock-curl-exact-bytes", "revocation_survives_restart": true, "extra_delivery_intents": 0, "receiver_persistence": "unknown", "business_processing": "unknown"}
	evidence["source_commit"] = sourceCommit
	encoded, _ := json.Marshal(evidence)
	t.Log(string(encoded))
}
