//go:build integration && davpeer

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/delivery"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func startNativeDAVBasicSource(t *testing.T, peer nativeDAVStockPeer, data, manifest []byte) (secure.HTTPSReadDestination, string) {
	return startNativeDAVBasicPeer(t, peer, data, manifest, false)
}

func startNativeDAVBasicPeer(t *testing.T, peer nativeDAVStockPeer, data, manifest []byte, receiver bool) (secure.HTTPSReadDestination, string) {
	t.Helper()
	name, user := "basic-source", "source-reader"
	if receiver {
		name, user = "delivery-receiver", "delivery-writer"
	}
	private := filepath.Join(peer.PrivateDirectory, name)
	root := filepath.Join(private, "root")
	if err := os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	if receiver {
		for _, name := range []string{"stage", "inbox"} {
			if err := os.Mkdir(filepath.Join(root, name), 0700); err != nil {
				t.Fatal(err)
			}
		}
	}
	// Publish immutable payload first and the ready manifest last,with exact
	// task-owned durable fixture files;the source profile stays read-only.
	for _, f := range []struct {
		name string
		body []byte
	}{{"input.dat", data}, {"batch.ready.json", manifest}} {
		file, err := os.OpenFile(filepath.Join(root, f.name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
		if err != nil {
			t.Fatal(err)
		}
		_, writeErr := file.Write(f.body)
		syncErr, closeErr := file.Sync(), file.Close()
		if writeErr != nil || syncErr != nil || closeErr != nil {
			t.Fatal("independent source fixture persistence failed")
		}
	}
	dir, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	err = dir.Sync()
	dir.Close()
	if err != nil {
		t.Fatal(err)
	}
	caRef, keyRef, passwordRef := filepath.Join(private, "ca.pem"), filepath.Join(private, "tls.key"), filepath.Join(private, "password")
	if err = secure.DevCertificate(caRef, keyRef); err != nil {
		t.Fatal(err)
	}
	if err = secure.WriteToken(passwordRef); err != nil {
		t.Fatal(err)
	}
	password, err := secure.ReadSecret(passwordRef, 64)
	if err != nil {
		t.Fatal(err)
	}
	defer password.Close()
	users, err := secure.NativeProofHTPasswd(user, password)
	if err != nil {
		t.Fatal(err)
	}
	usersRef, config := filepath.Join(private, "users.htpasswd"), filepath.Join(private, "empty.conf")
	if err = os.WriteFile(usersRef, users.Bytes, 0600); err != nil {
		users.Close()
		t.Fatal(err)
	}
	users.Close()
	if err = os.WriteFile(config, nil, 0600); err != nil {
		t.Fatal(err)
	}
	ca, err := secure.ReadSecret(caRef, 128<<10)
	if err != nil {
		t.Fatal(err)
	}
	defer ca.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	destination := secure.HTTPSReadDestination{Address: address, ServerName: "localhost", CAFile: caRef, CASHA256: secure.Digest(ca.Bytes), Authentication: "basic", User: user, PasswordFile: passwordRef, PasswordSHA256: secure.Digest(password.Bytes)}
	logPath := filepath.Join(private, "server.log")
	log, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"--config", config, "--cache-dir", filepath.Join(private, "cache"), "--temp-dir", private, "--ask-password=false", "--stats", "0", "--log-level", "ERROR", "serve", "webdav", root, "--addr", "tls://" + address, "--cert", caRef, "--key", keyRef, "--min-tls-version", "tls1.3", "--htpasswd", usersRef}
	if !receiver {
		args = append(args, "--read-only")
	}
	args = append(args, "--baseurl", "/dav")
	command := exec.Command(peer.Binary, args...)
	command.Env = davApplicationEnvironment(os.Environ())
	// Preserve the runner's HOME value for stock service initialization;never
	// repurpose it. Explicit empty config/cache/temp paths supply all peer state.
	// No proxy,RCLONE_* setting or cloud credential environment is inherited.
	if value, ok := os.LookupEnv("HOME"); ok {
		command.Env = append(command.Env, "HOME="+value)
	}
	command.Dir, command.Stdout, command.Stderr = private, log, log
	if err = command.Start(); err != nil {
		log.Close()
		t.Fatal("independent stock DAV server did not execute")
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			_ = command.Process.Signal(os.Interrupt)
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				_ = command.Process.Kill()
				<-done
			}
			log.Close()
			raw, err := os.ReadFile(logPath)
			if err != nil {
				t.Error("closed stock DAV server evidence unavailable")
				return
			}
			t.Logf("closed independent DAV server log SHA256=%s;binary-SHA256=%s;candidate=%s", secure.Digest(raw), peer.BinarySHA256, peer.Commit)
		})
	}
	t.Cleanup(stop)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		client, err := secure.NewHTTPSReadClient(ctx, destination, func() error { return nil })
		if err == nil {
			response, readErr := client.Get(ctx, "/dav/batch.ready.json")
			if readErr == nil {
				body, bodyErr := io.ReadAll(io.LimitReader(response.Body, (32<<10)+1))
				response.Body.Close()
				if bodyErr == nil && response.StatusCode == 200 && bytes.Equal(body, manifest) {
					client.Close()
					cancel()
					return destination, root
				}
			}
			client.Close()
		}
		cancel()
		time.Sleep(25 * time.Millisecond)
	}
	stop()
	t.Fatal("independent stock DAV server readiness failed;closed private log hash retained")
	return secure.HTTPSReadDestination{}, ""
}

func TestDAVBasicSourceNativeStockServerCapturesExactReadOnlyCustody(t *testing.T) {
	peer := loadNativeDAVStockPeer(t)
	data := bytes.Repeat([]byte("independent upstream DAV source;no execution or onward authority\n"), 2000)
	manifest := exchangeAPIJSON(t, workflow.CollectionManifest{Schema: 1, Batch: secure.NewID(), Files: []workflow.CollectionFile{{Name: "input.dat", Size: int64(len(data)), SHA256: secure.Digest(data)}}})
	destination, sourceRoot := startNativeDAVBasicSource(t, peer, data, manifest)
	consumer, scope, token, httpServer := browserAPI(t, 10*time.Minute)
	if _, err := consumer.PathCommand(t.Context(), scope, "basic-dav-inbox", store.PathCommand{Operation: "mkdir", Path: "/inbox"}); err != nil {
		t.Fatal(err)
	}
	engine := &workflow.Service{Custody: consumer}
	registered, err := engine.RegisterConnection(t.Context(), scope, "basic-dav-register", workflow.ConnectionRequest{Directory: "/dav", DAV: &delivery.DAVCollectionSource{Schema: 2, Destination: destination}})
	if err != nil {
		t.Fatal(err)
	}
	var connection workflow.ConnectionView
	if json.Unmarshal(registered.Resource, &connection) != nil || connection.DAV == nil || connection.DAV.Authentication != "basic" || !connection.DAV.ReadOnly {
		t.Fatal("independent DAV source registration invalid")
	}
	shapeTx, err := consumer.DB.Begin(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	configured, err := shapeTx.Configuration(t.Context(), true, connection.ID, connection.Version, false)
	if err != nil {
		shapeTx.Tx.Rollback(t.Context())
		t.Fatal(err)
	}
	var basic, bearer bool
	if err = shapeTx.Tx.QueryRow(t.Context(), `SELECT freightctl_dav_collection_connection($1::jsonb),freightctl_bearer_dav_collection_connection($1::jsonb)`, configured.Definition).Scan(&basic, &bearer); err != nil || !basic || bearer {
		shapeTx.Tx.Rollback(t.Context())
		t.Fatal("actual SQL mixed Basic and legacy bearer connection profiles", err)
	}
	for _, change := range []func(map[string]any){
		func(d map[string]any) { d["dav"].(map[string]any)["schema_version"] = 1 },
		func(d map[string]any) {
			d["dav"].(map[string]any)["destination"].(map[string]any)["authentication"] = "bearer"
		},
		func(d map[string]any) { d["dav"].(map[string]any)["destination"].(map[string]any)["user"] = "bad:user" },
		func(d map[string]any) {
			d["dav"].(map[string]any)["destination"].(map[string]any)["token_reference"] = "/mixed/token"
		},
	} {
		var altered map[string]any
		if json.Unmarshal(configured.Definition, &altered) != nil {
			t.Fatal("stored Basic definition invalid")
		}
		change(altered)
		if err = shapeTx.Tx.QueryRow(t.Context(), `SELECT freightctl_dav_collection_connection($1::jsonb)`, exchangeAPIJSON(t, altered)).Scan(&basic); err != nil || basic {
			shapeTx.Tx.Rollback(t.Context())
			t.Fatal("SQL admitted a mixed or aliased Basic source credential", err)
		}
	}
	shapeTx.Tx.Rollback(t.Context())
	source := &workflow.CollectionSource{Kind: "webdav.collect", Connection: workflow.Reference{ID: connection.ID, Version: connection.Version, Hash: connection.Hash}, Manifest: "batch.ready.json", Directory: "/inbox", Contract: workflow.CollectionContract, MaxFiles: 4, MaxFile: 1 << 20, MaxTotal: 4 << 20}
	drafted, err := engine.Draft(t.Context(), scope, "basic-dav-draft", workflow.DraftRequest{Definition: workflow.Definition{Schema: 1, Name: "Independent read-only DAV source", Steps: []workflow.Step{}, Source: source}})
	if err != nil {
		t.Fatal(err)
	}
	var config store.Configuration
	if json.Unmarshal(drafted.Resource, &config) != nil {
		t.Fatal("DAV workflow draft invalid")
	}
	if _, err = engine.Decide(t.Context(), scope, config.ID, config.Version, "basic-dav-approve", "approve", workflow.Decision{Hash: config.Hash, Revision: config.Revision}); err != nil {
		t.Fatal(err)
	}
	tx, err := consumer.DB.Begin(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	authority := tx.AuthorityRevision
	tx.Tx.Rollback(t.Context())
	prefix := "/v1/tenants/" + scope.Tenant + "/partners/" + scope.Partner
	headers := map[string]string{"Authorization": "Bearer " + string(token.Bytes)}
	selection := workflow.CollectionSelection{Workflow: workflow.Reference{ID: config.ID, Version: config.Version, Hash: config.Hash}, Timeout: 120, Authority: authority}
	_, raw := exchangeAPIRequest(t, httpServer, "POST", prefix+"/workflow-collections/preview", nil, headers, exchangeAPIJSON(t, selection), 200)
	var preview workflow.CollectionPreview
	if json.Unmarshal(raw, &preview) != nil || preview.ExternalContact || !preview.ApprovalRequired || preview.Definition.Connection.DAV == nil || preview.Definition.Connection.DAV.Authentication != "basic" {
		t.Fatal("independent DAV preview invalid")
	}
	for _, secret := range []string{destination.PasswordFile, destination.PasswordSHA256, destination.CAFile, `"password_sha256":`, `"password_reference":`} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("Basic source review exposed credential proof or references")
		}
	}
	headers["Idempotency-Key"] = "basic-dav-admit"
	_, raw = exchangeAPIRequest(t, httpServer, "POST", prefix+"/workflow-collections", nil, headers, exchangeAPIJSON(t, workflow.CollectionStartRequest{Selection: selection, Hash: preview.Hash}), 200)
	var result workflow.Result
	var action workflow.CollectionAction
	if json.Unmarshal(raw, &result) != nil || json.Unmarshal(result.Resource, &action) != nil || !store.ValidID(action.ID) {
		t.Fatal("DAV admission receipt invalid")
	}
	headers["Idempotency-Key"] = "basic-dav-work"
	_, first := exchangeAPIRequest(t, httpServer, "POST", prefix+"/workflow-collections/"+action.ID+"/work", nil, headers, exchangeAPIJSON(t, workflow.CollectionWorkRequest{Hash: action.Hash}), 200)
	view, err := engine.CollectionStatus(t.Context(), scope, action.ID)
	if err != nil || !view.Current || !view.Job.Captured || view.Job.State != "captured" || view.Job.Attempts != 1 || len(view.Inputs) != 1 || view.BusinessAcceptance != "unknown" {
		t.Fatal("independent stock DAV did not capture exact custody", err)
	}
	input := view.Inputs[0]
	file, stream, err := consumer.DownloadPath(t.Context(), scope, input.Target)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(io.LimitReader(stream, int64(len(data))+1))
	stream.Close()
	if err != nil || !bytes.Equal(got, data) || file.SHA256 != secure.Digest(data) || input.FileID == nil || *input.FileID != file.ID {
		t.Fatal("independent stock DAV bytes differ from durable destination")
	}
	for name, want := range map[string][]byte{"input.dat": data, "batch.ready.json": manifest} {
		got, err := os.ReadFile(filepath.Join(sourceRoot, name))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("independent producer bytes changed")
		}
	}
	count, err := consumer.DB.Begin(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	var files, intents, runs int
	err = count.Tx.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM files),(SELECT count(*) FROM delivery_intents),(SELECT count(*) FROM workflow_runs)`).Scan(&files, &intents, &runs)
	count.Tx.Rollback(t.Context())
	if err != nil || files != 1 || intents != 0 || runs != 0 {
		t.Fatal("independent DAV gained unrelated custody or onward effects", err)
	}
	if err = os.Remove(destination.PasswordFile); err != nil {
		t.Fatal(err)
	}
	_, again := exchangeAPIRequest(t, httpServer, "POST", prefix+"/workflow-collections/"+action.ID+"/work", nil, headers, exchangeAPIJSON(t, workflow.CollectionWorkRequest{Hash: action.Hash}), 200)
	var original, replay workflow.Result
	if json.Unmarshal(first, &original) != nil || json.Unmarshal(again, &replay) != nil || !replay.Replayed || !bytes.Equal(original.Resource, replay.Resource) {
		t.Fatal("independent DAV original receipt reopened missing credentials or changed outcome")
	}
	t.Logf("independent DAV source candidate=%s;arch=%s;binary-SHA256=%s;manifest-SHA256=%s;content-SHA256=%s;captured=1;onward=0;business-acceptance=unknown", peer.Commit, runtime.GOARCH, peer.BinarySHA256, peer.ManifestSHA256, secure.Digest(data))
}
