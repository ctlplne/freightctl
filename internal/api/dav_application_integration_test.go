//go:build integration && davpeer

package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestDAVApplicationNativeStockRcloneExactBytesConditionsAndRevocation(t *testing.T) {
	peer := loadNativeDAVStockPeer(t)
	binary, commit := peer.Binary, peer.Commit
	service, scope, admin, server := browserAPI(t, 10*time.Minute)
	cookie, csrf := loginBrowser(t, server, scope, admin)
	prefix := "/v1/tenants/" + scope.Tenant + "/partners/" + scope.Partner
	writer, participant := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "list", "write"})
	reader, _ := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "list"})
	mode := uint32(0770)
	if _, err := service.PathCommand(t.Context(), scope, "dav-app-parent", store.PathCommand{Operation: "mkdir", Path: "/application", Mode: &mode}); err != nil {
		t.Fatal(err)
	}
	sourceName := "source café #.dat"
	sourcePath := "/application/" + sourceName
	data := bytes.Repeat([]byte("inert independent DAV application bytes; no forwarding or execution authority\n"), 2000)
	source, _, err := service.AcceptAt(t.Context(), scope, "dav-app-source", int64(len(data)), secure.Digest(data), bytes.NewReader(data), custody.UploadTarget{Path: sourcePath})
	if err != nil {
		t.Fatal(err)
	}
	privateMode := uint32(0600)
	if _, _, err = service.AcceptAt(t.Context(), scope, "dav-app-private", 7, secure.Digest([]byte("private")), strings.NewReader("private"), custody.UploadTarget{Path: "/application/private.dat", Mode: &privateMode}); err != nil {
		t.Fatal(err)
	}
	private := filepath.Join(peer.PrivateDirectory, "protocol")
	if err = os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	ca, err := secure.NativeProofCertificatePEM(server.Certificate().Raw)
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(private, "ca.pem")
	if err = os.WriteFile(caPath, ca, 0600); err != nil {
		t.Fatal(err)
	}
	config := func(name string, token *secure.Secret) string {
		t.Helper()
		path := filepath.Join(private, name+".conf")
		value := "[freightctl]\ntype = webdav\nvendor = other\nurl = " + server.URL + prefix + "/dav/application/\nauth_redirect = false\nbearer_token = " + string(token.Bytes) + "\n"
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal("protected stock client configuration failed")
		}
		return path
	}
	writerConfig, readerConfig := config("writer", writer), config("reader", reader)
	var proofSteps []map[string]any
	run := func(phase, configuration string, success bool, args ...string) []byte {
		t.Helper()
		outputPath, logPath := filepath.Join(private, phase+".stdout"), filepath.Join(private, phase+".stderr")
		output, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal("unique stock client output unavailable")
		}
		log, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			output.Close()
			t.Fatal("unique stock client log unavailable")
		}
		base := []string{"--config", configuration, "--ca-cert", caPath, "--cache-dir", filepath.Join(private, "cache"), "--temp-dir", private, "--ask-password=false", "--stats", "0", "--log-level", "ERROR"}
		command := exec.CommandContext(t.Context(), binary, append(base, args...)...)
		command.Env = davApplicationEnvironment(os.Environ())
		command.Stdout, command.Stderr = output, log
		err = command.Run()
		output.Close()
		log.Close()
		code := 0
		if err != nil {
			var exit *exec.ExitError
			if !errors.As(err, &exit) {
				t.Fatal("stock application did not execute")
			}
			code = exit.ExitCode()
		}
		outRaw, outErr := os.ReadFile(outputPath)
		logRaw, logErr := os.ReadFile(logPath)
		if outErr != nil || logErr != nil {
			t.Fatal("stock application evidence unavailable")
		}
		proofSteps = append(proofSteps, map[string]any{"phase": phase, "exit_code": code, "stdout_sha256": secure.Digest(outRaw), "stderr_sha256": secure.Digest(logRaw)})
		stepRaw, encodeErr := json.Marshal(proofSteps[len(proofSteps)-1])
		if encodeErr != nil {
			t.Fatal("stock application safe step encoding failed")
		}
		t.Logf("independent DAV original operation %s", stepRaw)
		if (err == nil) != success {
			t.Fatalf("independent DAV application outcome differs;phase=%s;exit=%d;private-stderr-SHA256=%s", phase, code, secure.Digest(logRaw))
		}
		return outRaw
	}
	// Reads and refused client cleanup/mutations must not emit hidden effects.
	type counts struct{ Events, Files, Paths, Commands, Intents, Runs int }
	snapshot := func() counts {
		t.Helper()
		tx, err := service.DB.Begin(t.Context(), scope)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Tx.Rollback(t.Context())
		var c counts
		if err = tx.Tx.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM events),(SELECT count(*) FROM files),(SELECT count(*) FROM namespace_entries),(SELECT count(*) FROM namespace_commands),(SELECT count(*) FROM delivery_intents),(SELECT count(*) FROM workflow_runs)`).Scan(&c.Events, &c.Files, &c.Paths, &c.Commands, &c.Intents, &c.Runs); err != nil {
			t.Fatal("independent client no-effects counters unavailable")
		}
		return c
	}
	before := snapshot()
	raw := run("discovery", writerConfig, true, "lsjson", "freightctl:")
	var entries []struct {
		Path  string
		Name  string
		Size  int64
		IsDir bool
	}
	if json.Unmarshal(raw, &entries) != nil || len(entries) != 1 || entries[0].Path != sourceName || entries[0].Name != sourceName || entries[0].IsDir || entries[0].Size != source.Size {
		t.Fatal("independent DAV discovery lost exact Unicode/escaped name,size or path privacy")
	}
	download := filepath.Join(private, "download.dat")
	run("download", writerConfig, true, "copyto", "freightctl:"+sourceName, download)
	received, err := os.ReadFile(download)
	if err != nil || !bytes.Equal(received, data) || secure.Digest(received) != source.SHA256 {
		t.Fatal("independent application downloaded different immutable bytes")
	}
	run("private-refused", writerConfig, false, "copyto", "freightctl:private.dat", filepath.Join(private, "private-refused.dat"))
	if _, err = os.Stat(filepath.Join(private, "private-refused.dat")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("private child bytes escaped to the independent application")
	}
	upload := filepath.Join(private, "upload.dat")
	if err = os.WriteFile(upload, data, 0600); err != nil {
		t.Fatal(err)
	}
	put := func(key, target string) []string {
		return []string{"--header", "Idempotency-Key: " + key, "--header-upload", "If-None-Match: *", "--header-upload", "X-Content-SHA256: " + secure.Digest(data), "copyto", "--no-check-dest", upload, "freightctl:" + target}
	}
	run("write-authority-refused", readerConfig, false, put("dav-app-no-write", "reader-refused.dat")...)
	if snapshot() != before {
		t.Fatal("stock application reads or denied write/cleanup emitted a durable effect")
	}
	run("conditional-create", writerConfig, true, put("dav-app-create", "created.dat")...)
	current, err := service.StatPath(t.Context(), scope, "/application/created.dat")
	if err != nil || current.FileID == source.ID || current.Size != int64(len(data)) {
		t.Fatal("stock application did not publish one new exact custody revision")
	}
	_, accepted := exchangeAPIRequest(t, server, http.MethodGet, prefix+"/files/"+current.FileID, nil, map[string]string{"Authorization": "Bearer " + string(writer.Bytes)}, nil, 200)
	if !bytes.Equal(accepted, data) {
		t.Fatal("independent API read disagrees with stock application upload bytes")
	}
	after := snapshot()
	if after.Events != before.Events+3 || after.Files != before.Files+1 || after.Paths != before.Paths+1 || after.Commands != before.Commands+1 || after.Intents != before.Intents || after.Runs != before.Runs {
		t.Fatal("stock upload did not have exactly one custody/mapping outcome or gained onward execution")
	}
	run("conditional-retry-refused", writerConfig, false, put("dav-app-create", "created.dat")...)
	run("new-key-overwrite-refused", writerConfig, false, put("dav-app-create-other", "created.dat")...)
	stable, err := service.StatPath(t.Context(), scope, current.Path)
	if err != nil || stable.ID != current.ID || stable.FileID != current.FileID || stable.Revision != current.Revision || snapshot() != after {
		t.Fatal("stock application's retry or failed-upload cleanup changed a committed revision")
	}
	createdDownload := filepath.Join(private, "created-download.dat")
	run("created-download", writerConfig, true, "copyto", "freightctl:created.dat", createdDownload)
	readback, err := os.ReadFile(createdDownload)
	if err != nil || !bytes.Equal(readback, data) || secure.Digest(readback) != source.SHA256 || snapshot() != after {
		t.Fatal("stock application's exact readback differs or gained another effect")
	}
	exchangeAPIRequest(t, server, http.MethodPost, prefix+"/accounts/commands", cookie, map[string]string{"Origin": server.URL, "X-CSRF-Token": csrf, "Idempotency-Key": "dav-app-revoke"}, exchangeAPIJSON(t, store.AccountCommand{Operation: "revoke", ID: participant.Actor, ExpectedRevision: 1}), 200)
	revoked := snapshot()
	run("revoked-discovery", writerConfig, false, "lsjson", "freightctl:")
	run("revoked-download", writerConfig, false, "copyto", "freightctl:created.dat", filepath.Join(private, "revoked.dat"))
	if _, err = os.Stat(filepath.Join(private, "revoked.dat")); !errors.Is(err, os.ErrNotExist) || snapshot() != revoked {
		t.Fatal("revoked application retained byte access or produced a durable effect")
	}
	proof := map[string]any{"profile": "stock-rclone-webdav-v1", "candidate": commit, "architecture": runtime.GOARCH, "acquisition_manifest_sha256": peer.ManifestSHA256, "binary_sha256": peer.BinarySHA256, "source_bytes": strconv.Itoa(len(data)), "content_sha256": source.SHA256, "steps": proofSteps, "protocol_scope": "scoped discovery,exact read,conditional create,refused overwrite/cleanup,path privacy and credential revocation;no full DAV,locks,outbound or business acceptance claim"}
	encoded, err := json.Marshal(proof)
	if err != nil {
		t.Fatal("independent application proof encoding failed")
	}
	// Only the bounded safe manifest is public. Config,credentials,client output
	// and inert byte files stay in the exact private task directory.
	t.Logf("independent DAV native proof %s", encoded)
}
