//go:build integration && tuspeer

package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
)

func TestTusCoreStockClientNativeResumeResponseLossAndOrdinaryVerifiedAcceptance(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "true" || runtime.GOOS != "linux" || (runtime.GOARCH != "arm64" && runtime.GOARCH != "amd64") {
		t.Fatal("stock tus runtime requires its authorized native GitHub Linux environment")
	}
	commitRaw, err := exec.Command("git", "rev-parse", "HEAD").Output()
	commit := strings.TrimSpace(string(commitRaw))
	if err != nil || len(commit) != 40 || strings.Trim(commit, "0123456789abcdef") != "" || commit != os.Getenv("GITHUB_SHA") {
		t.Fatal("native source does not match the actual Actions candidate")
	}
	clientSource, err := os.ReadFile("../../scripts/peers/tus/client.mjs")
	if err != nil {
		t.Fatal(err)
	}
	clientLock, err := os.ReadFile("../../scripts/peers/tus/package-lock.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, override := range []bool{false, true} {
		name := "patch"
		if override {
			name = "method-override"
		}
		t.Run(name, func(t *testing.T) {
			_, scope, token, server := browserAPI(t, 600*time.Second)
			prefix := "/v1/tenants/" + scope.Tenant + "/partners/" + scope.Partner
			data := bytes.Repeat([]byte("inert stock tus payload;do not execute\n"), 4000)
			mode := uint32(0600)
			_, raw := exchangeAPIRequest(t, server, "POST", prefix+"/uploads", nil, map[string]string{"Authorization": "Bearer " + string(token.Bytes), "Idempotency-Key": "stock-tus-existing-ticket"}, exchangeAPIJSON(t, custody.CreateUpload{Path: "/stock-tus.dat", Size: int64(len(data)), SHA256: secure.Digest(data), Mode: &mode}), 201)
			var ticket custody.UploadResult
			if json.Unmarshal(raw, &ticket) != nil {
				t.Fatal("ticket response")
			}
			path := prefix + "/tus/uploads/" + ticket.Upload.ID
			upstream, _ := url.Parse(server.URL)
			proxy := httputil.NewSingleHostReverseProxy(upstream)
			proxy.Transport = server.Client().Transport
			lost := errors.New("selected committed response loss")
			var dropped atomic.Bool
			proxy.ModifyResponse = func(response *http.Response) error {
				if response.Request.URL.Path == path && (response.Request.Method == "PATCH" || response.Request.Method == "POST") && response.StatusCode == 204 && dropped.CompareAndSwap(false, true) {
					return lost
				}
				return nil
			}
			proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
				if errors.Is(err, lost) {
					connection, _, hijackErr := w.(http.Hijacker).Hijack()
					if hijackErr == nil {
						connection.Close()
					}
					return
				}
				http.Error(w, "loopback proxy failure", 502)
			}
			front := httptest.NewTLSServer(proxy)
			defer front.Close()
			private := t.TempDir()
			if err := os.Chmod(private, 0700); err != nil {
				t.Fatal(err)
			}
			credential, payload, result, logPath := filepath.Join(private, "credential"), filepath.Join(private, "payload"), filepath.Join(private, "result.json"), filepath.Join(private, "peer.log")
			if err := os.WriteFile(credential, token.Bytes, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(payload, data, 0600); err != nil {
				t.Fatal(err)
			}
			config := map[string]any{"url": front.URL + path, "token_file": credential, "payload_file": payload, "certificate_der": base64.StdEncoding.EncodeToString(front.Certificate().Raw), "size": len(data), "sha256": secure.Digest(data), "override_patch": override, "expect_lost_response": true, "result_file": result}
			encoded, _ := json.Marshal(config)
			configPath := filepath.Join(private, "config.json")
			if err := os.WriteFile(configPath, encoded, 0600); err != nil {
				t.Fatal(err)
			}
			log, err := os.OpenFile(logPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			command := exec.CommandContext(ctx, "node", "../../scripts/peers/tus/client.mjs", configPath)
			command.Stdout, command.Stderr = log, log
			command.Env = append(os.Environ(), "NODE_USE_ENV_PROXY=0", "HTTP_PROXY=", "HTTPS_PROXY=", "ALL_PROXY=", "NO_PROXY=127.0.0.1")
			err = command.Run()
			log.Close()
			peerRaw, readErr := os.ReadFile(result)
			if err != nil || readErr != nil {
				safeLog, _ := os.ReadFile(logPath)
				t.Fatalf("stock tus peer failed;private log SHA256=%s", secure.Digest(safeLog))
			}
			peer := decodeTusPeerSummary(peerRaw)
			architecture := "x64"
			if runtime.GOARCH == "arm64" {
				architecture = "arm64"
			}
			if peer == nil || peer.State != "passed" || peer.Architecture != architecture || *peer.Offset != int64(len(data)) || *peer.Bytes != int64(len(data)) || peer.SHA != secure.Digest(data) || !dropped.Load() || override && (*peer.Patches != 0 || *peer.Overrides < 3) || !override && (*peer.Overrides != 0 || *peer.Patches < 3) {
				t.Fatal("stock peer did not prove exact native TLS/resume scope")
			}
			_, raw = exchangeAPIRequest(t, server, "GET", prefix+"/uploads/"+ticket.Upload.ID, nil, map[string]string{"Authorization": "Bearer " + string(token.Bytes)}, nil, 200)
			var staged custody.UploadView
			if json.Unmarshal(raw, &staged) != nil || staged.State != "open" || staged.Offset != int64(len(data)) || staged.FileID != "" {
				t.Fatal("stock transport completion claimed accepted artifact")
			}
			_, raw = exchangeAPIRequest(t, server, "POST", prefix+"/uploads/"+ticket.Upload.ID+"/complete", nil, map[string]string{"Authorization": "Bearer " + string(token.Bytes), "Idempotency-Key": "ordinary-stock-completion"}, nil, 200)
			var accepted custody.UploadResult
			if json.Unmarshal(raw, &accepted) != nil || accepted.File == nil || accepted.File.SHA256 != secure.Digest(data) {
				t.Fatal("ordinary whole-file completion changed stock bytes")
			}
			_, received := exchangeAPIRequest(t, server, "GET", prefix+"/files/"+accepted.File.ID, nil, map[string]string{"Authorization": "Bearer " + string(token.Bytes)}, nil, 200)
			if !bytes.Equal(received, data) {
				t.Fatal("independent HTTPS receiver differs from stock sender")
			}
			t.Logf("native stock tus source proof;candidate=%s;mode=%s;client SHA256=%s;lock SHA256=%s;peer result SHA256=%s;bytes=%d;whole-file acceptance separately verified", commit, name, secure.Digest(clientSource), secure.Digest(clientLock), secure.Digest(peerRaw), len(data))
		})
	}
}
