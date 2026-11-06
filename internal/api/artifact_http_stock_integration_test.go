//go:build integration && downloadpeer

package api

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

type selectedArtifactCut struct {
	io.ReadCloser
	remaining int64
}

func (r *selectedArtifactCut) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.ErrUnexpectedEOF
	}
	n, err := r.ReadCloser.Read(p[:int(min(int64(len(p)), r.remaining))])
	r.remaining -= int64(n)
	return n, err
}

func TestArtifactHTTPNativeStockCurlInterruptedResumeAndCurrentRevocation(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "true" || runtime.GOOS != "linux" || (runtime.GOARCH != "arm64" && runtime.GOARCH != "amd64") {
		t.Fatal("stock curl runtime requires its authorized native GitHub environment")
	}
	commitRaw, err := exec.Command("git", "rev-parse", "HEAD").Output()
	commit := strings.TrimSpace(string(commitRaw))
	if err != nil || len(commit) != 40 || strings.Trim(commit, "0123456789abcdef") != "" || commit != os.Getenv("GITHUB_SHA") {
		t.Fatal("native source does not match actual Actions candidate")
	}
	_, scope, admin, server := browserAPI(t, 10*time.Minute)
	cookie, csrf := loginBrowser(t, server, scope, admin)
	prefix := "/v1/tenants/" + scope.Tenant + "/partners/" + scope.Partner
	sender, actor := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "write", "list"})
	data := bytes.Repeat([]byte("inert artifact;no execution authority\n"), 5000)
	_, raw := exchangeAPIRequest(t, server, "POST", prefix+"/files", nil, map[string]string{"Authorization": "Bearer " + string(sender.Bytes), "Idempotency-Key": "curl-resume-source", "X-File-Size": strconv.Itoa(len(data)), "X-Content-SHA256": secure.Digest(data)}, data, 201)
	var accepted struct {
		File store.File `json:"file"`
	}
	if json.Unmarshal(raw, &accepted) != nil || accepted.File.SHA256 != secure.Digest(data) {
		t.Fatal("ordinary source acceptance differs")
	}
	path := prefix + "/files/" + accepted.File.ID
	upstream, _ := url.Parse(server.URL)
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.Transport = server.Client().Transport
	proxy.ErrorLog = log.New(io.Discard, "", 0)
	var cut atomic.Bool
	proxy.ModifyResponse = func(response *http.Response) error {
		if response.Request.Method == "GET" && response.Request.URL.Path == path && response.Request.Header.Get("Range") == "" && response.StatusCode == 200 && cut.CompareAndSwap(false, true) {
			// Preserve original headers and bytes. Abort the real connection
			// after a prefix of an otherwise complete authorized response.
			response.Body = &selectedArtifactCut{ReadCloser: response.Body, remaining: 65536}
		}
		return nil
	}
	front := httptest.NewTLSServer(proxy)
	defer front.Close()
	private := t.TempDir()
	if err = os.Chmod(private, 0700); err != nil {
		t.Fatal(err)
	}
	ca, err := secure.NativeProofCertificatePEM(front.Certificate().Raw)
	if err != nil {
		t.Fatal(err)
	}
	caPath, credential, output := filepath.Join(private, "ca.pem"), filepath.Join(private, "headers"), filepath.Join(private, "received.dat")
	if err = os.WriteFile(caPath, ca, 0600); err != nil {
		t.Fatal(err)
	}
	authorization := "Authorization: Bearer " + string(sender.Bytes) + "\n"
	if err = os.WriteFile(credential, []byte(authorization), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(output, nil, 0600); err != nil {
		t.Fatal(err)
	}
	run := func(name string, extra []string, success bool) (int, http.Header, int) {
		t.Helper()
		headersPath, logPath := filepath.Join(private, name+".headers"), filepath.Join(private, name+".log")
		if err := os.WriteFile(headersPath, nil, 0600); err != nil {
			t.Fatal(err)
		}
		log, err := os.OpenFile(logPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		// --disable is first:never load a shared curlrc. No proxy,redirect,
		// insecure TLS,ambient authentication or credential value in argv.
		args := []string{"--disable", "--fail", "--silent", "--show-error", "--http1.1", "--tlsv1.3", "--tls-max", "1.3", "--noproxy", "*", "--proto", "=https", "--cacert", caPath, "--header", "@" + credential, "--header", "Accept-Encoding: identity", "--dump-header", headersPath}
		args = append(args, extra...)
		args = append(args, front.URL+path)
		command := exec.CommandContext(t.Context(), "curl", args...)
		command.Env = append(os.Environ(), "HTTP_PROXY=", "HTTPS_PROXY=", "ALL_PROXY=", "NO_PROXY=127.0.0.1")
		command.Stdout, command.Stderr = log, log
		err = command.Run()
		log.Close()
		code := 0
		if err != nil {
			var exit *exec.ExitError
			if !errors.As(err, &exit) {
				t.Fatal("stock curl did not execute")
			}
			code = exit.ExitCode()
		}
		if (err == nil) != success {
			privateLog, _ := os.ReadFile(logPath)
			t.Fatalf("stock curl outcome differs;phase=%s;exit=%d;private-log-SHA256=%s", name, code, secure.Digest(privateLog))
		}
		headerRaw, err := os.ReadFile(headersPath)
		if err != nil || len(headerRaw) > 65536 {
			t.Fatal("stock client response headers missing or oversized")
		}
		response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(headerRaw)), nil)
		if err != nil {
			t.Fatal("stock client response headers invalid")
		}
		response.Body.Close()
		return response.StatusCode, response.Header, code
	}
	status, first, lostExit := run("lost", []string{"--output", output}, false)
	partial, err := os.ReadFile(output)
	etag := first.Get("ETag")
	if err != nil || status != 200 || !cut.Load() || len(partial) != 65536 || !bytes.Equal(partial, data[:65536]) || etag == "" || first.Get("X-File-Revision-ID") != accepted.File.ID || first.Get("X-Content-SHA256") != secure.Digest(data) {
		t.Fatal("actual interrupted stock response did not retain the exact prefix and revision")
	}
	if err = os.WriteFile(credential, []byte(authorization+"If-Range: "+etag+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	status, resumed, _ := run("resumed", []string{"--continue-at", "-", "--output", output}, true)
	received, err := os.ReadFile(output)
	if err != nil || status != 206 || resumed.Get("ETag") != etag || resumed.Get("Content-Range") != "bytes 65536-"+strconv.Itoa(len(data)-1)+"/"+strconv.Itoa(len(data)) || !bytes.Equal(received, data) || secure.Digest(received) != accepted.File.SHA256 {
		t.Fatal("independent stock receiver did not reconstruct the exact immutable artifact")
	}
	exchangeAPIRequest(t, server, "POST", prefix+"/accounts/commands", cookie, map[string]string{"Origin": server.URL, "X-CSRF-Token": csrf, "Idempotency-Key": "curl-reader-revoke"}, exchangeAPIJSON(t, store.AccountCommand{Operation: "revoke", ID: actor.Actor, ExpectedRevision: 1}), 200)
	deniedOutput := filepath.Join(private, "denied")
	if err = os.WriteFile(deniedOutput, nil, 0600); err != nil {
		t.Fatal(err)
	}
	status, denied, _ := run("revoked", []string{"--head", "--header", "If-None-Match: " + etag, "--output", deniedOutput}, false)
	if status != 401 || denied.Get("ETag") != "" || denied.Get("Content-Range") != "" || denied.Get("Cache-Control") != "no-store" {
		t.Fatal("old validator bypassed current credential revocation")
	}
	binaryPath, err := exec.LookPath("curl")
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("native immutable HTTP resume proof;candidate=%s;architecture=%s;curl-SHA256=%s;lost-exit=%d;prefix=65536;bytes=%d;SHA256=%s;current-revocation=denied;receiver-file=independently-compared;business-processing=unknown", commit, runtime.GOARCH, secure.Digest(binary), lostExit, len(received), secure.Digest(received))
}
