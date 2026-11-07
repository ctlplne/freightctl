//go:build integration && downloadpeer

package api

import (
	"bufio"
	"bytes"
	"encoding/xml"
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
)

func TestWebDAVNativeStockCurlDiscoveryInterruptedReadAndExactResume(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "true" || runtime.GOOS != "linux" || (runtime.GOARCH != "arm64" && runtime.GOARCH != "amd64") {
		t.Fatal("stock DAV proof requires its authorized native GitHub environment")
	}
	commitRaw, err := exec.Command("git", "rev-parse", "HEAD").Output()
	commit := strings.TrimSpace(string(commitRaw))
	if err != nil || len(commit) != 40 || strings.Trim(commit, "0123456789abcdef") != "" || commit != os.Getenv("GITHUB_SHA") {
		t.Fatal("DAV proof source differs from actual Actions candidate")
	}
	_, scope, admin, server := browserAPI(t, time.Minute)
	prefix := "/v1/tenants/" + scope.Tenant + "/partners/" + scope.Partner
	data := bytes.Repeat([]byte("inert DAV artifact;no execution authority\n"), 4000)
	exchangeAPIRequest(t, server, "PUT", prefix+"/namespace/file?path=/stock%20artifact.dat", nil, map[string]string{"Authorization": "Bearer " + string(admin.Bytes), "Idempotency-Key": "dav-stock-source", "X-File-Size": strconv.Itoa(len(data)), "X-Content-SHA256": secure.Digest(data)}, data, 201)
	filePath := prefix + "/dav/stock artifact.dat"
	upstream, _ := url.Parse(server.URL)
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.Transport = server.Client().Transport
	proxy.ErrorLog = log.New(io.Discard, "", 0)
	var cut atomic.Bool
	proxy.ModifyResponse = func(response *http.Response) error {
		if response.Request.Method == "GET" && response.Request.URL.Path == filePath && response.Request.Header.Get("Range") == "" && response.StatusCode == 200 && cut.CompareAndSwap(false, true) {
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
	caPath, credential, query := filepath.Join(private, "ca.pem"), filepath.Join(private, "headers"), filepath.Join(private, "query.xml")
	for name, body := range map[string][]byte{caPath: ca, credential: []byte("Authorization: Bearer " + string(admin.Bytes) + "\n"), query: []byte(`<propfind xmlns="DAV:"><prop><getetag/><getcontentlength/><resourcetype/></prop></propfind>`)} {
		if err = os.WriteFile(name, body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	run := func(phase, target string, extra []string, success bool) (int, http.Header, []byte, int) {
		t.Helper()
		headersPath, outputPath, logPath := filepath.Join(private, phase+".headers"), filepath.Join(private, phase+".body"), filepath.Join(private, phase+".log")
		for _, name := range []string{headersPath, outputPath} {
			if err := os.WriteFile(name, nil, 0600); err != nil {
				t.Fatal(err)
			}
		}
		out, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal(err)
		}
		args := []string{"--disable", "--fail", "--silent", "--show-error", "--http1.1", "--tlsv1.3", "--tls-max", "1.3", "--noproxy", "*", "--proto", "=https", "--cacert", caPath, "--header", "@" + credential, "--header", "Accept-Encoding: identity", "--dump-header", headersPath, "--output", outputPath}
		args = append(args, extra...)
		args = append(args, front.URL+target)
		command := exec.CommandContext(t.Context(), "curl", args...)
		command.Env = append(os.Environ(), "HTTP_PROXY=", "HTTPS_PROXY=", "ALL_PROXY=", "NO_PROXY=127.0.0.1")
		command.Stdout, command.Stderr = out, out
		err = command.Run()
		out.Close()
		code := 0
		if err != nil {
			var exit *exec.ExitError
			if !errors.As(err, &exit) {
				t.Fatal("stock DAV client did not execute")
			}
			code = exit.ExitCode()
		}
		if (err == nil) != success {
			raw, _ := os.ReadFile(logPath)
			t.Fatalf("stock DAV result differs;phase=%s;exit=%d;private-log-SHA256=%s", phase, code, secure.Digest(raw))
		}
		headerRaw, err := os.ReadFile(headersPath)
		if err != nil || len(headerRaw) > 65536 {
			t.Fatal("stock DAV headers missing or oversized")
		}
		response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(headerRaw)), nil)
		if err != nil {
			t.Fatal("stock DAV response invalid")
		}
		response.Body.Close()
		body, err := os.ReadFile(outputPath)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, response.Header, body, code
	}
	status, _, body, _ := run("discovery", prefix+"/dav/", []string{"--request", "PROPFIND", "--header", "Depth: 1", "--header", "Content-Type: application/xml", "--data-binary", "@" + query}, true)
	var properties struct {
		Responses []struct {
			Href   string `xml:"DAV: href"`
			Groups []struct {
				Prop struct {
					ETag string `xml:"DAV: getetag"`
					Size string `xml:"DAV: getcontentlength"`
				} `xml:"DAV: prop"`
			} `xml:"DAV: propstat"`
		} `xml:"DAV: response"`
	}
	if status != 207 || xml.Unmarshal(body, &properties) != nil || len(properties.Responses) != 2 || properties.Responses[1].Href != prefix+"/dav/stock%20artifact.dat" || properties.Responses[1].Groups[0].Prop.Size != strconv.Itoa(len(data)) {
		t.Fatal("stock DAV client did not discover exact authorized artifact")
	}
	etag := properties.Responses[1].Groups[0].Prop.ETag
	target := prefix + "/dav/stock%20artifact.dat"
	status, headers, partial, lostExit := run("lost", target, nil, false)
	if status != 200 || lostExit != 18 || !cut.Load() || len(partial) != 65536 || !bytes.Equal(partial, data[:65536]) || headers.Get("ETag") != etag || etag == "" {
		t.Fatal("actual interrupted DAV response did not pin the exact prefix and revision")
	}
	status, headers, suffix, _ := run("resume", target, []string{"--header", "Range: bytes=65536-", "--header", "If-Range: " + etag}, true)
	received := append(append([]byte{}, partial...), suffix...)
	if status != 206 || headers.Get("ETag") != etag || !bytes.Equal(received, data) || secure.Digest(received) != secure.Digest(data) {
		t.Fatal("independent stock client did not reconstruct the exact DAV revision")
	}
	binaryPath, err := exec.LookPath("curl")
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("native read-only DAV proof;candidate=%s;architecture=%s;curl-SHA256=%s;lost-exit=%d;prefix=65536;bytes=%d;SHA256=%s;XML=independently-parsed;receiver=independently-compared;writes-locks-full-DAV=owed", commit, runtime.GOARCH, secure.Digest(binary), lostExit, len(received), secure.Digest(received))
}
