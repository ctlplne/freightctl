//go:build integration && downloadpeer

package api

import (
	"bufio"
	"bytes"
	"encoding/json"
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
	"github.com/ctlplne/freightctl/internal/store"
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
	sourcePath := filepath.Join(private, "upload.dat")
	if err = os.WriteFile(sourcePath, data, 0600); err != nil {
		t.Fatal(err)
	}
	collectionPath := prefix + "/dav/curl-created/"
	mkdirArgs := []string{"--request", "MKCOL", "--header", "Idempotency-Key: dav-stock-collection"}
	status, headers, _, _ = run("collection-create", collectionPath, mkdirArgs, true)
	if status != 201 || headers.Get("Location") != collectionPath || headers.Get("ETag") != "" {
		t.Fatal("stock DAV did not create an exact collection")
	}
	status, _, _, mkdirRefused := run("collection-retry", collectionPath, mkdirArgs, false)
	if status != 405 || mkdirRefused != 22 {
		t.Fatal("stock DAV directory retry created a duplicate effect")
	}
	createdPath := prefix + "/dav/curl-created/file.dat"
	createArgs := []string{"--upload-file", sourcePath, "--header", "If-None-Match: *", "--header", "Idempotency-Key: dav-stock-conditional-create", "--header", "X-Content-SHA256: " + secure.Digest(data)}
	status, headers, body, _ = run("conditional-create", createdPath, createArgs, true)
	var receipt struct {
		File      store.File `json:"file"`
		Namespace string     `json:"namespace_state"`
		Replayed  bool       `json:"replayed"`
	}
	if status != 201 || json.Unmarshal(body, &receipt) != nil || receipt.Replayed || receipt.Namespace != "published-at-commit" || receipt.File.SHA256 != secure.Digest(data) || headers.Get("ETag") != artifactRevisionETag(&receipt.File) {
		t.Fatal("stock DAV conditional write did not bind exact published bytes")
	}
	status, headers, _, refusedExit := run("conditional-retry", createdPath, createArgs, false)
	if status != 412 || refusedExit != 22 || headers.Get("ETag") != "" {
		t.Fatal("stock DAV conditional retry overwrote or invented a validator")
	}
	status, headers, readback, _ := run("conditional-readback", createdPath, nil, true)
	if status != 200 || !bytes.Equal(readback, data) || headers.Get("X-File-Revision-ID") != receipt.File.ID || headers.Get("ETag") != artifactRevisionETag(&receipt.File) {
		t.Fatal("independent stock client could not verify its exact created revision")
	}
	copiedPath := prefix + "/dav/curl-created/copied.dat"
	copyArgs := []string{"--request", "COPY", "--header", "If-Match: " + artifactRevisionETag(&receipt.File), "--header", "Overwrite: F", "--header", "Idempotency-Key: dav-stock-copy", "--header", "Destination: " + front.URL + copiedPath}
	status, headers, _, _ = run("copy", createdPath, copyArgs, true)
	if status != 201 || headers.Get("Location") != copiedPath {
		t.Fatal("stock DAV COPY did not publish its exact independent mapping")
	}
	status, _, _, copyRefused := run("copy-existing", createdPath, copyArgs, false)
	if status != 412 || copyRefused != 22 {
		t.Fatal("stock DAV COPY overwrote an existing destination even with its original key")
	}
	status, headers, copiedBytes, _ := run("copy-readback", copiedPath, nil, true)
	if status != 200 || !bytes.Equal(copiedBytes, data) || headers.Get("X-File-Revision-ID") != receipt.File.ID {
		t.Fatal("independent stock copy readback changed custody")
	}
	movedPath := prefix + "/dav/curl-created/moved.dat"
	moveArgs := []string{"--request", "MOVE", "--header", "If-Match: " + artifactRevisionETag(&receipt.File), "--header", "Overwrite: F", "--header", "Idempotency-Key: dav-stock-move", "--header", "Destination: " + front.URL + movedPath}
	status, headers, _, _ = run("move", createdPath, moveArgs, true)
	if status != 201 || headers.Get("Location") != movedPath {
		t.Fatal("stock DAV MOVE did not acknowledge its exact new virtual mapping")
	}
	status, _, _, moveRefused := run("move-retry", createdPath, moveArgs, false)
	if status != 412 || moveRefused != 22 {
		t.Fatal("stock DAV stale source condition created another move")
	}
	status, headers, movedBytes, _ := run("move-readback", movedPath, nil, true)
	if status != 200 || !bytes.Equal(movedBytes, data) || headers.Get("ETag") != artifactRevisionETag(&receipt.File) || headers.Get("X-File-Revision-ID") != receipt.File.ID {
		t.Fatal("independent stock client did not verify the moved immutable revision")
	}
	deleteArgs := []string{"--request", "DELETE", "--header", "If-Match: " + artifactRevisionETag(&receipt.File), "--header", "Idempotency-Key: dav-stock-remove"}
	status, headers, removedBody, _ := run("remove-file", movedPath, deleteArgs, true)
	if status != 204 || len(removedBody) != 0 || headers.Get("X-Freightctl-Namespace-State") != "removed-at-commit" || !store.ValidID(headers.Get("X-Freightctl-Event-ID")) || headers.Get("ETag") != "" {
		t.Fatal("stock DAV DELETE lost its exact namespace outcome or invented publication")
	}
	status, _, _, missingExit := run("removed-path", movedPath, nil, false)
	if status != 404 || missingExit != 22 {
		t.Fatal("removed DAV path remained readable")
	}
	status, _, _, deleteRetry := run("remove-retry", movedPath, deleteArgs, false)
	if status != 412 || deleteRetry != 22 {
		t.Fatal("stale DELETE condition performed another effect")
	}
	status, headers, retainedBytes, _ := run("retained-custody", prefix+"/files/"+receipt.File.ID, nil, true)
	if status != 200 || !bytes.Equal(retainedBytes, data) || headers.Get("X-File-Revision-ID") != receipt.File.ID {
		t.Fatal("independent authorized stock readback lost immutable custody after path removal")
	}
	status, headers, independentBytes, _ := run("copy-survives-source-move-remove", copiedPath, nil, true)
	if status != 200 || !bytes.Equal(independentBytes, data) || headers.Get("X-File-Revision-ID") != receipt.File.ID {
		t.Fatal("moving/removing the source mapping changed the copied resource")
	}
	replacement := []byte("independent stock conditional replacement\n")
	replacementPath := filepath.Join(private, "replacement.dat")
	if err = os.WriteFile(replacementPath, replacement, 0600); err != nil {
		t.Fatal(err)
	}
	replaceArgs := []string{"--upload-file", replacementPath, "--header", "If-Match: " + artifactRevisionETag(&receipt.File), "--header", "Idempotency-Key: dav-stock-replace", "--header", "X-Content-SHA256: " + secure.Digest(replacement)}
	status, headers, body, _ = run("conditional-replace", copiedPath, replaceArgs, true)
	var replaced struct {
		File      store.File `json:"file"`
		Replayed  bool       `json:"replayed"`
		Namespace string     `json:"namespace_state"`
	}
	if status != 200 || json.Unmarshal(body, &replaced) != nil || replaced.Replayed || replaced.Namespace != "replaced-at-commit" || replaced.File.ID == receipt.File.ID || replaced.File.SHA256 != secure.Digest(replacement) || headers.Get("ETag") != artifactRevisionETag(&replaced.File) {
		t.Fatal("stock replacement did not bind a new exact immutable revision")
	}
	status, headers, _, replaceRefused := run("conditional-replace-retry", copiedPath, replaceArgs, false)
	if status != 412 || replaceRefused != 22 || headers.Get("ETag") != "" {
		t.Fatal("stock stale replacement repeated an effect or invented a validator")
	}
	status, headers, replacedBytes, _ := run("conditional-replace-readback", copiedPath, nil, true)
	if status != 200 || !bytes.Equal(replacedBytes, replacement) || headers.Get("X-File-Revision-ID") != replaced.File.ID {
		t.Fatal("independent stock replacement readback differs")
	}
	status, _, previousBytes, _ := run("conditional-replace-old-custody", prefix+"/files/"+receipt.File.ID, nil, true)
	if status != 200 || !bytes.Equal(previousBytes, data) {
		t.Fatal("stock replacement destroyed original custody")
	}
	overwriteTarget := prefix + "/dav/curl-created/overwrite-target.dat"
	overwriteSeedArgs := []string{"--upload-file", sourcePath, "--header", "If-None-Match: *", "--header", "Idempotency-Key: dav-stock-overwrite-seed", "--header", "X-Content-SHA256: " + secure.Digest(data)}
	status, _, body, _ = run("move-overwrite-seed", overwriteTarget, overwriteSeedArgs, true)
	var destination struct {
		File store.File `json:"file"`
	}
	if status != 201 || json.Unmarshal(body, &destination) != nil {
		t.Fatal("stock overwrite destination was not created")
	}
	overwriteArgs := []string{"--request", "MOVE", "--header", "If-Match: " + artifactRevisionETag(&replaced.File), "--header", "Overwrite: T", "--header", "Idempotency-Key: dav-stock-move-overwrite", "--header", "Destination: " + front.URL + overwriteTarget}
	status, headers, overwriteBody, _ := run("move-overwrite", copiedPath, overwriteArgs, true)
	if status != 204 || len(overwriteBody) != 0 || headers.Get("X-Freightctl-Namespace-State") != "replaced-at-commit" || !store.ValidID(headers.Get("X-Freightctl-Event-ID")) || headers.Get("ETag") != "" {
		t.Fatal("stock overwrite lost exact atomic namespace outcome")
	}
	status, headers, overwrittenBytes, _ := run("move-overwrite-readback", overwriteTarget, nil, true)
	if status != 200 || !bytes.Equal(overwrittenBytes, replacement) || headers.Get("X-File-Revision-ID") != replaced.File.ID {
		t.Fatal("stock overwrite independently read another revision")
	}
	status, _, retainedTargetBytes, _ := run("move-overwrite-old-custody", prefix+"/files/"+destination.File.ID, nil, true)
	if status != 200 || !bytes.Equal(retainedTargetBytes, data) {
		t.Fatal("stock overwrite destroyed previous destination custody")
	}
	status, _, _, overwriteRetry := run("move-overwrite-retry", copiedPath, overwriteArgs, false)
	if status != 412 || overwriteRetry != 22 {
		t.Fatal("stock overwrite repeated after its source was moved")
	}
	copyOverwriteTarget := prefix + "/dav/curl-created/copy-overwrite.dat"
	copySeedArgs := []string{"--upload-file", sourcePath, "--header", "If-None-Match: *", "--header", "Idempotency-Key: dav-stock-copy-overwrite-seed", "--header", "X-Content-SHA256: " + secure.Digest(data)}
	status, _, body, _ = run("copy-overwrite-seed", copyOverwriteTarget, copySeedArgs, true)
	var copyPrevious struct {
		File store.File `json:"file"`
	}
	if status != 201 || json.Unmarshal(body, &copyPrevious) != nil {
		t.Fatal("stock copy overwrite destination was not created")
	}
	copyOverwriteArgs := []string{"--request", "COPY", "--header", "If-Match: " + artifactRevisionETag(&replaced.File), "--header", "Overwrite: T", "--header", "Idempotency-Key: dav-stock-copy-overwrite", "--header", "Destination: " + front.URL + copyOverwriteTarget}
	status, headers, copyOverwriteBody, _ := run("copy-overwrite", overwriteTarget, copyOverwriteArgs, true)
	if status != 204 || len(copyOverwriteBody) != 0 || headers.Get("X-Freightctl-Namespace-State") != "replaced-at-commit" || !store.ValidID(headers.Get("X-Freightctl-Event-ID")) || headers.Get("ETag") != "" {
		t.Fatal("stock copy overwrite lost its exact atomic publication")
	}
	for index, target := range []string{overwriteTarget, copyOverwriteTarget} {
		status, headers, actualCopy, _ := run("copy-overwrite-readback-"+strconv.Itoa(index), target, nil, true)
		if status != 200 || !bytes.Equal(actualCopy, replacement) || headers.Get("X-File-Revision-ID") != replaced.File.ID {
			t.Fatal("stock copy overwrite changed source or target custody")
		}
	}
	status, headers, body, _ = run("copy-overwrite-replay", overwriteTarget, copyOverwriteArgs, true)
	var copyHistory struct {
		Result    store.PathResult `json:"result"`
		Namespace string           `json:"namespace_state"`
	}
	if status != 200 || json.Unmarshal(body, &copyHistory) != nil || !copyHistory.Result.Replayed || copyHistory.Namespace != "not-asserted-original-receipt" || headers.Get("Location") != "" {
		t.Fatal("stock copy overwrite repeated its original receipt")
	}
	status, _, oldCopyBytes, _ := run("copy-overwrite-old-custody", prefix+"/files/"+copyPrevious.File.ID, nil, true)
	if status != 200 || !bytes.Equal(oldCopyBytes, data) {
		t.Fatal("stock copy overwrite destroyed previous custody")
	}
	status, _, body, _ = run("property-identity", copyOverwriteTarget, []string{"--request", "PROPFIND", "--header", "Depth: 0"}, true)
	var metadata struct {
		Responses []struct {
			Groups []struct {
				Prop struct {
					ID       string `xml:"urn:freightctl:namespace entry-id"`
					Revision int64  `xml:"urn:freightctl:namespace revision"`
				} `xml:"DAV: prop"`
			} `xml:"DAV: propstat"`
		} `xml:"DAV: response"`
	}
	if status != 207 || xml.Unmarshal(body, &metadata) != nil || len(metadata.Responses) != 1 || len(metadata.Responses[0].Groups) != 1 {
		t.Fatal("stock property condition not discovered")
	}
	identity := metadata.Responses[0].Groups[0].Prop
	if !store.ValidID(identity.ID) || identity.Revision < 1 {
		t.Fatal("stock property condition not exact")
	}
	propertyPath := filepath.Join(private, "property-update.xml")
	if err = os.WriteFile(propertyPath, []byte(`<propertyupdate xmlns="DAV:" xmlns:x="urn:example" xmlns:q="urn:types" xml:lang="fr"><set><prop><x:label>stock <q:part q:type="q:Label">été &amp; data</q:part> q:Label</x:label></prop></set></propertyupdate>`), 0600); err != nil {
		t.Fatal(err)
	}
	propertyArgs := []string{"--request", "PROPPATCH", "--header", "Content-Type: application/xml", "--header", "Idempotency-Key: dav-stock-properties", "--header", "X-Freightctl-Namespace-Revision: " + identity.ID + ":" + strconv.FormatInt(identity.Revision, 10), "--data-binary", "@" + propertyPath}
	status, headers, body, _ = run("property-mutation", copyOverwriteTarget, propertyArgs, true)
	if status != 207 || !bytes.Contains(body, []byte("HTTP/1.1 200 OK")) || headers.Get("ETag") != "" || headers.Get("X-Freightctl-Namespace-State") != "properties-changed-at-commit" || headers.Get("X-Freightctl-Namespace-Revision") != identity.ID+":"+strconv.FormatInt(identity.Revision+1, 10) {
		t.Fatal("stock property mutation lost its atomic result")
	}
	status, _, body, _ = run("property-readback", copyOverwriteTarget, []string{"--request", "PROPFIND", "--header", "Depth: 0"}, true)
	var propertyReadback struct {
		Responses []struct {
			Groups []struct {
				Prop struct {
					Label struct {
						Text string `xml:",chardata"`
						Part string `xml:"urn:types part"`
					} `xml:"urn:example label"`
				} `xml:"DAV: prop"`
			} `xml:"DAV: propstat"`
		} `xml:"DAV: response"`
	}
	if status != 207 || xml.Unmarshal(body, &propertyReadback) != nil || len(propertyReadback.Responses) != 1 || len(propertyReadback.Responses[0].Groups) != 1 || propertyReadback.Responses[0].Groups[0].Prop.Label.Text != "stock  q:Label" || propertyReadback.Responses[0].Groups[0].Prop.Label.Part != "été & data" || !bytes.Contains(body, []byte(`xmlns:q="urn:types"`)) || !bytes.Contains(body, []byte(`xml:lang="fr"`)) {
		t.Fatal("stock property mixed XML readback differs")
	}
	status, _, body, _ = run("property-replay", copyOverwriteTarget, propertyArgs, true)
	var propertyReceipt struct {
		Result store.PathResult `json:"result"`
		State  string           `json:"namespace_state"`
	}
	if status != 200 || json.Unmarshal(body, &propertyReceipt) != nil || !propertyReceipt.Result.Replayed || propertyReceipt.State != "not-asserted-original-receipt" {
		t.Fatal("stock property retry repeated effects")
	}
	staleArgs := append([]string{}, propertyArgs...)
	for i := range staleArgs {
		if staleArgs[i] == "Idempotency-Key: dav-stock-properties" {
			staleArgs[i] = "Idempotency-Key: dav-stock-properties-stale"
		}
	}
	status, _, _, stalePropertyExit := run("property-stale", copyOverwriteTarget, staleArgs, false)
	if status != 412 || stalePropertyExit != 22 {
		t.Fatal("stock stale property revision accepted")
	}
	status, _, propertyBytes, _ := run("property-bytes-unchanged", copyOverwriteTarget, nil, true)
	if status != 200 || !bytes.Equal(propertyBytes, replacement) {
		t.Fatal("stock property update changed file bytes")
	}
	status, _, body, _ = run("collection-move-identity", collectionPath, []string{"--request", "PROPFIND", "--header", "Depth: 0"}, true)
	metadata.Responses = nil
	if status != 207 || xml.Unmarshal(body, &metadata) != nil || len(metadata.Responses) != 1 || len(metadata.Responses[0].Groups) != 1 {
		t.Fatal("stock collection namespace identity missing")
	}
	collectionIdentity := metadata.Responses[0].Groups[0].Prop
	if !store.ValidID(collectionIdentity.ID) || collectionIdentity.Revision < 1 {
		t.Fatal("stock collection namespace condition not exact")
	}
	collectionTarget := prefix + "/dav/curl-moved/"
	collectionMoveArgs := []string{"--request", "MOVE", "--header", "Overwrite: F", "--header", "Depth: infinity", "--header", "Idempotency-Key: dav-stock-collection-move", "--header", "X-Freightctl-Namespace-Revision: " + collectionIdentity.ID + ":" + strconv.FormatInt(collectionIdentity.Revision, 10), "--header", "Destination: " + front.URL + collectionTarget}
	status, headers, body, _ = run("collection-move", collectionPath, collectionMoveArgs, true)
	var movedCollection struct {
		Result store.PathResult `json:"result"`
		State  string           `json:"namespace_state"`
	}
	if status != 201 || json.Unmarshal(body, &movedCollection) != nil || movedCollection.Result.Replayed || movedCollection.Result.Changed != 3 || movedCollection.Result.Entry.ID != collectionIdentity.ID || movedCollection.Result.Entry.Revision != collectionIdentity.Revision+1 || movedCollection.State != "collection-moved-at-commit" || headers.Get("Location") != collectionTarget || headers.Get("ETag") != "" {
		t.Fatal("stock collection MOVE lost its complete atomic namespace result")
	}
	for index, oldPath := range []string{overwriteTarget, copyOverwriteTarget} {
		newPath := collectionTarget + strings.TrimPrefix(oldPath, collectionPath)
		status, headers, movedMember, _ := run("collection-member-"+strconv.Itoa(index), newPath, nil, true)
		if status != 200 || !bytes.Equal(movedMember, replacement) || headers.Get("X-File-Revision-ID") != replaced.File.ID {
			t.Fatal("independent stock moved member custody differs")
		}
		status, _, _, oldMemberExit := run("collection-old-member-"+strconv.Itoa(index), oldPath, nil, false)
		if status != 404 || oldMemberExit != 22 {
			t.Fatal("stock collection MOVE retained an original member mapping")
		}
	}
	status, _, body, _ = run("collection-property-readback", collectionTarget+strings.TrimPrefix(copyOverwriteTarget, collectionPath), []string{"--request", "PROPFIND", "--header", "Depth: 0"}, true)
	propertyReadback.Responses = nil
	if status != 207 || xml.Unmarshal(body, &propertyReadback) != nil || len(propertyReadback.Responses) != 1 || len(propertyReadback.Responses[0].Groups) != 1 || propertyReadback.Responses[0].Groups[0].Prop.Label.Text != "stock  q:Label" || propertyReadback.Responses[0].Groups[0].Prop.Label.Part != "été & data" || !bytes.Contains(body, []byte(`xmlns:q="urn:types"`)) || !bytes.Contains(body, []byte(`xml:lang="fr"`)) {
		t.Fatal("stock collection MOVE lost mixed XML property context")
	}
	status, _, _, collectionRetry := run("collection-move-retry", collectionPath, collectionMoveArgs, false)
	if status != 412 || collectionRetry != 22 {
		t.Fatal("stock stale collection condition performed another move")
	}
	currentMember := collectionTarget + strings.TrimPrefix(copyOverwriteTarget, collectionPath)
	status, _, _, unsupportedConditionExit := run("unsupported-namespace-condition", currentMember, []string{"--request", "DELETE", "--header", "Idempotency-Key: dav-stock-unsupported-namespace", "--header", "If-Match: " + artifactRevisionETag(&replaced.File), "--header", "X-Freightctl-Namespace-Revision: " + identity.ID + ":" + strconv.FormatInt(identity.Revision, 10)}, false)
	if status != 400 || unsupportedConditionExit != 22 {
		t.Fatal("stock file mutation silently ignored a namespace condition")
	}
	status, headers, unchangedMember, _ := run("unsupported-condition-unchanged", currentMember, nil, true)
	if status != 200 || !bytes.Equal(unchangedMember, replacement) || headers.Get("X-File-Revision-ID") != replaced.File.ID {
		t.Fatal("unsupported namespace condition removed or changed the stock member")
	}
	deleteCollectionArgs := []string{"--request", "DELETE", "--header", "Depth: infinity", "--header", "Idempotency-Key: dav-stock-collection-delete", "--header", "X-Freightctl-Namespace-Revision: " + movedCollection.Result.Entry.ID + ":" + strconv.FormatInt(movedCollection.Result.Entry.Revision, 10)}
	status, headers, body, _ = run("collection-delete", collectionTarget, deleteCollectionArgs, true)
	if status != 204 || len(body) != 0 || headers.Get("X-Freightctl-Namespace-State") != "collection-removed-at-commit" || headers.Get("X-Freightctl-Removed-Entries") != "3" || !store.ValidID(headers.Get("X-Freightctl-Event-ID")) || headers.Get("ETag") != "" || headers.Get("Location") != "" {
		t.Fatal("stock collection DELETE lost its complete atomic result or invented publication")
	}
	for index, removedPath := range []string{collectionTarget, collectionTarget + strings.TrimPrefix(overwriteTarget, collectionPath), currentMember} {
		for _, method := range []string{"GET", "HEAD", "PROPFIND"} {
			args := []string{"--request", method, "--header", "Depth: 0"}
			if method == "HEAD" {
				args = []string{"--head", "--header", "Depth: 0"}
			}
			status, _, _, missingExit := run("collection-deleted-"+strconv.Itoa(index)+"-"+method, removedPath, args, false)
			if status != 404 || missingExit != 22 {
				t.Fatal("stock recursive DELETE retained a live mapping")
			}
		}
	}
	status, _, _, repeatedDeleteExit := run("collection-delete-retry", collectionTarget, deleteCollectionArgs, false)
	if status != 412 || repeatedDeleteExit != 22 {
		t.Fatal("lost collection DELETE response allowed repeated mutation")
	}
	status, headers, retainedCollectionBytes, _ := run("collection-delete-retained-custody", prefix+"/files/"+replaced.File.ID, nil, true)
	if status != 200 || !bytes.Equal(retainedCollectionBytes, replacement) || headers.Get("X-File-Revision-ID") != replaced.File.ID {
		t.Fatal("stock recursive DELETE erased immutable custody")
	}
	binaryPath, err := exec.LookPath("curl")
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("native conditional-create/file-replace/file-move/file-remove/collection-move/collection-remove/read DAV proof;candidate=%s;architecture=%s;curl-SHA256=%s;lost-exit=%d;prefix=65536;bytes=%d;SHA256=%s;XML=independently-parsed;receiver=independently-compared;conditional-retry=412;stale-replace=412;stale-move=412;overwrite-move=204;stale-overwrite=412;overwrite-copy=204;copy-replay=historical200;removed-path=404;stale-delete=412;removed-collection-members=3;removed-collection-retry=412;retained-custody=independently-compared;other-writes-locks-full-DAV=owed", commit, runtime.GOARCH, secure.Digest(binary), lostExit, len(received), secure.Digest(received))
}
