//go:build integration

package api

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/protectedfs"
)

type browserFailureTrace struct {
	Class  string
	Line   int
	Column int
	SHA256 string
}

func TestBrowserRuntimeErrorKeepsSafeBoundedAssetLocation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime-error.log")
	raw := []byte("TypeError: PRIVATE_RUNTIME_CANARY\n    at https://127.0.0.1:54321/assets/app.js:1:256842\n")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	trace := safeBrowserFailureTrace(path, "app.js")
	if trace.Class != "type" || trace.Line != 1 || trace.Column != 256842 || trace.SHA256 != secure.Digest(raw) {
		t.Fatal("runtime asset failure lost its safe class,large minified column or exact digest")
	}
	if got := safeBrowserFailureTrace(path, "PRIVATE_RUNTIME_CANARY"); got.Class != "unavailable" {
		t.Fatal("untrusted runtime asset name entered diagnostics")
	}
}

func TestBrowserFailureTraceKeepsClosedNetworkBodyCategoryWithoutMessages(t *testing.T) {
	path := filepath.Join(t.TempDir(), "failure.log")
	raw := []byte("Error: response.json: Protocol error (Network.getResponseBody): PRIVATE_BODY_CREDENTIAL\n    at file:///PRIVATE_PATH/scripts/json-intake-browser.mjs:289:35\n")
	f, err := protectedfs.CreateExclusive(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write(raw); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	trace := safeBrowserFailureTrace(path, "json-intake-browser.mjs")
	if trace.Class != "browser-response-body" || trace.Line != 289 || trace.Column != 35 || trace.SHA256 != secure.Digest(raw) {
		t.Fatal("native body failure lost its closed category,source or exact bounded digest")
	}
	wire, err := json.Marshal(trace)
	if err != nil || strings.Contains(string(wire), "PRIVATE") || strings.Contains(string(wire), "Network.getResponseBody") {
		t.Fatal("private browser protocol message entered public diagnostics")
	}
}

func safeExchangeBrowserFailure(private string) browserFailureTrace {
	// The receive script catches its error into this exclusive private file;
	// stdout can contain only a summary. Use the original stack first. A failure
	// outside that boundary still needs the bounded protected process-log path.
	trace := safeBrowserFailureTrace(filepath.Join(private, "first-failure.log"), "artifact-exchange-browser.mjs")
	if trace.Class != "unavailable" {
		return trace
	}
	return safeBrowserFailureTrace(filepath.Join(private, "browser.log"), "artifact-exchange-browser.mjs")
}

func TestExchangeBrowserFailureUsesTheProtectedOriginalFailure(t *testing.T) {
	directory := t.TempDir()
	first := []byte("AssertionError: PRIVATE_ORIGINAL_FAILURE\n    at file:///PRIVATE_PATH/scripts/artifact-exchange-browser.mjs:357:9\n")
	for leaf, body := range map[string][]byte{"browser.log": []byte(`{"state":"failed"}`), "first-failure.log": first} {
		f, err := protectedfs.CreateExclusive(filepath.Join(directory, leaf))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.Write(body); err != nil {
			f.Close()
			t.Fatal(err)
		}
		if err = f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	trace := safeExchangeBrowserFailure(directory)
	if trace.Class != "assertion" || trace.Line != 357 || trace.Column != 9 || trace.SHA256 != secure.Digest(first) {
		t.Fatal("console output hid the original protected failure")
	}
	if err := os.Remove(filepath.Join(directory, "first-failure.log")); err != nil {
		t.Fatal(err)
	}
	trace = safeExchangeBrowserFailure(directory)
	if trace.Class != "unclassified" || trace.Line != 0 || trace.Column != 0 || trace.SHA256 != secure.Digest([]byte(`{"state":"failed"}`)) {
		t.Fatal("missing first failure lost exact bounded process fallback")
	}
}

// Only a closed failure class,numeric source location and whole bounded-file
// digest may leave the private fixture. Never print a stack,message,path or DOM.
func safeBrowserFailureTrace(path, script string) browserFailureTrace {
	unavailable := browserFailureTrace{Class: "unavailable", SHA256: "unavailable"}
	switch script {
	case "artifact-exchange-browser.mjs", "json-intake-browser.mjs", "processing-review-browser.mjs", "processing-browser.mjs", "local-collection-browser.mjs", "local-calendar-browser.mjs", "app.js":
	default:
		return unavailable
	}
	secret, err := secure.ReadSecret(path, 64<<10)
	if err != nil {
		return unavailable
	}
	defer secret.Close()
	raw := secret.Bytes
	trace := browserFailureTrace{Class: "unclassified", SHA256: secure.Digest(raw)}
	for _, item := range []struct{ marker, class string }{
		{"ERR_MODULE_NOT_FOUND", "dependency"}, {"Cannot find module", "dependency"},
		{"ERR_PACKAGE_PATH_NOT_EXPORTED", "dependency"}, {"SyntaxError", "syntax"},
		{"ReferenceError", "reference"}, {"AssertionError", "assertion"},
		{"Network.getResponseBody", "browser-response-body"},
		{"TypeError", "type"},
		{"TimeoutError", "timeout"}, {"Timeout ", "timeout"},
		{"EEXIST", "evidence-exists"}, {"ENOENT", "evidence-path"},
		{"Failed to launch", "browser-launch"},
	} {
		if bytes.Contains(raw, []byte(item.marker)) {
			trace.Class = item.class
			break
		}
	}
	pattern := regexp.MustCompile(`(?m)^\s*at [^\r\n]*[/\\]` + regexp.QuoteMeta(script) + `:([0-9]{1,5}):([0-9]{1,8})\)?\s*$`)
	if match := pattern.FindSubmatch(raw); len(match) == 3 {
		line, e1 := strconv.Atoi(string(match[1]))
		column, e2 := strconv.Atoi(string(match[2]))
		if e1 == nil && e2 == nil && line > 0 && column > 0 {
			trace.Line, trace.Column = line, column
		}
	}
	return trace
}

func TestBrowserFailureTraceKeepsOnlyClosedClassLocationAndBoundedDigest(t *testing.T) {
	for _, script := range []string{"artifact-exchange-browser.mjs", "json-intake-browser.mjs", "processing-review-browser.mjs", "processing-browser.mjs", "local-collection-browser.mjs"} {
		body := []byte("AssertionError: PRIVATE_CREDENTIAL DOM_AND_PAYLOAD\n    at file:///PRIVATE_PATH/scripts/" + script + ":123:7\n")
		path := filepath.Join(t.TempDir(), "failure.log")
		f, err := protectedfs.CreateExclusive(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.Write(body); err != nil {
			f.Close()
			t.Fatal(err)
		}
		if err = f.Close(); err != nil {
			t.Fatal(err)
		}
		trace := safeBrowserFailureTrace(path, script)
		if trace.Class != "assertion" || trace.Line != 123 || trace.Column != 7 || trace.SHA256 != secure.Digest(body) {
			t.Fatal("closed candidate source location was lost")
		}
		wire, err := json.Marshal(trace)
		if err != nil || strings.Contains(string(wire), "PRIVATE_") || strings.Contains(string(wire), "DOM_AND_PAYLOAD") || strings.Contains(string(wire), script) {
			t.Fatal("private browser failure entered public diagnostics")
		}
		if got := safeBrowserFailureTrace(path, "untrusted-script.mjs"); got.Class != "unavailable" || got.Line != 0 || got.SHA256 != "unavailable" {
			t.Fatal("untrusted script supplied diagnostic authority")
		}
	}
}

func TestBrowserFailureTraceRefusesOversizedPrivateEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "failure.log")
	f, err := protectedfs.CreateExclusive(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write(bytes.Repeat([]byte("x"), (64<<10)+1)); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	trace := safeBrowserFailureTrace(path, "artifact-exchange-browser.mjs")
	if trace.Class != "unavailable" || trace.Line != 0 || trace.Column != 0 || trace.SHA256 != "unavailable" {
		t.Fatal("oversized private evidence produced a partial or misleading digest")
	}
}
