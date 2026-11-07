//go:build integration

package api

import (
	"bytes"
	"encoding/json"
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

// Only a closed failure class,numeric source location and whole bounded-file
// digest may leave the private fixture. Never print a stack,message,path or DOM.
func safeBrowserFailureTrace(path, script string) browserFailureTrace {
	unavailable := browserFailureTrace{Class: "unavailable", SHA256: "unavailable"}
	switch script {
	case "artifact-exchange-browser.mjs", "json-intake-browser.mjs", "processing-review-browser.mjs", "processing-browser.mjs":
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
		{"TimeoutError", "timeout"}, {"Timeout ", "timeout"},
		{"EEXIST", "evidence-exists"}, {"ENOENT", "evidence-path"},
		{"Failed to launch", "browser-launch"},
	} {
		if bytes.Contains(raw, []byte(item.marker)) {
			trace.Class = item.class
			break
		}
	}
	pattern := regexp.MustCompile(`(?m)^\s*at [^\r\n]*[/\\]` + regexp.QuoteMeta(script) + `:([0-9]{1,5}):([0-9]{1,5})\)?\s*$`)
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
	for _, script := range []string{"artifact-exchange-browser.mjs", "json-intake-browser.mjs", "processing-review-browser.mjs", "processing-browser.mjs"} {
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
