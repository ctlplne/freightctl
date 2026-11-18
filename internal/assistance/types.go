// Package assistance treats model responses as untrusted proposals. It has no
// runtime launcher, file-content reader, shell tool or execution authority.
package assistance

import (
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

var ErrInput = errors.New("invalid assistance request")
var ErrDisabled = errors.New("inference is disabled; context preparation and ordinary workflows remain available")
var ErrBackend = errors.New("configured model endpoint did not produce a bounded complete response")
var ErrModelOutput = errors.New("model proposal failed validation")
var keyPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
var hashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var modelPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_./:-]{0,127}$`)

type Profile struct {
	Schema            int    `json:"schema_version"`
	Endpoint          string `json:"endpoint"`
	Model             string `json:"model"`
	ModelDigest       string `json:"model_digest"`
	TokenizerDigest   string `json:"tokenizer_digest"`
	AllowRemote       bool   `json:"allow_remote"`
	AllowOperatorText bool   `json:"allow_operator_text"`
	ContextBytes      int    `json:"context_bytes"`
	ContextTokens     int    `json:"context_tokens"`
	OutputTokens      int    `json:"output_tokens"`
	TimeoutSeconds    int    `json:"timeout_seconds"`
}
type ProfileRequest struct {
	ID              string  `json:"profile_id,omitempty"`
	ExpectedVersion int     `json:"expected_version"`
	Definition      Profile `json:"definition"`
}
type Destination struct {
	Connection workflow.Reference `json:"connection"`
	Filename   string             `json:"filename"`
}
type PrepareRequest struct {
	Profile      workflow.Reference `json:"profile"`
	Kind         string             `json:"kind"`
	Name         string             `json:"name,omitempty"`
	Requirements string             `json:"requirements,omitempty"`
	Destinations []Destination      `json:"destinations,omitempty"`
	RunID        string             `json:"run_id,omitempty"`
}
type Snapshot struct {
	Kind     string `json:"kind"`
	ID       string `json:"id"`
	Version  int    `json:"version"`
	Revision int64  `json:"revision"`
	Hash     string `json:"hash"`
	EventID  string `json:"event_id"`
}
type Citation struct {
	EventID    string `json:"event_id"`
	Kind       string `json:"kind"`
	ResourceID string `json:"resource_id"`
}
type Fact struct {
	Alias string `json:"alias"`
	Code  string `json:"code"`
}
type Finding struct {
	Code      string   `json:"code"`
	Evidence  []string `json:"evidence"`
	NextCheck string   `json:"next_check"`
}
type Context struct {
	Schema           int       `json:"schema_version"`
	Kind             string    `json:"kind"`
	Requirements     string    `json:"operator_text,omitempty"`
	Destinations     []string  `json:"destinations,omitempty"`
	FTPSDestinations []string  `json:"ftps_destinations,omitempty"`
	Facts            []Fact    `json:"facts,omitempty"`
	Supported        []Finding `json:"supported_findings,omitempty"`
}
type Bindings struct {
	Request            PrepareRequest        `json:"request"`
	Snapshots          []Snapshot            `json:"snapshots"`
	Evidence           map[string][]Citation `json:"evidence"`
	OperatorTextPolicy string                `json:"operator_text_policy,omitempty"`
}
type Decision struct {
	Hash     string `json:"context_hash"`
	Revision int64  `json:"expected_revision"`
}
type Proposal struct {
	Status  string   `json:"status"`
	Order   []string `json:"order"`
	Missing []string `json:"missing"`
}
type Diagnosis struct {
	Code      string   `json:"code"`
	Evidence  []string `json:"evidence"`
	NextCheck string   `json:"next_check"`
}
type ValidatedResult struct {
	Proposal    *Proposal  `json:"proposal,omitempty"`
	Diagnosis   *Diagnosis `json:"diagnosis,omitempty"`
	Explanation string     `json:"explanation,omitempty"`
	Citations   []Citation `json:"citations,omitempty"`
	Usage       *usage     `json:"reported_usage,omitempty"`
}
type Result struct {
	Resource json.RawMessage `json:"resource"`
	Replayed bool            `json:"replayed"`
}
type JobView struct {
	Job     *store.AIJob `json:"job"`
	Current bool         `json:"current"`
}
type GenerationResult struct {
	Job      *store.AIJob `json:"job"`
	Replayed bool         `json:"replayed"`
}

func canonical(v any) (json.RawMessage, string, error) {
	data, err := json.Marshal(v)
	return data, secure.Digest(data), err
}
func normalizeProfile(p Profile) (Profile, error) {
	if p.Schema != 1 || !modelPattern.MatchString(p.Model) || !hashPattern.MatchString(p.ModelDigest) || !hashPattern.MatchString(p.TokenizerDigest) {
		return p, ErrInput
	}
	endpoint, err := url.Parse(p.Endpoint)
	if err != nil || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || (endpoint.Path != "" && endpoint.Path != "/") || endpoint.Hostname() == "" || len(p.Endpoint) > 2048 {
		return p, ErrInput
	}
	ip := net.ParseIP(endpoint.Hostname())
	local := ip != nil && ip.IsLoopback()
	if endpoint.Scheme == "http" {
		if !local {
			return p, ErrInput
		}
	} else if endpoint.Scheme != "https" {
		return p, ErrInput
	}
	if !local && !p.AllowRemote {
		return p, ErrInput
	}
	if p.ContextBytes == 0 {
		p.ContextBytes = 8192
	}
	if p.ContextTokens == 0 {
		p.ContextTokens = 4096
	}
	if p.OutputTokens == 0 {
		p.OutputTokens = 512
	}
	if p.TimeoutSeconds == 0 {
		p.TimeoutSeconds = 30
	}
	if p.ContextBytes < 256 || p.ContextBytes > 12<<10 || p.ContextTokens < 1024 || p.ContextTokens > 8192 || p.OutputTokens < 32 || p.OutputTokens > 1024 || p.TimeoutSeconds < 1 || p.TimeoutSeconds > 60 {
		return p, ErrInput
	}
	p.Endpoint = strings.TrimSuffix(p.Endpoint, "/")
	return p, nil
}

// Bump this version whenever a change affects which operator text can leave.
const operatorTextPolicy = "credential-guard-v4"

var credentialField = regexp.MustCompile(`(?i)\b(?:[a-z0-9]+[-_])*(?:authorization|cookie|password|passwd|secret|api[-_ ]?key|access[-_ ]?key|token)["']?\s*[:=]`)

// The administrator policy and exact-context approval govern disclosure.
var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bBearer\s+["']?[A-Za-z0-9._~+/-]+=*`),
	regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^\s]+`),
	regexp.MustCompile(`\b[A-Za-z0-9_+/=-]{32,}\b`),
}

func redact(text string, privateLabels map[string]string) (string, error) {
	if len(text) > 4096 || !utf8.ValidString(text) {
		return "", ErrInput
	}
	for _, r := range text {
		if unicode.IsControl(r) && r != '\n' && r != '\t' && r != '\r' {
			return "", ErrInput
		}
	}
	upper := strings.ToUpper(text)
	if strings.Contains(upper, "PRIVATE KEY") || strings.Contains(upper, "-----BEGIN PGP") {
		return "[private key material redacted]", nil
	}
	// Credential fields may have quoted, compound or multiline values.
	// Suppress the entire input before parsing or replacing private labels.
	if credentialField.MatchString(text) {
		return "[credential-bearing text redacted]", nil
	}
	// Find both sets on the original text. Replacing a generic match first can
	// split an exact path into a private prefix and a masked suffix. Replacing a
	// label first can interrupt a longer bearer token and leave its tail behind.
	type span struct {
		end   int
		value string
	}
	spans := make([]span, len(text))
	for label, replacement := range privateLabels {
		if label == "" {
			continue
		}
		for offset := 0; offset+len(label) <= len(text); {
			n := strings.Index(text[offset:], label)
			if n < 0 {
				break
			}
			start := offset + n
			end := start + len(label)
			if end > spans[start].end {
				spans[start] = span{end, replacement}
			}
			offset = start + 1
		}
	}
	for _, pattern := range secretPatterns {
		for _, match := range pattern.FindAllStringIndex(text, -1) {
			if start, end := match[0], match[1]; end > spans[start].end {
				spans[start] = span{end, "[redacted]"}
			}
		}
	}
	var output strings.Builder
	written := 0
	for start := 0; start < len(text); {
		match := spans[start]
		if match.end == 0 {
			start++
			continue
		}
		// Keep exact label aliases for a fully contained generic match.
		// For a partial overlap, cover both ranges with a single safe marker.
		for next := start + 1; next < match.end; next++ {
			if spans[next].end > match.end {
				match = span{spans[next].end, "[redacted]"}
			}
		}
		output.WriteString(text[written:start])
		output.WriteString(match.value)
		written, start = match.end, match.end
	}
	output.WriteString(text[written:])
	return strings.TrimSpace(output.String()), nil
}
