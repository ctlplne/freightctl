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
	Schema       int       `json:"schema_version"`
	Kind         string    `json:"kind"`
	Requirements string    `json:"operator_text,omitempty"`
	Destinations []string  `json:"destinations,omitempty"`
	Facts        []Fact    `json:"facts,omitempty"`
	Supported    []Finding `json:"supported_findings,omitempty"`
}
type Bindings struct {
	Request   PrepareRequest        `json:"request"`
	Snapshots []Snapshot            `json:"snapshots"`
	Evidence  map[string][]Citation `json:"evidence"`
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

// Redaction is a guard for recognizable secrets, not a grant to disclose text.
// The administrator policy and exact-context approval remain mandatory.
var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`),
	regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*`),
	regexp.MustCompile(`(?i)\b(password|passwd|secret|api[_ -]?key|token|authorization)\s*[:=]\s*[^\s,;]+`),
	regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^\s]+`),
	regexp.MustCompile(`\b[A-Za-z0-9_+/=-]{32,}\b`),
}

func redact(text string, privateLabels []string) (string, error) {
	if len(text) > 4096 || !utf8.ValidString(text) {
		return "", ErrInput
	}
	for _, r := range text {
		if unicode.IsControl(r) && r != '\n' && r != '\t' && r != '\r' {
			return "", ErrInput
		}
	}
	if strings.Contains(text, "PRIVATE KEY") || strings.Contains(text, "-----BEGIN PGP") {
		return "[private key material redacted]", nil
	}
	for _, label := range privateLabels {
		if label != "" {
			text = strings.ReplaceAll(text, label, "[label redacted]")
		}
	}
	for _, pattern := range secretPatterns {
		text = pattern.ReplaceAllString(text, "[redacted]")
	}
	return strings.TrimSpace(text), nil
}
