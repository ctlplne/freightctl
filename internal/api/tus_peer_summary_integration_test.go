//go:build integration && tuspeer

package api

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ctlplne/freightctl/internal/workflow"
)

type tusPeerSummary struct {
	Kind         string `json:"kind"`
	State        string `json:"state"`
	Phase        string `json:"phase"`
	Client       string `json:"client"`
	Version      string `json:"version"`
	Node         string `json:"node"`
	Architecture string `json:"architecture"`
	Heads        *int   `json:"heads"`
	Patches      *int   `json:"patches"`
	Overrides    *int   `json:"overrides"`
	Failures     *int   `json:"network_failures"`
	Offset       *int64 `json:"checkpoint_offset"`
	Bytes        *int64 `json:"checkpoint_bytes"`
	SHA          string `json:"sha256"`
	Acceptance   string `json:"acceptance"`
	Receiver     string `json:"receiver_persistence"`
	Business     string `json:"business_processing"`
	Verified     *bool  `json:"tls_verified"`
	Creation     *bool  `json:"creation_endpoint"`
	Model        *bool  `json:"model_started"`
	FailureHash  string `json:"failure_sha256,omitempty"`
}

func decodeTusPeerSummary(raw []byte) *tusPeerSummary {
	var s tusPeerSummary
	if len(raw) > 8192 || workflow.Decode(raw, &s) != nil || s.Kind != "native-tus-core-stock-client" || s.Client != "tus-js-client" || s.Version != "4.3.1" || s.Node != "v26.13.0" || (s.Architecture != "x64" && s.Architecture != "arm64") || s.Heads == nil || s.Patches == nil || s.Overrides == nil || s.Failures == nil || s.Offset == nil || s.Bytes == nil || s.Verified == nil || s.Creation == nil || s.Model == nil || *s.Heads < 0 || *s.Patches < 0 || *s.Overrides < 0 || *s.Failures < 0 || *s.Offset < 0 || *s.Bytes < 1 || *s.Offset > *s.Bytes || len(s.SHA) != 64 || strings.Trim(s.SHA, "0123456789abcdef") != "" || s.Acceptance != "checkpoint-only;ordinary completion required" || s.Receiver != "unknown" || s.Business != "unknown" {
		return nil
	}
	if s.State == "passed" {
		if s.Phase != "complete" || s.FailureHash != "" || !*s.Verified || *s.Creation || *s.Model || *s.Offset != *s.Bytes || *s.Heads < 2 || *s.Failures < 1 {
			return nil
		}
	} else if s.State != "failed" || s.Phase != "stock-client" || len(s.FailureHash) != 64 || strings.Trim(s.FailureHash, "0123456789abcdef") != "" {
		return nil
	}
	return &s
}

func TestTusPeerSummaryRejectsMissingDuplicateUnknownAndStrongerEvidence(t *testing.T) {
	value := map[string]any{"kind": "native-tus-core-stock-client", "state": "passed", "phase": "complete", "client": "tus-js-client", "version": "4.3.1", "node": "v26.13.0", "architecture": "x64", "heads": 2, "patches": 3, "overrides": 0, "network_failures": 1, "checkpoint_offset": 131075, "checkpoint_bytes": 131075, "sha256": strings.Repeat("a", 64), "acceptance": "checkpoint-only;ordinary completion required", "receiver_persistence": "unknown", "business_processing": "unknown", "tls_verified": true, "creation_endpoint": false, "model_started": false}
	raw, _ := json.Marshal(value)
	if decodeTusPeerSummary(raw) == nil {
		t.Fatal("complete exact safe summary refused")
	}
	for _, key := range []string{"heads", "patches", "overrides", "network_failures", "checkpoint_offset", "checkpoint_bytes", "tls_verified", "creation_endpoint", "model_started"} {
		v := map[string]any{}
		for k, x := range value {
			v[k] = x
		}
		delete(v, key)
		b, _ := json.Marshal(v)
		if decodeTusPeerSummary(b) != nil {
			t.Fatal("missing required evidence", key)
		}
	}
	for _, extra := range []string{`,"MODEL_STARTED":true}`, `,"model_started":false}`, `,"private_credential":"untrusted"}`, `,"receiver_persistence":"verified"}`} {
		if decodeTusPeerSummary([]byte(strings.TrimSuffix(string(raw), "}")+extra)) != nil {
			t.Fatal("ambiguous/private/stronger evidence accepted")
		}
	}
	for key, changed := range map[string]any{"model_started": true, "creation_endpoint": true, "tls_verified": false, "receiver_persistence": "verified", "business_processing": "complete", "checkpoint_offset": 1, "network_failures": 0, "heads": 1, "phase": "prepared"} {
		v := map[string]any{}
		for k, x := range value {
			v[k] = x
		}
		v[key] = changed
		b, _ := json.Marshal(v)
		if decodeTusPeerSummary(b) != nil {
			t.Fatal("contradictory or stronger evidence accepted", key)
		}
	}
}
