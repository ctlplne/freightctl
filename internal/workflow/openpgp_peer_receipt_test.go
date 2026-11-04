package workflow

import (
	"encoding/json"
	"strings"
	"testing"
)

// The independent peer is untrusted input too. Public test diagnostics admit
// only fixed stage names, never its exception, filename or packet contents.
func aeadPeerFailureStage(data []byte) string {
	if len(data) > 4096 {
		return "unrecognized-proof"
	}
	var v map[string]any
	if json.Unmarshal(data, &v) != nil || len(v) != 6 || v["schema_version"] != float64(1) || v["state"] != "failed" || v["peer"] != "OpenPGP.js" || v["version"] != "6.3.2" || v["profile"] != "seipd-v2-aes256-ocb" {
		return "unrecognized-proof"
	}
	switch v["stage"] {
	case "arguments", "directory", "key-generation", "key-serialization", "fixture-write", "read-inputs", "packet-policy", "decrypt", "integrity-refusals", "result-write":
		return v["stage"].(string)
	}
	return "unrecognized-proof"
}

func TestIndependentAEADFailureDiagnosticOnlyAdmitsFixedStages(t *testing.T) {
	base := map[string]any{"schema_version": 1, "state": "failed", "peer": "OpenPGP.js", "version": "6.3.2", "profile": "seipd-v2-aes256-ocb", "stage": "arguments"}
	for _, stage := range []string{"arguments", "directory", "key-generation", "key-serialization", "fixture-write", "read-inputs", "packet-policy", "decrypt", "integrity-refusals", "result-write"} {
		t.Run(stage, func(t *testing.T) {
			base["stage"] = stage
			raw, _ := json.Marshal(base)
			if aeadPeerFailureStage(raw) != stage {
				t.Fatal("fixed observation lost")
			}
		})
	}
	for name, mutate := range map[string]func(map[string]any){
		"private stage":     func(v map[string]any) { v["stage"] = "/private/recipient.key" },
		"private exception": func(v map[string]any) { v["error"] = "PRIVATE KEY VALUE" },
		"claimed pass":      func(v map[string]any) { v["state"] = "passed" },
		"different peer":    func(v map[string]any) { v["peer"] = "other" },
		"different version": func(v map[string]any) { v["version"] = "automatic" },
		"wrong schema type": func(v map[string]any) { v["schema_version"] = true },
		"unbounded stage":   func(v map[string]any) { v["stage"] = strings.Repeat("x", 8192) },
	} {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(base)
			var v map[string]any
			json.Unmarshal(raw, &v)
			mutate(v)
			raw, _ = json.Marshal(v)
			if aeadPeerFailureStage(raw) != "unrecognized-proof" {
				t.Fatal("untrusted peer text became public")
			}
		})
	}
	if aeadPeerFailureStage([]byte("private stderr\n{}")) != "unrecognized-proof" {
		t.Fatal("non-JSON peer output admitted")
	}
}
