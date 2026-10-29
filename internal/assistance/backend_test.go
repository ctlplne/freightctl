package assistance

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// These peers implement a bounded JSON transport contract, not inference. They
// load no model and establish no model quality or private-profile qualification.
func TestBackendRejectsRedirectDigestAndOversizedResponse(t *testing.T) {
	for _, mode := range []string{"redirect", "digest", "oversized", "truncated", "wrong_model"} {
		t.Run(mode, func(t *testing.T) {
			var generation atomic.Int32
			peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mode == "redirect" {
					http.Redirect(w, r, "http://127.0.0.1:1/should-not-follow", 307)
					return
				}
				if r.URL.Path == "/api/tags" {
					digest := strings.Repeat("a", 64)
					if mode == "digest" {
						digest = strings.Repeat("b", 64)
					}
					json.NewEncoder(w).Encode(map[string]any{"models": []any{map[string]any{"name": "contract-peer", "digest": digest}}})
					return
				}
				generation.Add(1)
				if mode == "oversized" {
					fmt.Fprint(w, strings.Repeat("x", (64<<10)+1))
					return
				}
				model := "contract-peer"
				reason := "stop"
				if mode == "wrong_model" {
					model = "other"
				}
				if mode == "truncated" {
					reason = "length"
				}
				json.NewEncoder(w).Encode(map[string]any{"model": model, "response": `{"status":"ready","order":["d1"],"missing":[]}`, "done": true, "done_reason": reason, "eval_count": 5, "prompt_eval_count": 30})
			}))
			defer peer.Close()
			p, err := normalizeProfile(Profile{Schema: 1, Endpoint: peer.URL, Model: "contract-peer", ModelDigest: strings.Repeat("a", 64), TokenizerDigest: strings.Repeat("b", 64), TimeoutSeconds: 1})
			if err != nil {
				t.Fatal(err)
			}
			data, _, _ := canonical(Context{Schema: 1, Kind: "propose", Destinations: []string{"d1"}})
			if _, err = generate(context.Background(), p, data); err == nil {
				t.Fatal("bad model transport accepted", mode)
			}
			if (mode == "redirect" || mode == "digest") && generation.Load() != 0 {
				t.Fatal("context sent after failed endpoint trust")
			}
		})
	}
}
