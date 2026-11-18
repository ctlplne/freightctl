package assistance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ctlplne/freightctl/internal/store"
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
			data, hash, _ := canonical(Context{Schema: 1, Kind: "propose", Destinations: []string{"d1"}})
			if _, err = generate(context.Background(), p, data, hash); err == nil {
				t.Fatal("bad model transport accepted", mode)
			}
			if (mode == "redirect" || mode == "digest") && generation.Load() != 0 {
				t.Fatal("context sent after failed endpoint trust")
			}
		})
	}
}

func TestBackendRequiresExactApprovedContextBeforeAnyContact(t *testing.T) {
	_, hash, _ := canonical(Context{Schema: 1, Kind: "propose", Destinations: []string{"d1"}})
	for _, tc := range []struct {
		name, data string
		want       error
	}{
		{"changed alias", `{"schema_version":1,"kind":"propose","destinations":["d2"]}`, store.ErrRevision},
		{"extra field", `{"schema_version":1,"kind":"propose","destinations":["d1"],"extra":"inert-fixture"}`, store.ErrState},
		{"duplicate kind", `{"schema_version":1,"kind":"propose","kind":"diagnose","destinations":["d1"]}`, store.ErrState},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var hits atomic.Int32
			peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				http.Error(w, "fixture refuses all contact", http.StatusForbidden)
			}))
			defer peer.Close()
			p, err := normalizeProfile(Profile{Schema: 1, Endpoint: peer.URL, Model: "contract-peer", ModelDigest: strings.Repeat("a", 64), TokenizerDigest: strings.Repeat("b", 64), TimeoutSeconds: 1})
			if err != nil {
				t.Fatal(err)
			}
			_, err = generate(t.Context(), p, json.RawMessage(tc.data), hash)
			if !errors.Is(err, tc.want) || hits.Load() != 0 {
				t.Fatal("unapproved context caused endpoint contact")
			}
		})
	}
}

func TestBackendSendsCanonicalApprovedContextAfterStorageRoundTrip(t *testing.T) {
	contextData, hash, _ := canonical(Context{Schema: 1, Kind: "propose", Destinations: []string{"d1"}})
	var hits atomic.Int32
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.URL.Path {
		case "/api/tags":
			json.NewEncoder(w).Encode(map[string]any{"models": []any{map[string]any{"name": "contract-peer", "digest": strings.Repeat("a", 64)}}})
		case "/api/generate":
			var request struct {
				Prompt string `json:"prompt"`
			}
			if json.NewDecoder(r.Body).Decode(&request) != nil || !strings.Contains(request.Prompt, "\nCONTEXT:\n"+string(contextData)+"\nSCHEMA:\n") {
				t.Error("wire context differs from the approved canonical bytes")
			}
			json.NewEncoder(w).Encode(map[string]any{"model": "contract-peer", "response": `{"status":"ready","order":["d1"],"missing":[]}`, "done": true, "done_reason": "stop", "eval_count": 5, "prompt_eval_count": 30})
		default:
			t.Error("unexpected request")
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer peer.Close()
	p, err := normalizeProfile(Profile{Schema: 1, Endpoint: peer.URL, Model: "contract-peer", ModelDigest: strings.Repeat("a", 64), TokenizerDigest: strings.Repeat("b", 64), TimeoutSeconds: 1})
	if err != nil {
		t.Fatal(err)
	}
	reordered := json.RawMessage(`{"kind": "propose", "destinations": ["d1"], "schema_version": 1}`)
	if _, err = generate(t.Context(), p, reordered, hash); err != nil || hits.Load() != 2 {
		t.Fatal("matching context could not reach the bounded endpoint contract", err)
	}
}
