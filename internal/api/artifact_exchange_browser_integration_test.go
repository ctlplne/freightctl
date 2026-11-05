//go:build integration && exchangebrowser

package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
)

type exchangeBrowserSummary struct {
	State         string `json:"state"`
	Phase         string `json:"phase"`
	Egress        *int   `json:"external_egress"`
	Downloads     *int   `json:"exact_downloads"`
	Declines      *int   `json:"terminal_declines"`
	Model         *bool  `json:"model_started"`
	Sandbox       *bool  `json:"browser_sandbox"`
	Accessibility *int   `json:"accessibility_checks"`
	Browser       string `json:"browser_version"`
	Node          string `json:"node_version"`
	Axe           string `json:"axe_version"`
	FailureHash   string `json:"failure_sha256,omitempty"`
}

func TestExchangeBrowserSummaryRefusesAmbiguousEvidence(t *testing.T) {
	valid := `{"state":"passed","phase":"complete","external_egress":0,"exact_downloads":1,"terminal_declines":1,"model_started":false,"browser_sandbox":true,"accessibility_checks":6,"browser_version":"142.0.1","node_version":"v26.13.0","axe_version":"4.14.0"}`
	for _, raw := range []string{
		strings.Replace(valid, `"external_egress":0`, `"external_egress":1,"external_egress":0`, 1),
		strings.Replace(valid, `"model_started":false`, `"model_started":true,"MODEL_STARTED":false`, 1),
		strings.Replace(valid, `"model_started":false,`, "", 1),
		strings.Replace(valid, `"model_started":false`, `"model_started":null`, 1),
		strings.Replace(valid, `"terminal_declines":1,`, "", 1),
		strings.Replace(valid, `"terminal_declines":1`, `"terminal_declines":0,"terminal_declines":1`, 1),
		strings.Replace(valid, `"phase":"complete"`, `"phase":"private-path-and-credential"`, 1),
		strings.Replace(valid, `"node_version":"v26.13.0"`, `"node_version":"v25.0.0"`, 1),
		valid + `{}`,
	} {
		path := filepath.Join(t.TempDir(), "result.json")
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if summary, _ := readExchangeBrowserSummary(path); summary != nil {
			t.Fatal("ambiguous or incomplete browser evidence accepted")
		}
	}
	path := filepath.Join(t.TempDir(), "result.json")
	if err := os.WriteFile(path, []byte(valid), 0600); err != nil {
		t.Fatal(err)
	}
	if summary, hash := readExchangeBrowserSummary(path); summary == nil || hash != secure.Digest([]byte(valid)) {
		t.Fatal("complete exact evidence refused")
	}
}

func readExchangeBrowserSummary(path string) (*exchangeBrowserSummary, string) {
	f, err := os.Open(path)
	if err != nil {
		return nil, "unavailable"
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(raw) > 4096 {
		return nil, "unavailable"
	}
	hash := secure.Digest(raw)
	// A repeated field cannot erase an earlier failed observation. This result
	// is a flat scalar document; decoding the typed shape alone accepts aliases.
	keys := json.NewDecoder(bytes.NewReader(raw))
	first, err := keys.Token()
	if err != nil || first != json.Delim('{') {
		return nil, hash
	}
	seen := map[string]bool{}
	allowed := map[string]bool{"state": true, "phase": true, "external_egress": true, "exact_downloads": true, "terminal_declines": true, "model_started": true, "browser_sandbox": true, "accessibility_checks": true, "browser_version": true, "node_version": true, "axe_version": true, "failure_sha256": true}
	for keys.More() {
		field, err := keys.Token()
		name, ok := field.(string)
		if err != nil || !ok || seen[name] || !allowed[name] {
			return nil, hash
		}
		seen[name] = true
		var value json.RawMessage
		if keys.Decode(&value) != nil {
			return nil, hash
		}
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var s exchangeBrowserSummary
	var tail any
	if d.Decode(&s) != nil || d.Decode(&tail) != io.EOF || s.Egress == nil || s.Downloads == nil || s.Declines == nil || s.Model == nil || s.Sandbox == nil || s.Accessibility == nil || *s.Egress < 0 || *s.Downloads < 0 || *s.Downloads > 1 || *s.Declines < 0 || *s.Declines > 1 || *s.Accessibility < 0 || *s.Accessibility > 6 {
		return nil, hash
	}
	switch s.Phase {
	case "launch", "recipient-login", "recipient-directory", "recipient-discovery", "receive-accessibility", "recipient-details", "details-accessibility", "exact-download", "recipient-decline-review", "decline-review-accessibility", "recipient-decline", "declined-retrieval", "declined-discovery", "declined-accessibility", "unrelated-directory", "unrelated-discovery", "unrelated-accessibility", "revocation-barrier", "revoked-discovery", "revoked-accessibility", "complete":
	default:
		return nil, hash
	}
	if s.State != "passed" && s.State != "failed" || len(s.Browser) > 80 || s.Browser != "" && !regexp.MustCompile(`^[0-9.]+$`).MatchString(s.Browser) || s.Node != "v26.13.0" || s.Axe != "4.14.0" || s.FailureHash != "" && !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(s.FailureHash) {
		return nil, hash
	}
	return &s, hash
}

func TestArtifactExchangeNativeBrowserReceiptWrongActorAndRevocation(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "true" || runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Fatal("this explicit Chrome/PostgreSQL profile requires its authorized native GitHub Linux x86_64 job")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	settings := custody.ExchangeSettings{MaxLifetime: time.Hour, MaxSenders: 16, MaxOpenViews: 128, MaxEndpoints: 16}
	s, administrator, _, server := browserAPI(t, 600*time.Second, settings)
	t.Cleanup(func() { _ = s.Disk.Close() })
	participant := func(permissions []string) (string, store.Scope, store.ExchangeParticipant) {
		path := filepath.Join(t.TempDir(), "credential")
		if err := secure.WriteToken(path); err != nil {
			t.Fatal(err)
		}
		token, err := secure.ReadSecret(path, 64)
		if err != nil {
			t.Fatal(err)
		}
		proof := secure.Digest(token.Bytes)
		token.Close()
		id := secure.NewID()
		if _, err = s.DB.ChangeAccount(ctx, administrator, "browser-participant-"+id, store.AccountCommand{Operation: "create", ID: id, CredentialHash: proof, Policy: &store.AccountPolicy{Label: "Browser exchange participant", Root: "/", Permissions: permissions}}); err != nil {
			t.Fatal(err)
		}
		scope := store.Scope{Tenant: administrator.Tenant, Partner: administrator.Partner, TokenHash: proof}
		identity, err := s.DB.Identity(ctx, scope)
		if err != nil {
			t.Fatal(err)
		}
		return path, scope, store.ExchangeParticipant{Tenant: scope.Tenant, Partner: scope.Partner, Actor: identity.Actor, AuthorityRevision: identity.AuthorityRevision, RootPolicyDigest: identity.RootPolicyDigest}
	}
	_, sender, actorA := participant([]string{"read", "write", "list", "deliver"})
	b, _, actorB := participant([]string{"read", "list"})
	other, _, _ := participant([]string{"read", "list"})
	limits, _, err := s.ExchangeLimits()
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := s.DB.RegisterExchangeEndpoint(ctx, administrator, "browser-receive-endpoint", store.ExchangeEndpointCommand{Operation: "create", ID: secure.NewID(), Definition: &store.ExchangeEndpointDefinition{Schema: 1, Profile: "custody-https-poll-v1", Recipient: actorB, Senders: []store.ExchangeParticipant{actorA}}}, limits, 16)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte(`<script>globalThis.freightctlArtifactExecuted=true</script>`)
	file, _, err := s.Accept(ctx, sender, "browser-artifact", int64(len(data)), secure.Digest(data), bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	offer, err := s.OfferExchange(ctx, sender, "browser-offer", store.ExchangeRequest{Schema: 1, Artifact: store.ExchangeArtifact{ID: file.ID, Size: file.Size, SHA256: file.SHA256, Policy: file.Policy}, Endpoint: store.ExchangeEndpointReference{ID: endpoint.Endpoint.ID, Revision: endpoint.Endpoint.Revision, Hash: endpoint.Endpoint.Hash}, ExpiresAt: time.Now().UTC().Add(2 * time.Minute).Truncate(time.Microsecond), Receipt: "availability-only-v1"})
	if err != nil {
		t.Fatal(err)
	}
	declineOffer, err := s.OfferExchange(ctx, sender, "browser-decline-offer", offer.Exchange.Request)
	if err != nil {
		t.Fatal(err)
	}
	private := t.TempDir()
	if err = os.Chmod(private, 0700); err != nil {
		t.Fatal(err)
	}
	ready, revoked, result := filepath.Join(private, "ready"), filepath.Join(private, "revoked"), filepath.Join(private, "result.json")
	config := map[string]any{"url": server.URL, "tenant": administrator.Tenant, "partner": administrator.Partner, "endpoint": endpoint.Endpoint.ID, "exchange": offer.Exchange.ID, "closure_exchange": declineOffer.Exchange.ID, "closure_request_hash": declineOffer.Exchange.RequestHash, "file": file.ID, "size": file.Size, "sha256": file.SHA256, "recipient_token": b, "unrelated_token": other, "certificate_der": base64.StdEncoding.EncodeToString(server.Certificate().Raw), "download": filepath.Join(private, "download"), "ready": ready, "revoked": revoked, "result": result, "failure": filepath.Join(private, "first-failure.log")}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(private, "config.json")
	if err = os.WriteFile(input, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	output, err := os.OpenFile(filepath.Join(private, "browser.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	command := exec.CommandContext(ctx, "node", "../../scripts/artifact-exchange-browser.mjs", input)
	command.Stdout, command.Stderr = output, output
	command.Cancel = func() error { return command.Process.Signal(os.Interrupt) }
	command.WaitDelay = 5 * time.Second
	if err = command.Start(); err != nil {
		t.Fatal("native browser process did not start")
	}
	defer command.Process.Kill()
	completed := make(chan error, 1)
	go func() { completed <- command.Wait() }()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err = os.Stat(ready); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("browser did not reach revocation barrier")
		case <-completed:
			summary, hash := readExchangeBrowserSummary(result)
			if summary != nil {
				t.Fatalf("browser failed before revocation barrier; phase=%s, result SHA256=%s", summary.Phase, hash)
			}
			t.Fatalf("browser failed before revocation barrier; safe result=%s", hash)
		case <-ticker.C:
		}
	}
	if _, err = s.DB.RegisterExchangeEndpoint(ctx, administrator, "browser-endpoint-revoke", store.ExchangeEndpointCommand{Operation: "revoke", ID: endpoint.Endpoint.ID, ExpectedRevision: 1}, limits, 16); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(revoked, []byte("revoked\n"), 0600); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-completed:
	case <-ctx.Done():
		t.Fatal("browser did not finish after exact endpoint revocation")
	}
	summary, hash := readExchangeBrowserSummary(result)
	if err != nil || summary == nil || summary.State != "passed" || summary.Phase != "complete" || *summary.Egress != 0 || *summary.Downloads != 1 || *summary.Declines != 1 || *summary.Model || !*summary.Sandbox || *summary.Accessibility != 6 || summary.Browser == "" || summary.FailureHash != "" {
		t.Fatalf("native receive browser proof failed; safe result SHA256=%s", hash)
	}
	t.Logf("native receive browser proof passed; exact result SHA256=%s; bytes=%d; Chrome=%s; axe=%s", hash, file.Size, summary.Browser, summary.Axe)
}
