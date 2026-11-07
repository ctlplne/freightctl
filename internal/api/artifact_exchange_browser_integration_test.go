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
	"slices"
	"strings"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

type exchangeBrowserSummary struct {
	HistorySearches  *int   `json:"history_searches"`
	OwnedCopies      *int   `json:"owned_copies"`
	CopyRecoveries   *int   `json:"copy_recoveries"`
	EvidenceReads    *int   `json:"evidence_reads"`
	State            string `json:"state"`
	Phase            string `json:"phase"`
	Egress           *int   `json:"external_egress"`
	Downloads        *int   `json:"exact_downloads"`
	Declines         *int   `json:"terminal_declines"`
	Offers           *int   `json:"committed_offers"`
	Cancels          *int   `json:"sender_cancellations"`
	Recovery         *int   `json:"recovery_roundtrips"`
	EndpointCommands *int   `json:"endpoint_commands"`
	HumanIngress     *int   `json:"human_ingress"`
	OnwardRuns       *int   `json:"onward_runs"`
	OnwardRecoveries *int   `json:"onward_recoveries"`
	OnwardRefusals   *int   `json:"onward_refusals"`
	Model            *bool  `json:"model_started"`
	Sandbox          *bool  `json:"browser_sandbox"`
	Accessibility    *int   `json:"accessibility_checks"`
	Browser          string `json:"browser_version"`
	Node             string `json:"node_version"`
	Axe              string `json:"axe_version"`
	FailureHash      string `json:"failure_sha256,omitempty"`
}

func TestExchangeBrowserSummaryRefusesAmbiguousEvidence(t *testing.T) {
	valid := `{"state":"passed","phase":"complete","external_egress":0,"exact_downloads":2,"terminal_declines":1,"committed_offers":1,"sender_cancellations":1,"recovery_roundtrips":1,"model_started":false,"browser_sandbox":true,"endpoint_commands":3,"human_ingress":1,"onward_runs":1,"onward_recoveries":1,"onward_refusals":1,"evidence_reads":2,"owned_copies":1,"copy_recoveries":1,"history_searches":3,"accessibility_checks":31,"browser_version":"142.0.1","node_version":"v26.13.0","axe_version":"4.14.0"}`
	for _, raw := range []string{
		strings.Replace(valid, `"history_searches":3,`, "", 1),
		strings.Replace(valid, `"history_searches":3`, `"history_searches":0,"HISTORY_SEARCHES":3`, 1),
		strings.Replace(valid, `"owned_copies":1,`, "", 1),
		strings.Replace(valid, `"copy_recoveries":1,`, "", 1),
		strings.Replace(valid, `"owned_copies":1`, `"owned_copies":0,"OWNED_COPIES":1`, 1),
		strings.Replace(valid, `"evidence_reads":2,`, "", 1),
		strings.Replace(valid, `"evidence_reads":2`, `"evidence_reads":0,"EVIDENCE_READS":2`, 1),
		strings.Replace(valid, `"external_egress":0`, `"external_egress":1,"external_egress":0`, 1),
		strings.Replace(valid, `"model_started":false`, `"model_started":true,"MODEL_STARTED":false`, 1),
		strings.Replace(valid, `"model_started":false,`, "", 1),
		strings.Replace(valid, `"model_started":false`, `"model_started":null`, 1),
		strings.Replace(valid, `"terminal_declines":1,`, "", 1),
		strings.Replace(valid, `"committed_offers":1,`, "", 1),
		strings.Replace(valid, `"recovery_roundtrips":1,`, "", 1),
		strings.Replace(valid, `"endpoint_commands":3,`, "", 1),
		strings.Replace(valid, `"human_ingress":1,`, "", 1),
		strings.Replace(valid, `"onward_runs":1,`, "", 1),
		strings.Replace(valid, `"onward_recoveries":1,`, "", 1),
		strings.Replace(valid, `"onward_refusals":1,`, "", 1),
		strings.Replace(valid, `"onward_runs":1`, `"onward_runs":0,"ONWARD_RUNS":1`, 1),
		strings.Replace(valid, `"human_ingress":1`, `"human_ingress":0,"HUMAN_INGRESS":1`, 1),
		strings.Replace(valid, `"endpoint_commands":3`, `"endpoint_commands":0,"ENDPOINT_COMMANDS":3`, 1),
		strings.Replace(valid, `"recovery_roundtrips":1`, `"recovery_roundtrips":0,"RECOVERY_ROUNDTRIPS":1`, 1),
		strings.Replace(valid, `"sender_cancellations":1`, `"sender_cancellations":0,"sender_cancellations":1`, 1),
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

func TestExchangeBrowserSummaryKeepsConfigurationFailuresSafeAndDistinctFromSuccess(t *testing.T) {
	zero, no, yes := 0, false, true
	for _, phase := range []string{"configuration-identities", "configuration-integrity", "configuration-certificate"} {
		summary := exchangeBrowserSummary{State: "failed", Phase: phase, HistorySearches: &zero, OwnedCopies: &zero, CopyRecoveries: &zero, EvidenceReads: &zero, Egress: &zero, Downloads: &zero, Declines: &zero, Offers: &zero, Cancels: &zero, Recovery: &zero, EndpointCommands: &zero, HumanIngress: &zero, OnwardRuns: &zero, OnwardRecoveries: &zero, OnwardRefusals: &zero, Model: &no, Sandbox: &yes, Accessibility: &zero, Node: "v26.13.0", Axe: "4.14.0", FailureHash: secure.Digest([]byte("synthetic private failure"))}
		raw, err := json.Marshal(summary)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "configuration-failure.json")
		if err = os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		observed, hash := readExchangeBrowserSummary(path)
		if observed == nil || observed.Phase != phase || observed.State != "failed" || hash != secure.Digest(raw) || observed.Browser != "" {
			t.Fatal("bounded prelaunch failure lost its safe phase or became success")
		}
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
	allowed := map[string]bool{"state": true, "phase": true, "external_egress": true, "exact_downloads": true, "terminal_declines": true, "committed_offers": true, "sender_cancellations": true, "recovery_roundtrips": true, "endpoint_commands": true, "human_ingress": true, "onward_runs": true, "onward_recoveries": true, "onward_refusals": true, "model_started": true, "browser_sandbox": true, "evidence_reads": true, "owned_copies": true, "copy_recoveries": true, "history_searches": true, "accessibility_checks": true, "browser_version": true, "node_version": true, "axe_version": true, "failure_sha256": true}
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
	if d.Decode(&s) != nil || d.Decode(&tail) != io.EOF || s.Egress == nil || s.Downloads == nil || s.Declines == nil || s.Offers == nil || s.Cancels == nil || s.Recovery == nil || s.EndpointCommands == nil || s.HumanIngress == nil || s.OnwardRuns == nil || s.OnwardRecoveries == nil || s.OnwardRefusals == nil || s.Model == nil || s.Sandbox == nil || s.EvidenceReads == nil || s.OwnedCopies == nil || s.CopyRecoveries == nil || s.HistorySearches == nil || s.Accessibility == nil || *s.EvidenceReads < 0 || *s.EvidenceReads > 2 || *s.Egress < 0 || *s.Downloads < 0 || *s.Downloads > 2 || *s.Declines < 0 || *s.Declines > 1 || *s.Accessibility < 0 || *s.Accessibility > 31 || *s.HistorySearches < 0 || *s.HistorySearches > 3 || *s.OwnedCopies < 0 || *s.OwnedCopies > 1 || *s.CopyRecoveries < 0 || *s.CopyRecoveries > 1 || *s.HumanIngress < 0 || *s.HumanIngress > 1 || *s.OnwardRuns < 0 || *s.OnwardRuns > 1 || *s.OnwardRecoveries < 0 || *s.OnwardRecoveries > 1 || *s.OnwardRefusals < 0 || *s.OnwardRefusals > 1 || *s.EndpointCommands < 0 || *s.EndpointCommands > 3 || *s.Recovery < 0 || *s.Recovery > 1 || *s.Offers < 0 || *s.Offers > 1 || *s.Cancels < 0 || *s.Cancels > 1 {
		return nil, hash
	}
	switch s.Phase {
	case "configuration-identities", "configuration-integrity", "configuration-certificate", "audit-login", "audit-first-page", "audit-first-accessibility", "audit-next-page", "audit-next-accessibility", "audit-resource-search", "audit-resource-accessibility", "copy-login", "copy-review-accessibility", "copy-lost-response", "copy-uncertain-accessibility", "copy-import", "copy-import-accessibility", "copy-recover", "copy-receipt-accessibility", "incoming-evidence", "incoming-evidence-accessibility", "outgoing-evidence", "outgoing-evidence-accessibility", "onward-verify-review", "onward-login", "onward-review", "onward-review-accessibility", "onward-save-recovery", "onward-lost-response", "onward-reload-recovery", "onward-recovery-accessibility", "onward-receipt", "onward-receipt-accessibility", "onward-status", "onward-status-accessibility", "onward-refusal", "onward-refusal-accessibility", "launch", "recipient-login", "recipient-directory", "recipient-discovery", "receive-accessibility", "recipient-details", "details-accessibility", "exact-download", "sender-login", "sender-upload", "sender-upload-accessibility", "sender-human-receive", "sender-human-receive-accessibility", "sender-directory", "sender-review", "sender-review-accessibility", "sender-offer", "sender-receipt-accessibility", "sender-cancel", "sender-save-recovery", "sender-reload-recovery", "sender-recovery-accessibility", "sender-recover-offer", "sender-recover-cancel", "sender-history", "sender-history-accessibility", "sender-history-details", "sender-history-detail-accessibility", "recipient-decline-review", "decline-review-accessibility", "recipient-decline", "declined-retrieval", "declined-discovery", "declined-accessibility", "unrelated-directory", "unrelated-discovery", "unrelated-accessibility", "manager-login", "manager-accounts", "manager-review", "manager-review-accessibility", "manager-create", "manager-create-accessibility", "manager-replay", "manager-replace", "manager-replace-accessibility", "manager-revoke", "manager-revoke-accessibility", "revocation-barrier", "revoked-discovery", "revoked-accessibility", "complete":
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
	// This GitHub-only aggregate uses the runner's platform lifetime (S004).
	// Individual API/DB/read/interaction deadlines remain independently bounded.
	ctx, cancel := context.WithCancel(context.Background())
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
	a, sender, actorA := participant([]string{"read", "write", "list", "deliver"})
	b, recipient, actorB := participant([]string{"read", "list"})
	copyToken, copyScope, copyActor := participant([]string{"read", "write", "list"})
	auditToken, _, auditActor := participant([]string{"read", "list", "audit_read"})
	other, _, _ := participant([]string{"read", "list"})
	managerToken, managerScope, managerActor := participant([]string{"read", "list", "admin", "accounts_manage"})
	onwardPermissions := []string{"read", "write", "list", "deliver", "workflow_manage", "workflow_approve", "workflow_execute"}
	onwardToken, onwardScope, onwardActor := participant(append(slices.Clone(onwardPermissions), "admin", "connections_manage"))
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
	offer, err := s.OfferExchange(ctx, sender, "browser-offer", store.ExchangeRequest{Schema: 1, Artifact: store.ExchangeArtifact{ID: file.ID, Size: file.Size, SHA256: file.SHA256, Policy: file.Policy}, Endpoint: store.ExchangeEndpointReference{ID: endpoint.Endpoint.ID, Revision: endpoint.Endpoint.Revision, Hash: endpoint.Endpoint.Hash}, ExpiresAt: time.Now().UTC().Add(10 * time.Minute).Truncate(time.Microsecond), Receipt: "availability-only-v1"})
	if err != nil {
		t.Fatal(err)
	}
	declineOffer, err := s.OfferExchange(ctx, sender, "browser-decline-offer", offer.Exchange.Request)
	if err != nil {
		t.Fatal(err)
	}
	copyEndpoint, err := s.DB.RegisterExchangeEndpoint(ctx, administrator, "browser-copy-endpoint", store.ExchangeEndpointCommand{Operation: "create", ID: secure.NewID(), Definition: &store.ExchangeEndpointDefinition{Schema: 1, Profile: "custody-https-poll-v1", Recipient: copyActor, Senders: []store.ExchangeParticipant{actorA}}}, limits, 16)
	if err != nil {
		t.Fatal(err)
	}
	copyRequest := offer.Exchange.Request
	copyRequest.Endpoint = store.ExchangeEndpointReference{ID: copyEndpoint.Endpoint.ID, Revision: copyEndpoint.Endpoint.Revision, Hash: copyEndpoint.Endpoint.Hash}
	copyOffer, err := s.OfferExchange(ctx, sender, "browser-copy-offer", copyRequest)
	if err != nil {
		t.Fatal(err)
	}
	private := t.TempDir()
	if err = os.Chmod(private, 0700); err != nil {
		t.Fatal(err)
	}
	ready, revoked, result := filepath.Join(private, "ready"), filepath.Join(private, "revoked"), filepath.Join(private, "result.json")
	// Provision through ordinary trusted operator services. The receive-only
	// participant gets neither these grants nor workflow configuration powers.
	host, hostPub := filepath.Join(private, "onward-host"), filepath.Join(private, "onward-host.pub")
	key, keyPub := filepath.Join(private, "onward-key"), filepath.Join(private, "onward-key.pub")
	if err = secure.GenerateSSHHostIdentity(host, hostPub); err != nil {
		t.Fatal(err)
	}
	if err = secure.GenerateSSHHostIdentity(key, keyPub); err != nil {
		t.Fatal(err)
	}
	wf := &workflow.Service{Custody: s}
	registered, err := wf.RegisterConnection(ctx, onwardScope, "browser-onward-connection", workflow.ConnectionRequest{Address: "127.0.0.1:9", User: "receiver", Directory: "/inbox", HostPublicFile: hostPub, KeyFile: key, KeyPublicFile: keyPub})
	if err != nil {
		t.Fatal(err)
	}
	var connection workflow.ConnectionView
	if json.Unmarshal(registered.Resource, &connection) != nil {
		t.Fatal("onward connection")
	}
	// Trusted operator provisioning is complete. Remove its explicit bootstrap
	// grants before task approval,source acceptance or any browser login. The
	// runtime journey must use only its separately granted onward permissions.
	onwardAccount, err := s.DB.Account(ctx, administrator, onwardActor.Actor)
	if err != nil {
		t.Fatal(err)
	}
	onwardPolicy := onwardAccount.AccountPolicy
	onwardPolicy.Permissions = slices.Clone(onwardPermissions)
	if _, err = s.DB.ChangeAccount(ctx, administrator, "browser-finish-onward-provisioning", store.AccountCommand{Operation: "update", ID: onwardActor.Actor, ExpectedRevision: onwardAccount.Revision, Policy: &onwardPolicy}); err != nil {
		t.Fatal(err)
	}
	onwardIdentity, err := s.DB.Identity(ctx, onwardScope)
	wantPermissions := slices.Clone(onwardPermissions)
	slices.Sort(wantPermissions)
	if err != nil || onwardIdentity.Actor != onwardActor.Actor || onwardIdentity.RootPolicyDigest != onwardActor.RootPolicyDigest || onwardIdentity.AuthorityRevision != onwardActor.AuthorityRevision+1 || !slices.Equal(onwardIdentity.Permissions, wantPermissions) {
		t.Fatal("browser onward actor retained operator authority or changed identity", err)
	}
	drafted, err := wf.Draft(ctx, onwardScope, "browser-onward-draft", workflow.DraftRequest{Definition: workflow.Definition{Schema: 1, Name: "Browser reviewed onward", Steps: []workflow.Step{{ID: "send", Kind: "sftp.deliver", Connection: workflow.Reference{ID: connection.ID, Version: connection.Version, Hash: connection.Hash}, Filename: "onward.bin"}}}})
	if err != nil {
		t.Fatal(err)
	}
	var configuration store.Configuration
	if json.Unmarshal(drafted.Resource, &configuration) != nil {
		t.Fatal("onward draft")
	}
	if _, err = wf.Decide(ctx, onwardScope, configuration.ID, configuration.Version, "browser-onward-approve", "approve", workflow.Decision{Hash: configuration.Hash, Revision: configuration.Revision}); err != nil {
		t.Fatal(err)
	}
	onwardFile, _, err := s.Accept(ctx, onwardScope, "browser-onward-source", int64(len(data)), secure.Digest(data), bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}

	uploadSource := filepath.Join(private, "human-upload-source.json")
	if err = os.WriteFile(uploadSource, data, 0600); err != nil {
		t.Fatal(err)
	}
	config := map[string]any{"url": server.URL, "tenant": administrator.Tenant, "partner": administrator.Partner, "endpoint": endpoint.Endpoint.ID, "exchange": offer.Exchange.ID, "closure_exchange": declineOffer.Exchange.ID, "closure_request_hash": declineOffer.Exchange.RequestHash, "file": file.ID, "size": file.Size, "sha256": file.SHA256, "recipient_token": b, "sender_token": a, "sender_actor": actorA.Actor, "recipient_actor": actorB.Actor, "unrelated_token": other, "manager_token": managerToken, "manager_actor": managerActor.Actor, "upload_source": uploadSource, "human_download": filepath.Join(private, "human-download"), "certificate_der": base64.StdEncoding.EncodeToString(server.Certificate().Raw), "download": filepath.Join(private, "download"), "recovery": filepath.Join(private, "recovery.json"), "ready": ready, "revoked": revoked, "result": result, "failure": filepath.Join(private, "first-failure.log")}
	config["onward_token"], config["onward_file"], config["onward_workflow"], config["onward_hash"], config["onward_recovery"] = onwardToken, onwardFile.ID, configuration.ID, configuration.Hash, filepath.Join(private, "onward-recovery.json")
	config["copy_token"], config["copy_actor"], config["copy_endpoint"], config["copy_exchange"], config["copy_request_hash"], config["copy_recovery"] = copyToken, copyActor.Actor, copyEndpoint.Endpoint.ID, copyOffer.Exchange.ID, copyOffer.Exchange.RequestHash, filepath.Join(private, "copy-recovery.json")
	config["audit_token"], config["audit_actor"], config["audit_event"] = auditToken, auditActor.Actor, file.EventID
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
			trace := safeExchangeBrowserFailure(private)
			exit := -1
			if command.ProcessState != nil {
				exit = command.ProcessState.ExitCode()
			}
			t.Fatalf("browser failed before revocation barrier;safe result=%s;exit=%d;class=%s;source=%d:%d;private log SHA256=%s", hash, exit, trace.Class, trace.Line, trace.Column, trace.SHA256)
		case <-ticker.C:
		}
	}
	live, err := s.InspectExchange(ctx, recipient, offer.Exchange.ID)
	if err != nil || live.State != "offered" {
		t.Fatal("original receive grant must remain live immediately before endpoint revocation", err)
	}
	if _, err = s.DB.RegisterExchangeEndpoint(ctx, administrator, "browser-endpoint-revoke", store.ExchangeEndpointCommand{Operation: "revoke", ID: endpoint.Endpoint.ID, ExpectedRevision: 1}, limits, 16); err != nil {
		t.Fatal(err)
	}
	currentWorkflow, err := wf.Configuration(ctx, onwardScope, configuration.ID, configuration.Version)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = wf.Decide(ctx, onwardScope, configuration.ID, configuration.Version, "browser-onward-revoke", "revoke", workflow.Decision{Hash: currentWorkflow.Hash, Revision: currentWorkflow.Revision}); err != nil {
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
	if err != nil || summary == nil || summary.State != "passed" || summary.Phase != "complete" || *summary.Egress != 0 || *summary.Downloads != 2 || *summary.Declines != 1 || *summary.Offers != 1 || *summary.Cancels != 1 || *summary.Recovery != 1 || *summary.Model || !*summary.Sandbox || *summary.EvidenceReads != 2 || *summary.Accessibility != 31 || *summary.HistorySearches != 3 || *summary.OwnedCopies != 1 || *summary.CopyRecoveries != 1 || *summary.OnwardRuns != 1 || *summary.OnwardRecoveries != 1 || *summary.OnwardRefusals != 1 || *summary.HumanIngress != 1 || *summary.EndpointCommands != 3 || summary.Browser == "" || summary.FailureHash != "" {
		t.Fatalf("native receive browser proof failed; safe result SHA256=%s", hash)
	}
	proof, err := s.DB.Begin(ctx, sender)
	if err != nil {
		t.Fatal(err)
	}
	defer proof.Tx.Rollback(ctx)
	var offers, receipts, closures int
	if err = proof.Tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM artifact_exchanges WHERE sender_actor_id=$1 AND exchange_id<>$2),(SELECT count(*) FROM artifact_exchange_commands WHERE actor_id=$1 AND exchange_id<>$2),(SELECT count(*) FROM artifact_exchange_closures)`, actorA.Actor, copyOffer.Exchange.ID).Scan(&offers, &receipts, &closures); err != nil || offers != 3 || receipts != 3 || closures != 2 {
		t.Fatal("saved browser retries changed durable view/receipt/decision counts", offers, receipts, closures, err)
	}
	copyProof, err := s.DB.Begin(ctx, copyScope)
	if err != nil {
		t.Fatal(err)
	}
	var copyFiles, copyReceipts, copyBindings, copyEvents int
	err = copyProof.Tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM files f JOIN events e ON e.event_id=f.accepted_event_id WHERE e.actor_id=$1),(SELECT count(*) FROM idempotency WHERE actor_id=$1),(SELECT count(*) FROM namespace_entries WHERE owner_actor_id=$1 AND path='/browser-owned-copy.dat' AND mode=384 AND NOT deleted),(SELECT count(*) FROM events WHERE actor_id=$1 AND kind='FileAccepted' AND payload->'schema_version'='4'::jsonb AND payload->'exchange_copy'->>'exchange_id'=$2)`, copyActor.Actor, copyOffer.Exchange.ID).Scan(&copyFiles, &copyReceipts, &copyBindings, &copyEvents)
	copyProof.Tx.Rollback(ctx)
	if err != nil || copyFiles != 1 || copyReceipts != 1 || copyBindings != 1 || copyEvents != 1 {
		t.Fatal("browser copy replay changed custody/provenance cardinality", err, copyFiles, copyReceipts, copyBindings, copyEvents)
	}

	var uploadBindings int
	if err = proof.Tx.QueryRow(ctx, `SELECT count(*) FROM upload_sessions u JOIN artifact_exchanges e ON e.file_id=u.file_id AND e.sender_actor_id=u.actor_id WHERE u.actor_id=$1 AND u.state='completed' AND u.expected_size=$2 AND u.expected_sha256=$3 AND e.file_id<>$4`, actorA.Actor, file.Size, file.SHA256, file.ID).Scan(&uploadBindings); err != nil || uploadBindings != 1 {
		t.Fatal("human offer did not bind exactly one actual completed upload", uploadBindings, err)
	}
	if err = proof.Tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	management, err := s.DB.Begin(ctx, managerScope)
	if err != nil {
		t.Fatal(err)
	}
	defer management.Tx.Rollback(ctx)
	var versions, commands, revokedHeads int
	if err = management.Tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM exchange_endpoint_versions WHERE recorded_by=$1),(SELECT count(*) FROM exchange_endpoint_commands WHERE actor_id=$1),(SELECT count(*) FROM exchange_endpoint_heads h JOIN exchange_endpoint_versions v USING(tenant_id,partner_id,endpoint_id,revision) WHERE v.recorded_by=$1 AND v.state='revoked' AND v.revision=3)`, managerActor.Actor).Scan(&versions, &commands, &revokedHeads); err != nil || versions != 3 || commands != 3 || revokedHeads != 1 {
		t.Fatal("browser manager retry changed immutable versions/receipts/head", versions, commands, revokedHeads, err)
	}
	if err = management.Tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	onwardProof, err := s.DB.Begin(ctx, onwardScope)
	if err != nil {
		t.Fatal(err)
	}
	defer onwardProof.Tx.Rollback(ctx)
	var onwardRuns, onwardIntents, onwardReceipts, onwardAttempts int
	if err = onwardProof.Tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM workflow_runs WHERE actor_id=$1),(SELECT count(*) FROM delivery_intents WHERE actor_id=$1),(SELECT coalesce(sum(attempts),0) FROM delivery_intents WHERE actor_id=$1)`, onwardProof.Actor).Scan(&onwardRuns, &onwardIntents, &onwardAttempts); err != nil {
		t.Fatal(err)
	}
	// The original run's private receipt is one of the operator's configuration
	// receipts. Bind it by its exact run instead of counting setup commands.
	if err = onwardProof.Tx.QueryRow(ctx, `SELECT count(*) FROM workflow_receipts wr JOIN workflow_runs r ON r.run_id=wr.resource_id AND r.actor_id=wr.actor_id WHERE r.actor_id=$1`, onwardProof.Actor).Scan(&onwardReceipts); err != nil || onwardRuns != 1 || onwardIntents != 1 || onwardReceipts != 1 || onwardAttempts != 0 {
		t.Fatal("browser onward recovery/refusal changed durable run/intents/receipt/attempts", onwardRuns, onwardIntents, onwardReceipts, onwardAttempts, err)
	}
	if err = onwardProof.Tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	t.Logf("native receive browser proof passed; exact result SHA256=%s; bytes=%d; Chrome=%s; axe=%s", hash, file.Size, summary.Browser, summary.Axe)
}
