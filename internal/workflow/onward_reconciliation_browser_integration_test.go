//go:build integration && exchangebrowser && (linux || darwin)

package workflow

import (
	"encoding/json"
	"encoding/pem"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestStockSFTPOnwardBrowserRecoversOriginalReceiverCheck(t *testing.T) {
	stockOnwardWorkerDeath(t, checkReceiverInBrowser)
}

func checkReceiverInBrowser(t *testing.T, f *fixture, client stockExchangeHTTPS, token string, scope store.Scope, review *OnwardReview, recovery OnwardReconcileRequest) (OnwardReconciliation, string) {
	t.Helper()
	identity, err := f.s.Custody.DB.Identity(f.ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	address, err := url.Parse(client.prefix)
	if err != nil {
		t.Fatal(err)
	}
	origin := address.Scheme + "://" + address.Host
	pemBytes, err := os.ReadFile(client.certificate)
	certificate, _ := pem.Decode(pemBytes)
	if err != nil || certificate == nil || certificate.Type != "CERTIFICATE" {
		t.Fatal("exact fixture certificate unavailable", err)
	}
	dir, err := os.MkdirTemp("../../.private", "freightctl-onward-reconcile-browser-")
	if err != nil {
		t.Fatal(err)
	}
	dir, err = filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if !t.Failed() {
			if err := os.RemoveAll(dir); err != nil {
				t.Error(err)
			}
		}
	})
	config, result, imported, exported := filepath.Join(dir, "config.json"), filepath.Join(dir, "result.json"), filepath.Join(dir, "original.json"), filepath.Join(dir, "saved.json")
	privateJSON := func(path string, value any) {
		t.Helper()
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	privateJSON(imported, map[string]any{
		"schema_version": 1, "profile": "freightctl-onward-recovery-v1", "server_origin": origin,
		"participant": store.ExchangeParticipant{Tenant: scope.Tenant, Partner: scope.Partner, Actor: identity.Actor, AuthorityRevision: identity.AuthorityRevision, RootPolicyDigest: identity.RootPolicyDigest},
		"review":      review, "request_key": recovery.ReceiptKey, "expected_run_id": recovery.RunID,
	})
	privateJSON(config, map[string]any{
		"origin": origin, "prefix": client.prefix, "tenant": scope.Tenant, "partner": scope.Partner, "token": token,
		"certificate_der": certificate.Bytes, "review_file": imported, "saved_file": exported,
		"request": recovery, "result": result,
	})
	child := exec.CommandContext(f.ctx, "node", "../../scripts/stock-onward-reconcile-browser.mjs", config)
	child.Cancel = func() error { return child.Process.Signal(os.Interrupt) }
	child.WaitDelay = 5 * time.Second
	output, runErr := child.CombinedOutput()
	if err = os.WriteFile(filepath.Join(dir, "browser.log"), output, 0600); err != nil {
		t.Fatal(err)
	}
	var summary struct {
		Phase         string               `json:"phase"`
		Browser       string               `json:"browser_version"`
		Sandbox       bool                 `json:"browser_sandbox"`
		Requests      int                  `json:"reconcile_requests"`
		WorkRequests  int                  `json:"work_requests"`
		Accessibility int                  `json:"accessibility_checks"`
		Egress        int                  `json:"external_egress"`
		Errors        int                  `json:"runtime_errors"`
		Key           string               `json:"request_key"`
		Original      OnwardReconciliation `json:"original"`
	}
	data, err := os.ReadFile(result)
	if err != nil || json.Unmarshal(data, &summary) != nil || runErr != nil || summary.Phase != "complete" || !summary.Sandbox ||
		summary.Requests != 2 || summary.WorkRequests != 0 || summary.Accessibility != 2 || summary.Egress != 0 || summary.Errors != 0 || !store.ValidID(summary.Key) {
		t.Fatalf("browser receiver check failed; phase=%q; output_sha256=%s; private_fixture=%s; error=%v", summary.Phase, secure.Digest(output), filepath.Base(dir), runErr)
	}
	t.Logf("stock browser receiver check passed; browser=%s; requests=%d; work=%d; accessibility=%d; egress=%d", summary.Browser, summary.Requests, summary.WorkRequests, summary.Accessibility, summary.Egress)
	return summary.Original, summary.Key
}
