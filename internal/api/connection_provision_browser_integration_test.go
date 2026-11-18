//go:build integration && provisionbrowser && (linux || darwin)

package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func TestConnectionProvisionNativeBrowserRecoversOriginalAssignment(t *testing.T) {
	service, manager, _, server := browserAPI(t, 10*time.Minute)
	t.Cleanup(func() { _ = service.Disk.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	dir, err := os.MkdirTemp("../../.private", "freightctl-provision-browser-")
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
	account := func(name string, permissions ...string) (store.Scope, string, string) {
		t.Helper()
		file := filepath.Join(dir, name+".token")
		if err := secure.WriteToken(file); err != nil {
			t.Fatal(err)
		}
		secret, err := secure.ReadSecret(file, 64)
		if err != nil {
			t.Fatal(err)
		}
		scope := store.Scope{Tenant: manager.Tenant, Partner: manager.Partner, TokenHash: secure.Digest(secret.Bytes)}
		secret.Close()
		command := store.AccountCommand{Operation: "create", ID: secure.NewID(), CredentialHash: scope.TokenHash,
			Policy: &store.AccountPolicy{Label: name, Root: "/", Permissions: permissions}}
		if _, err = service.DB.ChangeAccount(ctx, manager, "create-"+name, command); err != nil {
			t.Fatal(err)
		}
		return scope, file, command.ID
	}
	operator, operatorFile, operatorID := account("Route-operator", "admin", "connections_manage")
	recipient, recipientFile, recipientID := account("Receiving-agent", "read", "deliver", "workflow_execute")
	account("Second-agent", "read", "deliver", "workflow_execute")
	account("Receiving-only", "read", "list")

	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	for _, key := range []string{"host", "client"} {
		if err := secure.GenerateSSHHostIdentity(filepath.Join(dir, key), filepath.Join(dir, key+".pub")); err != nil {
			t.Fatal(err)
		}
	}
	control := &workflow.Service{Custody: service}
	register := func(scope store.Scope, directory string) workflow.ConnectionView {
		t.Helper()
		result, err := control.RegisterConnection(ctx, scope, "register-"+directory[1:], workflow.ConnectionRequest{
			Address: listener.Addr().String(), User: "freightctl-peer", Directory: directory,
			HostPublicFile: filepath.Join(dir, "host.pub"), KeyFile: filepath.Join(dir, "client"), KeyPublicFile: filepath.Join(dir, "client.pub"),
		})
		var view workflow.ConnectionView
		if err != nil || json.Unmarshal(result.Resource, &view) != nil {
			t.Fatal("fixture connection registration failed", err)
		}
		return view
	}
	source := register(operator, "/settlement")
	register(operator, "/alternate")
	foreign := register(manager, "/other-operator")
	for _, kind := range []string{"sources", "recipients"} {
		value, err := control.ConnectionProvisionChoices(ctx, operator, kind, "", 1)
		var next string
		switch page := value.(type) {
		case *workflow.CollectionConnectionPage:
			if len(page.Connections) == 1 && page.Connections[0].ID != foreign.ID {
				next = page.Next
			}
		case workflow.ConnectionProvisionRecipientPage:
			if len(page.Recipients) == 1 && page.Recipients[0].ID != operatorID {
				next = page.Next
			}
		}
		if err != nil || !store.ValidID(next) {
			t.Fatal("operator list lost its scoped page or continuation", err)
		}
		if _, err = control.ConnectionProvisionChoices(ctx, operator, kind, next, 1); err != nil {
			t.Fatal("operator list could not continue", err)
		}
	}
	resultFile, configuration := filepath.Join(dir, "result.json"), filepath.Join(dir, "browser.json")
	input, err := json.Marshal(map[string]any{
		"url": server.URL, "tenant": operator.Tenant, "partner": operator.Partner,
		"certificate_der": base64.StdEncoding.EncodeToString(server.Certificate().Raw),
		"operator":        operatorFile, "recipient": recipientFile, "recipient_id": recipientID,
		"source": source, "result": resultFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(configuration, input, 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, "node", "../../scripts/connection-provision-browser.mjs", configuration)
	command.Cancel = func() error { return command.Process.Signal(os.Interrupt) }
	command.WaitDelay = 5 * time.Second
	output, runErr := command.CombinedOutput()
	if err := os.WriteFile(filepath.Join(dir, "browser.log"), output, 0600); err != nil {
		t.Fatal(err)
	}
	var result struct {
		Connection    string `json:"connection"`
		State         string `json:"state"`
		Phase         string `json:"phase"`
		Browser       string `json:"browser_version"`
		Requests      int    `json:"command_requests"`
		Accessibility int    `json:"accessibility_checks"`
		Egress        int    `json:"external_egress"`
		Errors        int    `json:"runtime_errors"`
		Sandbox       bool   `json:"browser_sandbox"`
	}
	raw, err := os.ReadFile(resultFile)
	if err != nil || json.Unmarshal(raw, &result) != nil || runErr != nil || result.State != "passed" ||
		!store.ValidID(result.Connection) || result.Requests != 3 || result.Accessibility != 2 || result.Egress != 0 || result.Errors != 0 || !result.Sandbox {
		t.Fatalf("browser provision failed; phase=%q; output_sha256=%s; private_fixture=%s; error=%v", result.Phase, secure.Digest(output), filepath.Base(dir), runErr)
	}
	assigned, err := control.Connection(ctx, recipient, result.Connection, 1)
	if err != nil || assigned.State != "revoked" || assigned.Revision != 2 || assigned.Hash != source.Hash ||
		assigned.HostFingerprint != source.HostFingerprint || assigned.KeyFingerprint != source.KeyFingerprint {
		t.Fatal("browser did not withdraw the exact projected route", err)
	}
	if _, err = control.Connection(ctx, operator, result.Connection, 1); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("operator gained the recipient's ordinary catalog read", err)
	}
	page, err := control.ConnectionProvisionChoices(ctx, manager, "assignments", "", 20)
	if err != nil || len(page.(*workflow.ConnectionProvisionAssignmentPage).Assignments) != 0 {
		t.Fatal("another operator received private assignment history", err)
	}
	tx, err := service.DB.Begin(ctx, operator)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Tx.Rollback(ctx)
	var recorded int
	if err := tx.Tx.QueryRow(ctx, `SELECT count(*) FROM events WHERE kind='OperatorConnectionChanged' AND actor_id=$1`, operatorID).Scan(&recorded); err != nil || recorded != 2 {
		t.Fatal("one lost response created an extra operator event", err)
	}
	if err := listener.SetDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if socket, err := listener.Accept(); socket != nil {
		_ = socket.Close()
		t.Fatal("provisioning contacted the peer")
	} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatal("unable to verify no peer contact", err)
	}
	t.Logf("operator browser passed; browser=%s; commands=%d; accessibility=%d; egress=%d", result.Browser, result.Requests, result.Accessibility, result.Egress)
}
