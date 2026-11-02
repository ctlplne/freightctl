//go:build integration

package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/delivery"
	"github.com/ctlplne/freightctl/internal/store"
)

type routingRecipientKey struct {
	ID          string `json:"id"`
	Version     int    `json:"version"`
	Hash        string `json:"definition_hash"`
	State       string `json:"state"`
	Revision    int64  `json:"revision"`
	Fingerprint string `json:"fingerprint"`
	Purpose     string `json:"purpose"`
}

// Exercise ordinary public key registration/revocation through the CLI. The
// separate process also avoids importing the checks service back into workflow.
// Its source-adapter fixtures are stand-ins; no receiver or encryption work is
// started by these negative admission tests.
func routingKeyCLI(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "freightctl")
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "sh", "scripts/go.sh", "build", "-p", "1", "-race", "-buildvcs=false", "-o", binary, "./cmd/freightctl")
	command.Dir = root
	command.Env = append(os.Environ(), "GOMAXPROCS=1", "GOMEMLIMIT=192MiB")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("cannot build the native key-control CLI: %v (diagnostic sha256 %s)", err, secure.Digest(output))
	}
	return binary
}

func routingKeyCommand(t *testing.T, f *fixture, binary, operation string, args ...string) routingRecipientKey {
	t.Helper()
	argv := []string{operation, "--dsn-file", f.runtimePath, "--token-file", f.tokenPath, "--tenant", f.scope.Tenant, "--partner", f.scope.Partner}
	command := exec.CommandContext(f.ctx, binary, append(argv, args...)...)
	command.Env = append(os.Environ(), "GOMAXPROCS=1", "GOMEMLIMIT=192MiB")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("native key-control command %s failed: %v (diagnostic sha256 %s)", operation, err, secure.Digest(output))
	}
	var result struct {
		Resource routingRecipientKey `json:"resource"`
	}
	if json.Unmarshal(output, &result) != nil || !store.ValidID(result.Resource.ID) || result.Resource.Purpose != "encrypt" {
		t.Fatal("invalid native key-control receipt")
	}
	return result.Resource
}

func TestCapturedRoutingRecipientRevocationFencesProposalAdmissionAndQueuedCiphertext(t *testing.T) {
	binary := routingKeyCLI(t)
	directory := os.Getenv("FREIGHTCTL_TEST_PGP_DIR")
	if directory == "" {
		t.Fatal("independent GnuPG public fixture required")
	}
	manifest, err := os.ReadFile(filepath.Join(directory, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var public struct {
		Fingerprints map[string]string `json:"fingerprints"`
	}
	if json.Unmarshal(manifest, &public) != nil || public.Fingerprints["recipient"] == "" || public.Fingerprints["recipient-rsa"] == "" {
		t.Fatal("independent recipient fingerprint required")
	}
	for _, phase := range []string{"proposed", "approved", "queued"} {
		t.Run(phase, func(t *testing.T) {
			f := setup(t)
			request, err := json.Marshal(map[string]any{"expected_version": 0, "purpose": "encrypt", "fingerprint": public.Fingerprints["recipient"]})
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "recipient.json")
			if err = os.WriteFile(path, request, 0600); err != nil {
				t.Fatal(err)
			}
			key := routingKeyCommand(t, f, binary, "pgp-key-register", "--request-file", path, "--pgp-public-file", filepath.Join(directory, "recipient-public.gpg"), "--idempotency-key", "routing-recipient-register")
			if key.State != "active" || key.Version != 1 || key.Revision != 1 || key.Fingerprint != public.Fingerprints["recipient"] {
				t.Fatal("recipient registration changed the independently generated key")
			}
			d := f.definition()
			source := collectionTestSource()
			source.Directory = "/"
			source.Connection = Reference{ID: f.connection.ID, Version: f.connection.Version, Hash: f.connection.Hash}
			d.Schema, d.Source = 2, &source
			d.Program = &Program{Nodes: []ProgramNode{{Kind: "deliver", Step: d.Steps[0].ID}}}
			original := f.approved(t, d)
			job, owner, inputs := sealedCollectionFixture(t, f, CollectionSelection{Workflow: Reference{ID: original.ID, Version: original.Version, Hash: original.Hash}, Timeout: 120, Authority: 1}, "recipient-captured-source", "abc", "def")
			captured := finishSealedCollection(t, f, job, owner, inputs)
			d.Steps[1].Filename = "second.pgp"
			d.Steps[1].Encryption = &store.EncryptionPolicy{Key: store.PGPReference{ID: key.ID, Version: key.Version, Hash: key.Hash}, Profile: secure.PGPEncryptMDC}
			d.Program = &Program{Nodes: []ProgramNode{{Kind: "deliver", Step: d.Steps[1].ID}}}
			target := revisedCollectionRoutingWorkflow(t, f, original, d)
			x := CollectionRoutingSelection{Collection: Decision{Hash: captured.Job.Hash, Revision: captured.Job.Revision}, Workflow: Reference{ID: target.ID, Version: target.Version, Hash: target.Hash}, Authority: 1}
			a := proposeRoutingAuthorization(t, f, job.ID, x, "recipient-routing-propose")
			if phase != "proposed" {
				a = decideRoutingAuthorization(t, f, a, "approve", "recipient-routing-approve")
			}
			deliveries := []string{}
			if phase == "queued" {
				if _, err = f.s.RefreshCollection(f.ctx, f.scope, job.ID, "recipient-routing-admit", x.Collection); err != nil {
					t.Fatal(err)
				}
				view := assertCapturedRoutingRuns(t, f, captured, x, a.ID, 2)
				for _, input := range view.Inputs {
					status, err := f.s.Status(f.ctx, f.scope, *input.RunID)
					if err != nil {
						t.Fatal(err)
					}
					deliveries = append(deliveries, status.Steps[0].DeliveryID)
				}
			}
			revoked := routingKeyCommand(t, f, binary, "pgp-key-revoke", "--pgp-key-id", key.ID, "--version", strconv.Itoa(key.Version), "--definition-hash", key.Hash, "--expected-revision", strconv.FormatInt(key.Revision, 10), "--idempotency-key", "routing-recipient-revoke")
			if revoked.ID != key.ID || revoked.Hash != key.Hash || revoked.Revision != key.Revision+1 || revoked.State != "revoked" {
				t.Fatal("revocation replaced the public key identity")
			}
			before := routingPreviewCounts(t, f)
			if phase == "proposed" {
				if _, err = f.s.DecideCollectionRouting(f.ctx, f.scope, a.JobID, a.ID, "revoked-recipient-cannot-approve", "approve", Decision{Hash: a.Hash, Revision: a.Revision}); !errors.Is(err, store.ErrState) {
					t.Fatal("revoked recipient allowed a routing approval", err)
				}
			} else if _, err = f.s.RefreshCollection(f.ctx, f.scope, job.ID, "revoked-recipient-no-plaintext-fallback", x.Collection); !errors.Is(err, store.ErrState) {
				t.Fatal("revoked recipient restored original plaintext rules", err)
			}
			for _, id := range deliveries {
				if _, _, err = (&delivery.Service{Custody: f.s.Custody}).Claim(f.ctx, f.scope, id, secure.NewID()); !errors.Is(err, store.ErrState) {
					t.Fatal("revoked recipient started a queued encrypted transfer", err)
				}
			}
			if routingPreviewCounts(t, f) != before {
				t.Fatal("recipient refusal created partial routing or execution effects")
			}
			var effects int
			if err = f.admin.QueryRow(f.ctx, `SELECT (SELECT coalesce(sum(attempts),0) FROM delivery_intents)+(SELECT count(*) FROM delivery_ciphertexts)`).Scan(&effects); err != nil || effects != 0 {
				t.Fatal("recipient refusal consumed an attempt or generated ciphertext", effects, err)
			}
			if phase == "approved" {
				// A replacement key alone cannot repair an approval for the old
				// exact version. Review a new workflow and batch authorization.
				request, err = json.Marshal(map[string]any{"key_id": key.ID, "expected_version": key.Version, "purpose": "encrypt", "fingerprint": public.Fingerprints["recipient-rsa"]})
				if err != nil {
					t.Fatal(err)
				}
				rotationPath := filepath.Join(t.TempDir(), "recipient-rotation.json")
				if err = os.WriteFile(rotationPath, request, 0600); err != nil {
					t.Fatal("cannot save the explicit replacement-key request", err)
				}
				replacement := routingKeyCommand(t, f, binary, "pgp-key-register", "--request-file", rotationPath, "--pgp-public-file", filepath.Join(directory, "recipient-rsa-public.gpg"), "--idempotency-key", "routing-recipient-rotation")
				if replacement.ID != key.ID || replacement.Version != key.Version+1 || replacement.State != "active" || replacement.Hash == key.Hash || replacement.Fingerprint != public.Fingerprints["recipient-rsa"] {
					t.Fatal("replacement key lost its explicit family/version binding")
				}
				if _, err = f.s.RefreshCollection(f.ctx, f.scope, job.ID, "new-key-does-not-rebind-old-approval", x.Collection); !errors.Is(err, store.ErrState) || routingPreviewCounts(t, f)[0] != before[0] || routingPreviewCounts(t, f)[1] != before[1] {
					t.Fatal("new key silently rebound the old approval", err)
				}
				d.Steps[1].Encryption = &store.EncryptionPolicy{Key: store.PGPReference{ID: replacement.ID, Version: replacement.Version, Hash: replacement.Hash}, Profile: secure.PGPEncryptMDC}
				draft, err := f.s.Draft(f.ctx, f.scope, "recipient-rotation-workflow-draft", DraftRequest{ID: target.ID, ExpectedVersion: target.Version, Definition: d})
				var next store.Configuration
				if err != nil || json.Unmarshal(draft.Resource, &next) != nil {
					t.Fatal("replacement workflow draft", err)
				}
				approved, err := f.s.Decide(f.ctx, f.scope, next.ID, next.Version, "recipient-rotation-workflow-approve", "approve", Decision{Hash: next.Hash, Revision: next.Revision})
				if err != nil || json.Unmarshal(approved.Resource, &next) != nil {
					t.Fatal("replacement workflow approval", err)
				}
				nextSelection := x
				nextSelection.Workflow = Reference{ID: next.ID, Version: next.Version, Hash: next.Hash}
				b := proposeRoutingAuthorization(t, f, job.ID, nextSelection, "recipient-rotation-propose")
				if _, err = f.s.RefreshCollection(f.ctx, f.scope, job.ID, "new-proposal-is-not-replacement-consent", x.Collection); !errors.Is(err, store.ErrState) {
					t.Fatal("a proposal restored an invalid recipient approval", err)
				}
				b = decideRoutingAuthorization(t, f, b, "approve", "recipient-rotation-approve")
				if _, err = f.s.RefreshCollection(f.ctx, f.scope, job.ID, "recipient-rotation-admit", x.Collection); err != nil {
					t.Fatal(err)
				}
				view := assertCapturedRoutingRuns(t, f, captured, nextSelection, b.ID, 2)
				if counts := routingPreviewCounts(t, f); counts[0] != 2 || counts[1] != 2 {
					t.Fatal("replacement consent created extra or plaintext fallback runs", counts)
				}
				for _, input := range view.Inputs {
					status, err := f.s.Status(f.ctx, f.scope, *input.RunID)
					if err != nil {
						t.Fatal(err)
					}
					effect, err := (&delivery.Service{Custody: f.s.Custody}).Status(f.ctx, f.scope, status.Steps[0].DeliveryID)
					var spec delivery.Definition
					if err != nil || json.Unmarshal(effect.Definition, &spec) != nil || effect.Attempts != 0 || spec.Encryption == nil || spec.Encryption.Key != d.Steps[1].Encryption.Key || status.Steps[0].Ciphertext != nil {
						t.Fatal("replacement run did not keep the reviewed key", err)
					}
				}
			}
			metadata, err := f.s.CollectionRoutingDetails(f.ctx, f.scope, a.JobID, a.ID)
			if err != nil || metadata.Current || metadata.Workflow == nil || metadata.Workflow.Version != target.Version || len(metadata.Effects) != 2 || metadata.Effects[1].EncryptionFingerprint == "" || metadata.Effects[1].Encryption == nil || metadata.Effects[1].Encryption.Key != (store.PGPReference{ID: key.ID, Version: key.Version, Hash: key.Hash}) {
				t.Fatal("revocation lost historical recipient evidence or restored execution", err)
			}
			view, err := f.s.CollectionStatus(f.ctx, f.scope, job.ID)
			if err != nil || !reflect.DeepEqual(view.Job, captured.Job) {
				t.Fatal("recipient revocation changed the original captured job", err)
			}
			for _, input := range view.Inputs {
				file, body, err := f.s.Custody.DownloadPath(f.ctx, f.scope, input.Target)
				if err != nil {
					t.Fatal("recipient revocation lost accepted local bytes", err)
				}
				data, readErr := io.ReadAll(io.LimitReader(body, 4))
				closeErr := body.Close()
				if readErr != nil || closeErr != nil || len(data) != 3 || file.ID != *input.FileID || secure.Digest(data) != input.SHA256 {
					t.Fatal("accepted source bytes changed during recipient recovery", readErr, closeErr)
				}
			}
			if phase == "proposed" {
				a = decideRoutingAuthorization(t, f, a, "withdraw", "withdraw-revoked-recipient-proposal")
				if a.State != "withdrawn" {
					t.Fatal("revoked recipient stranded a nonexecuting proposal")
				}
			}
		})
	}
}
