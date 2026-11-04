//go:build integration

package workflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/delivery"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/jackc/pgx/v5/pgconn"
)

type ftpsPGPPeer struct {
	Fingerprints map[string]string `json:"fingerprints"`
	Image        string            `json:"peer_image"`
	Backend      string            `json:"peer_backend"`
}

func ftpsRecipient(t *testing.T, f *fixture, binary, name string) (routingRecipientKey, ftpsPGPPeer, string) {
	t.Helper()
	dir := os.Getenv("FREIGHTCTL_TEST_PGP_DIR")
	return ftpsRecipientAt(t, f, binary, name, dir)
}

func ftpsRecipientAt(t *testing.T, f *fixture, binary, name, dir string) (routingRecipientKey, ftpsPGPPeer, string) {
	t.Helper()
	manifest, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	var peer ftpsPGPPeer
	if err != nil || json.Unmarshal(manifest, &peer) != nil || peer.Fingerprints[name] == "" || !strings.HasPrefix(peer.Image, "sha256:") {
		t.Fatal("exact independent recipient fixture required", err)
	}
	request := filepath.Join(t.TempDir(), "recipient.json")
	raw, _ := json.Marshal(map[string]any{"expected_version": 0, "purpose": "encrypt", "fingerprint": peer.Fingerprints[name]})
	if err = os.WriteFile(request, raw, 0600); err != nil {
		t.Fatal(err)
	}
	key := routingKeyCommand(t, f, binary, "pgp-key-register", "--request-file", request, "--pgp-public-file", filepath.Join(dir, name+"-public.gpg"), "--idempotency-key", "encrypted-ftps-recipient")
	return key, peer, dir
}

func encryptedFTPSRun(t *testing.T, f *fixture, s *delivery.Service, c ConnectionView, key routingRecipientKey, program bool) (*store.WorkflowRun, *store.Delivery) {
	t.Helper()
	return encryptedFTPSRunProfile(t, f, s, c, key, program, secure.PGPEncryptMDC)
}

func encryptedFTPSRunProfile(t *testing.T, f *fixture, s *delivery.Service, c ConnectionView, key routingRecipientKey, program bool, profile string) (*store.WorkflowRun, *store.Delivery) {
	t.Helper()
	policy := &store.EncryptionPolicy{Key: store.PGPReference{ID: key.ID, Version: key.Version, Hash: key.Hash}, Profile: profile}
	step := Step{ID: "send", Kind: "ftps.deliver", Connection: Reference{ID: c.ID, Version: c.Version, Hash: c.Hash}, Filename: "payroll.pgp", Encryption: policy}
	definition := Definition{Schema: 1, Name: "Encrypted registered FTPS", Steps: []Step{step}}
	if program {
		definition.Schema = 2
		// A catalog ordinal is not an execution ordinal. The approved plan selects
		// the second catalog step; an unused first step has no encryption policy.
		unused := step
		unused.ID, unused.Encryption = "unused", nil
		definition.Steps = []Step{unused, step}
		definition.Program = &Program{Nodes: []ProgramNode{{Kind: "deliver", Step: "send"}}}
	}
	preview, err := f.s.Validate(f.ctx, f.scope, PreviewRequest{Definition: definition, FileID: f.file.ID})
	if err != nil || preview.ExternalContact {
		t.Fatal("encrypted metadata preview", err)
	}
	last := preview.Effects[len(preview.Effects)-1]
	if last.Encryption == nil || *last.Encryption != *policy || last.RecipientFingerprint != key.Fingerprint || last.EncryptionFingerprint == "" {
		t.Fatal("preview lost exact recipient")
	}
	w := f.approved(t, definition)
	request := RunRequest{Workflow: Reference{ID: w.ID, Version: w.Version, Hash: w.Hash}, FileID: f.file.ID}
	first, err := f.s.Run(f.ctx, f.scope, "encrypted-ftps-run", request)
	if err != nil {
		t.Fatal(err)
	}
	again, err := f.s.Run(f.ctx, f.scope, "encrypted-ftps-run", request)
	var run, replay store.WorkflowRun
	if err != nil || !again.Replayed || json.Unmarshal(first.Resource, &run) != nil || json.Unmarshal(again.Resource, &replay) != nil {
		t.Fatal("run replay", err)
	}
	a, e := canonicalWorkflowRunReceipt(run)
	b, e2 := canonicalWorkflowRunReceipt(replay)
	if e != nil || e2 != nil || !reflect.DeepEqual(a, b) {
		t.Fatal("run/plan replay differs", e, e2)
	}
	status, err := f.s.Status(f.ctx, f.scope, run.ID)
	if err != nil || len(status.Steps) != 1 || status.Steps[0].ID != "send" {
		t.Fatal("selected encrypted step", err)
	}
	d, err := s.Status(f.ctx, f.scope, status.Steps[0].DeliveryID)
	if err != nil {
		t.Fatal(err)
	}
	var spec delivery.Definition
	if json.Unmarshal(d.Definition, &spec) != nil || spec.Encryption == nil || *spec.Encryption != *policy || spec.Binding == nil || spec.Binding.ConnectionHash != c.Hash || spec.Binding.WorkflowHash != w.Hash || spec.Source != *f.file {
		t.Fatal("frozen encryption/run/source binding")
	}
	return &run, d
}

func ftpsCiphertext(t *testing.T, f *fixture, id string) *store.DeliveryCiphertext {
	t.Helper()
	tx, err := f.s.Custody.DB.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Tx.Rollback(f.ctx)
	a, err := tx.DeliveryCiphertext(f.ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func requireNoFTPSCiphertext(t *testing.T, f *fixture, id string) {
	t.Helper()
	tx, err := f.s.Custody.DB.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Tx.Rollback(f.ctx)
	if _, err = tx.DeliveryCiphertext(f.ctx, id); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("metadata/refused work generated ciphertext", err)
	}
}

func decryptFTPSReceiver(t *testing.T, r *fixture, filename, keyName string, peer ftpsPGPPeer, fixtureDir string, a *store.DeliveryCiphertext) {
	t.Helper()
	_, file, err := r.s.Custody.DownloadPath(r.ctx, r.scope, filename)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(io.LimitReader(file, secure.PGPCiphertextLimit(3)+1))
	file.Close()
	if err != nil || int64(len(body)) != a.Size || secure.Digest(body) != a.SHA256 || bytes.Equal(body, []byte("abc")) {
		t.Fatal("separate receiver ciphertext differs", err)
	}
	work := t.TempDir()
	if err = os.WriteFile(filepath.Join(work, "cipher.pgp"), body, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(r.ctx, 30*time.Second)
	defer cancel()
	if a.Policy.Profile == secure.PGPEncryptAEAD {
		if peer.Backend != "docker-openpgpjs" {
			t.Fatal("independent AEAD recipient required")
		}
		command := exec.CommandContext(ctx, "docker", "run", "--rm", "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--memory=192m", "--cpus=1", "--pids-limit=32", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m", "--user", strconv.Itoa(os.Getuid())+":"+strconv.Itoa(os.Getgid()), "-v", fixtureDir+":/fixture:ro", "-v", work+":/result", peer.Image, "decrypt", "/fixture", "/result")
		output, err := command.Output()
		if err != nil {
			t.Fatalf("independent AEAD recipient failed: %v (stage %s; diagnostic sha256 %s)", err, aeadPeerFailureStage(output), secure.Digest(output))
		}
		var actual map[string]any
		expected := map[string]any{"schema_version": float64(1), "state": "passed", "peer": "OpenPGP.js", "version": "6.3.2", "profile": secure.PGPEncryptAEAD, "primary_fingerprint": a.Proof.PrimaryFingerprint, "encryption_fingerprint": a.Proof.EncryptionFingerprint, "seipd_version": float64(2), "cipher": "AES-256", "aead": "OCB", "plaintext_bytes": float64(3), "plaintext_sha256": secure.Digest([]byte("abc")), "ciphertext_sha256": a.SHA256, "corrupt_refused": true, "truncated_refused": true}
		if json.Unmarshal(output, &actual) != nil || !reflect.DeepEqual(actual, expected) {
			t.Fatal("independent AEAD proof differs")
		}
		plain, err := os.ReadFile(filepath.Join(work, "plain.csv"))
		if err != nil || !bytes.Equal(plain, []byte("abc")) {
			t.Fatal("independent AEAD plaintext differs", err)
		}
		return
	}
	if a.Policy.Profile != secure.PGPEncryptMDC || peer.Backend != "docker" {
		t.Fatal("independent GnuPG recipient required")
	}
	// Only the independent peer sees this synthetic private recipient. The
	// product stores its public key; neither model nor product receives a secret.
	command := exec.CommandContext(ctx, "docker", "run", "--rm", "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--memory=128m", "--cpus=1", "--pids-limit=32", "--tmpfs", "/tmp:rw,noexec,nosuid,size=32m", "--user", strconv.Itoa(os.Getuid())+":"+strconv.Itoa(os.Getgid()), "-v", fixtureDir+":/fixture:ro", "-v", work+":/result", peer.Image, "/bin/sh", "-ec", "mkdir -m 700 /tmp/recipient; : > /tmp/recipient/common.conf; gpg --homedir /tmp/recipient --batch --import /fixture/"+keyName+"-private.gpg; gpg --homedir /tmp/recipient --batch --status-fd 2 --output /result/plain.csv --decrypt /result/cipher.pgp")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("independent recipient decrypt failed: %v (diagnostic sha256 %s)", err, secure.Digest(output))
	}
	plain, err := os.ReadFile(filepath.Join(work, "plain.csv"))
	for _, proof := range []string{"DECRYPTION_OKAY", "GOODMDC", "DECRYPTION_INFO 2 9 0"} {
		if !strings.Contains(string(output), proof) {
			t.Fatal("GnuPG authenticated AES256 proof absent")
		}
	}
	if err != nil || !bytes.Equal(plain, []byte("abc")) {
		t.Fatal("independent recipient plaintext differs", err)
	}
}

func requireFTPSArtifactReceipt(t *testing.T, d *store.Delivery, a *store.DeliveryCiphertext, reconciled bool) {
	t.Helper()
	var got struct {
		Protocol   string `json:"protocol"`
		SHA        string `json:"sha256"`
		Size       int64  `json:"size_bytes"`
		Fsync      bool   `json:"file_fsync_acknowledged"`
		Rename     bool   `json:"rename_acknowledged"`
		Reconciled bool   `json:"reconciled"`
		Business   string `json:"business_acceptance"`
		Encryption struct {
			Key       store.PGPReference `json:"key"`
			Profile   string             `json:"profile"`
			Primary   string             `json:"primary_fingerprint"`
			Subkey    string             `json:"encryption_fingerprint"`
			Object    string             `json:"ciphertext_object_id"`
			Source    string             `json:"source_file_id"`
			SourceSHA string             `json:"source_sha256"`
		} `json:"encryption"`
	}
	if json.Unmarshal(d.Observation, &got) != nil || got.Protocol != "ftps" || got.SHA != a.SHA256 || got.Size != a.Size || got.Fsync || got.Rename == reconciled || got.Reconciled != reconciled || got.Business != "unknown" || got.Encryption.Key != a.Policy.Key || got.Encryption.Profile != a.Policy.Profile || got.Encryption.Primary != a.Proof.PrimaryFingerprint || got.Encryption.Subkey != a.Proof.EncryptionFingerprint || got.Encryption.Object != a.ObjectID || got.Encryption.Source != a.SourceID || got.Encryption.SourceSHA != a.SourceSHA256 {
		t.Fatal("ciphertext/source proof or FTPS guarantee differs")
	}
}

func TestEncryptedFTPSWorkflowGnuPGReadbackAndAmbiguousRecovery(t *testing.T) {
	binary := routingKeyCLI(t)
	for _, implicit := range []bool{false, true} {
		for _, program := range []bool{false, true} {
			for _, name := range []string{"recipient", "recipient-rsa"} {
				for _, lost := range []bool{false, true} {
					t.Run(fmt.Sprintf("implicit-%t/program-%t/%s/lost-rename-%t", implicit, program, name, lost), func(t *testing.T) {
						f, s, reviewer, account := outboundFixture(t)
						r, spec, listener := governedFTPSReceiver(t, implicit)
						key, peer, dir := ftpsRecipient(t, f, binary, name)
						c := registeredFTPSConnection(t, f, spec)
						run, d := encryptedFTPSRun(t, f, s, c, key, program)
						if _, err := f.s.Work(f.ctx, f.scope, run.ID, "encrypted-worker"); !errors.Is(err, store.ErrDispatchApproval) {
							t.Fatal("workflow bypassed recipient consent", err)
						}
						requireUntouchedFTPSWorkflow(t, f, s, d, listener, 0)
						requireNoFTPSCiphertext(t, f, d.ID)
						review := approveFTPS(t, f, s, d, reviewer, account)
						view, err := s.DispatchReview(f.ctx, reviewer, review.ID)
						if err != nil || view.Definition.Effect.Encryption == nil || view.Definition.Effect.Encryption.Key.Hash != key.Hash || view.Definition.Effect.RecipientFingerprint != key.Fingerprint {
							t.Fatal("review did not bind recipient", err)
						}
						requireNoFTPSCiphertext(t, f, d.ID)
						final := "/inbox/" + d.ID + "-payroll.pgp"
						if lost {
							listener.setAfter(func() bool { _, err := r.s.Custody.StatPath(r.ctx, r.scope, final); return err == nil })
						}
						out, err := f.s.Work(f.ctx, f.scope, run.ID, "encrypted-worker")
						if err != nil {
							t.Fatal(err)
						}
						a := ftpsCiphertext(t, f, d.ID)
						if a.Policy.Key.Hash != key.Hash || a.SourceID != f.file.ID || a.SourceSHA256 != f.file.SHA256 || a.DefinitionHash != d.DefinitionHash || a.Proof.PrimaryFingerprint != key.Fingerprint {
							t.Fatal("sealed ciphertext identity differs")
						}
						before, err := s.Status(f.ctx, f.scope, d.ID)
						if err != nil || before.Attempts != 1 || before.Fence != 1 {
							t.Fatal("sending attempt identity", err)
						}
						contacts := listener.contacts.Load()
						if lost {
							if out.Status.ObservedState != "attention" || out.Status.ObservedReason != "delivery_ambiguous" || len(out.Status.Steps) != 1 || out.Status.Steps[0].State != "ambiguous" || !listener.fired.Load() {
								t.Fatal("lost completion not ambiguous")
							}
							if _, err = f.s.Work(f.ctx, f.scope, run.ID, "encrypted-worker"); !errors.Is(err, store.ErrState) || listener.contacts.Load() != contacts {
								t.Fatal("ambiguous work resent", err)
							}
							entry, err := r.s.Custody.StatPath(r.ctx, r.scope, final)
							if err != nil {
								t.Fatal(err)
							}
							snapshot := snapshotReceiverReads(t, r)
							reconciled, err := s.Reconcile(f.ctx, f.scope, d.ID)
							if err != nil || reconciled.State != "succeeded" || reconciled.Attempts != before.Attempts || reconciled.Fence != before.Fence {
								t.Fatal("exact ciphertext recovery", err)
							}
							mode := "explicit"
							if implicit {
								mode = "implicit"
							}
							decryptFTPSReceiver(t, r, final, name, peer, dir, a)
							after := snapshotReceiverReads(t, r)
							requireOnlyReceiverReadAuditDigest(t, r, snapshot, after, entry.FileID, "rename", mode, a.SHA256)
							requireFTPSArtifactReceipt(t, reconciled, a, true)
						} else {
							if out.Status.ObservedState != "succeeded" {
								t.Fatal("encrypted send did not succeed")
							}
							requireFTPSArtifactReceipt(t, before, a, false)
							again, err := f.s.Work(f.ctx, f.scope, run.ID, "encrypted-worker")
							if err != nil || !again.Replayed || again.Dispatch != out.Dispatch || listener.contacts.Load() != contacts {
								t.Fatal("completed saved key resent", err)
							}
						}
						if !reflect.DeepEqual(a, ftpsCiphertext(t, f, d.ID)) {
							t.Fatal("worker/recovery replaced sealed randomized ciphertext")
						}
						if !lost {
							decryptFTPSReceiver(t, r, final, name, peer, dir, a)
						}
					})
				}
			}
		}
	}
}

func TestEncryptedFTPSRecipientRotationAndRevocationFenceSavedWork(t *testing.T) {
	binary := routingKeyCLI(t)
	for _, implicit := range []bool{false, true} {
		for _, ambiguous := range []bool{false, true} {
			t.Run(fmt.Sprintf("implicit-%t/ambiguous-%t", implicit, ambiguous), func(t *testing.T) {
				f, s, reviewer, account := outboundFixture(t)
				r, spec, listener := governedFTPSReceiver(t, implicit)
				key, peer, dir := ftpsRecipient(t, f, binary, "recipient")
				c := registeredFTPSConnection(t, f, spec)
				run, d := encryptedFTPSRun(t, f, s, c, key, true)
				if _, err := f.s.Work(f.ctx, f.scope, run.ID, "encrypted-revoke-worker"); !errors.Is(err, store.ErrDispatchApproval) {
					t.Fatal(err)
				}
				requireUntouchedFTPSWorkflow(t, f, s, d, listener, 0)
				approveFTPS(t, f, s, d, reviewer, account)
				var artifact *store.DeliveryCiphertext
				if ambiguous {
					final := "/inbox/" + d.ID + "-payroll.pgp"
					listener.setAfter(func() bool { _, err := r.s.Custody.StatPath(r.ctx, r.scope, final); return err == nil })
					out, err := f.s.Work(f.ctx, f.scope, run.ID, "encrypted-revoke-worker")
					if err != nil || out.Status.ObservedState != "attention" || out.Status.ObservedReason != "delivery_ambiguous" || len(out.Status.Steps) != 1 || out.Status.Steps[0].State != "ambiguous" || !listener.fired.Load() {
						t.Fatal("real encrypted rename loss", err)
					}
					artifact = ftpsCiphertext(t, f, d.ID)
					decryptFTPSReceiver(t, r, final, "recipient", peer, dir, artifact)
				} else {
					requireNoFTPSCiphertext(t, f, d.ID)
				}
				before, err := s.Status(f.ctx, f.scope, d.ID)
				if err != nil {
					t.Fatal(err)
				}
				contacts := listener.contacts.Load()
				snapshot := snapshotReceiverReads(t, r)
				request := filepath.Join(t.TempDir(), "rotated-recipient.json")
				raw, _ := json.Marshal(map[string]any{"key_id": key.ID, "expected_version": key.Version, "purpose": "encrypt", "fingerprint": peer.Fingerprints["recipient-rsa"]})
				if err = os.WriteFile(request, raw, 0600); err != nil {
					t.Fatal(err)
				}
				next := routingKeyCommand(t, f, binary, "pgp-key-register", "--request-file", request, "--pgp-public-file", filepath.Join(dir, "recipient-rsa-public.gpg"), "--idempotency-key", "encrypted-ftps-rotate")
				if next.ID != key.ID || next.Version != key.Version+1 || next.Hash == key.Hash {
					t.Fatal("rotation did not create exact successor")
				}
				unchanged, err := s.Status(f.ctx, f.scope, d.ID)
				if err != nil || !reflect.DeepEqual(before, unchanged) {
					t.Fatal("rotation silently rebound saved work", err)
				}
				routingKeyCommand(t, f, binary, "pgp-key-revoke", "--pgp-key-id", key.ID, "--version", strconv.Itoa(key.Version), "--definition-hash", key.Hash, "--expected-revision", "1", "--idempotency-key", "encrypted-ftps-revoke")
				if _, err = f.s.Work(f.ctx, f.scope, run.ID, "encrypted-revoke-worker"); !errors.Is(err, store.ErrState) {
					t.Fatal("saved work bypassed revoked recipient", err)
				}
				if ambiguous {
					if _, err = s.Reconcile(f.ctx, f.scope, d.ID); !errors.Is(err, store.ErrState) {
						t.Fatal("recovery contacted revoked recipient", err)
					}
					if !reflect.DeepEqual(artifact, ftpsCiphertext(t, f, d.ID)) {
						t.Fatal("revocation changed original ciphertext")
					}
				} else {
					requireNoFTPSCiphertext(t, f, d.ID)
				}
				after, err := s.Status(f.ctx, f.scope, d.ID)
				if err != nil || !reflect.DeepEqual(before, after) || listener.contacts.Load() != contacts || !reflect.DeepEqual(snapshot, snapshotReceiverReads(t, r)) {
					t.Fatal("revoked work changed intent or receiver", err)
				}
			})
		}
	}
}

func TestEncryptedFTPSWorkflowSQLRejectsRecipientPolicySubstitution(t *testing.T) {
	binary := routingKeyCLI(t)
	for _, implicit := range []bool{false, true} {
		t.Run(fmt.Sprintf("implicit-%t", implicit), func(t *testing.T) {
			f, s, _, _ := outboundFixture(t)
			_, spec, listener := governedFTPSReceiver(t, implicit)
			key, _, _ := ftpsRecipient(t, f, binary, "recipient")
			c := registeredFTPSConnection(t, f, spec)
			run, d := encryptedFTPSRun(t, f, s, c, key, true)
			for _, mutation := range []string{"omit", "version", "hash", "profile", "unknown-policy-field", "unknown-key-field"} {
				t.Run(mutation, func(t *testing.T) {
					tx, err := f.s.Custody.DB.Begin(f.ctx, f.scope)
					if err != nil {
						t.Fatal(err)
					}
					defer tx.Tx.Rollback(f.ctx)
					clone := *run
					clone.ID = secure.NewID()
					if err = tx.SaveWorkflowRun(f.ctx, &clone, 0); err != nil {
						t.Fatal(err)
					}
					var definition map[string]any
					if json.Unmarshal(d.Definition, &definition) != nil {
						t.Fatal("definition")
					}
					definition["workflow_binding"].(map[string]any)["run_id"] = clone.ID
					policy := definition["encryption"].(map[string]any)
					recipient := policy["key"].(map[string]any)
					switch mutation {
					case "omit":
						delete(definition, "encryption")
					case "version":
						recipient["version"] = key.Version + 1
					case "hash":
						recipient["hash"] = strings.Repeat("a", 64)
					case "profile":
						policy["profile"] = "automatic"
					case "unknown-policy-field":
						policy["private_reference"] = "/synthetic/private"
					case "unknown-key-field":
						recipient["private_reference"] = "/synthetic/private"
					}
					raw, _, err := digest(definition)
					if err != nil {
						t.Fatal(err)
					}
					forged := *d
					forged.ID = secure.NewID()
					forged.Definition = raw
					forged.DefinitionHash = secure.Digest(raw)
					forged.State = "draft"
					forged.Revision = 1
					if err = tx.SaveDelivery(f.ctx, &forged, 0); err == nil {
						err = tx.BindWorkflowStep(f.ctx, &store.WorkflowStep{RunID: clone.ID, ID: "send", Ordinal: 1, ConnectionID: c.ID, ConnectionVersion: c.Version, ConnectionHash: c.Hash, DeliveryID: forged.ID})
					}
					if err == nil {
						err = tx.Tx.Commit(f.ctx)
					} else {
						tx.Tx.Rollback(f.ctx)
					}
					var pg *pgconn.PgError
					if !errors.As(err, &pg) || pg.Code != "23514" {
						t.Fatal("SQL did not refuse forged recipient", err)
					}
					switch pg.Message {
					case "FTPS encryption requires exact workflow recipient policy", "delivery encryption must match approved workflow step", "delivery requires exact live encryption recipient":
					default:
						t.Fatal("unrelated SQL failure cannot qualify recipient binding", pg.Message)
					}
				})
			}
			if listener.contacts.Load() != 0 {
				t.Fatal("SQL/metadata qualification contacted receiver")
			}
			requireNoFTPSCiphertext(t, f, d.ID)
		})
	}
}
