//go:build integration

package workflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

func independentAEADRecipient(t *testing.T) string {
	t.Helper()
	dir := privatePeerDirectory(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	image, err := exec.CommandContext(ctx, "docker", "image", "inspect", "--format", "{{.Id}}", "freightctl-openpgp-peer:6.3.2-r1").Output()
	id := strings.TrimSpace(string(image))
	if err != nil || !strings.HasPrefix(id, "sha256:") || len(id) != 71 || !hashPattern.MatchString(id[7:]) {
		t.Fatal("pinned independent AEAD image required", err)
	}
	t.Logf("independent AEAD recipient image %s; OpenPGP.js6.3.2", id)
	command := exec.CommandContext(ctx, "docker", "run", "--rm", "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--memory=192m", "--cpus=1", "--pids-limit=32", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m", "--user", strconv.Itoa(os.Getuid())+":"+strconv.Itoa(os.Getgid()), "-v", dir+":/fixture", id, "generate", "/fixture")
	output, err := command.Output()
	if err != nil {
		t.Fatalf("independent AEAD generation failed: %v (stage %s; diagnostic sha256 %s)", err, aeadPeerFailureStage(output), secure.Digest(output))
	}
	var result struct {
		State     string `json:"state"`
		Peer      string `json:"peer"`
		Version   string `json:"version"`
		Profile   string `json:"profile"`
		Primary   string `json:"primary_fingerprint"`
		Subkey    string `json:"encryption_fingerprint"`
		PublicSHA string `json:"public_sha256"`
	}
	public, err := os.ReadFile(filepath.Join(dir, "recipient-public.gpg"))
	if err != nil || json.Unmarshal(output, &result) != nil || result.State != "passed" || result.Peer != "OpenPGP.js" || result.Version != "6.3.2" || result.Profile != secure.PGPEncryptAEAD || len(result.Primary) != 40 || len(result.Subkey) != 40 || result.PublicSHA != secure.Digest(public) {
		t.Fatal("independent AEAD generation proof differs", err)
	}
	recorded, err := os.ReadFile(filepath.Join(dir, "generation.json"))
	if err != nil || !bytes.Equal(recorded, output) {
		t.Fatal("generation output differs from original peer file", err)
	}
	manifest := map[string]any{"fingerprints": map[string]string{"recipient": result.Primary}, "peer_image": id, "peer_backend": "docker-openpgpjs"}
	raw, _ := json.Marshal(manifest)
	if err = os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestEncryptedFTPSAEADIndependentRecipientAndRecovery(t *testing.T) {
	binary := routingKeyCLI(t)
	dir := independentAEADRecipient(t)
	for _, implicit := range []bool{false, true} {
		for _, program := range []bool{false, true} {
			for _, lost := range []bool{false, true} {
				t.Run(fmt.Sprintf("implicit-%t/program-%t/lost-rename-%t", implicit, program, lost), func(t *testing.T) {
					f, s, reviewer, account := outboundFixture(t)
					r, spec, listener := governedFTPSReceiver(t, implicit)
					key, peer, _ := ftpsRecipientAt(t, f, binary, "recipient", dir)
					c := registeredFTPSConnection(t, f, spec)
					run, d := encryptedFTPSRunProfile(t, f, s, c, key, program, secure.PGPEncryptAEAD)
					if _, err := f.s.Work(f.ctx, f.scope, run.ID, "aead-worker"); !errors.Is(err, store.ErrDispatchApproval) {
						t.Fatal("AEAD bypassed ordinary consent", err)
					}
					requireUntouchedFTPSWorkflow(t, f, s, d, listener, 0)
					requireNoFTPSCiphertext(t, f, d.ID)
					approveFTPS(t, f, s, d, reviewer, account)
					final := "/inbox/" + d.ID + "-payroll.pgp"
					if lost {
						listener.setAfter(func() bool { _, err := r.s.Custody.StatPath(r.ctx, r.scope, final); return err == nil })
					}
					out, err := f.s.Work(f.ctx, f.scope, run.ID, "aead-worker")
					if err != nil {
						t.Fatal(err)
					}
					a := ftpsCiphertext(t, f, d.ID)
					before, err := s.Status(f.ctx, f.scope, d.ID)
					if err != nil || before.Attempts != 1 || before.Fence != 1 || a.Policy.Profile != secure.PGPEncryptAEAD || a.Policy.Key.Hash != key.Hash || a.SourceID != f.file.ID || a.SourceSHA256 != f.file.SHA256 || a.DefinitionHash != d.DefinitionHash {
						t.Fatal("AEAD source/artifact/attempt identity differs", err)
					}
					contacts := listener.contacts.Load()
					if lost {
						if out.Status.ObservedState != "attention" || out.Status.ObservedReason != "delivery_ambiguous" || len(out.Status.Steps) != 1 || out.Status.Steps[0].State != "ambiguous" || !listener.fired.Load() {
							t.Fatal("lost AEAD rename not retained")
						}
						if _, err = f.s.Work(f.ctx, f.scope, run.ID, "aead-worker"); !errors.Is(err, store.ErrState) || listener.contacts.Load() != contacts {
							t.Fatal("ambiguous AEAD resent", err)
						}
						entry, err := r.s.Custody.StatPath(r.ctx, r.scope, final)
						if err != nil {
							t.Fatal(err)
						}
						snapshot := snapshotReceiverReads(t, r)
						reconciled, err := s.Reconcile(f.ctx, f.scope, d.ID)
						if err != nil || reconciled.State != "succeeded" || reconciled.Attempts != before.Attempts || reconciled.Fence != before.Fence {
							t.Fatal("AEAD recovery changed sending identity", err)
						}
						decryptFTPSReceiver(t, r, final, "recipient", peer, dir, a)
						mode := "explicit"
						if implicit {
							mode = "implicit"
						}
						requireOnlyReceiverReadAuditDigest(t, r, snapshot, snapshotReceiverReads(t, r), entry.FileID, "rename", mode, a.SHA256)
						requireFTPSArtifactReceipt(t, reconciled, a, true)
					} else {
						if out.Status.ObservedState != "succeeded" {
							t.Fatal("AEAD workflow did not finish")
						}
						requireFTPSArtifactReceipt(t, before, a, false)
						again, err := f.s.Work(f.ctx, f.scope, run.ID, "aead-worker")
						if err != nil || !again.Replayed || again.Dispatch != out.Dispatch || listener.contacts.Load() != contacts {
							t.Fatal("saved AEAD work resent", err)
						}
						decryptFTPSReceiver(t, r, final, "recipient", peer, dir, a)
					}
					if !reflect.DeepEqual(a, ftpsCiphertext(t, f, d.ID)) {
						t.Fatal("AEAD retry/recovery changed ciphertext")
					}
				})
			}
		}
	}
}
