package workflow

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/delivery"
	"github.com/ctlplne/freightctl/internal/store"
)

func exchangeFixture(t *testing.T) (*store.OnboardingProbe, *RunView, Step, *ConnectionDefinition, *store.Delivery) {
	t.Helper()
	now := time.Now().UTC()
	p := &store.OnboardingProbe{State: "succeeded", CompletedAt: &now, Observation: store.OnboardingProbeObservation{Code: "connectivity_verified", SSH: true, SFTP: true, Extensions: true, Directory: true}}
	run := &store.WorkflowRun{ID: secure.NewID(), WorkflowID: secure.NewID(), WorkflowVersion: 2, WorkflowHash: secure.Digest([]byte("workflow")), FileID: secure.NewID(), StorageID: secure.NewID(), Root: "/", Authority: 7}
	run.Source = store.File{ID: run.FileID, Size: 123, SHA256: secure.Digest([]byte("source")), Policy: "sha256", EventID: secure.NewID()}
	step := Step{ID: "send", Kind: "sftp.deliver", Connection: Reference{ID: secure.NewID(), Version: 3, Hash: secure.Digest([]byte("connection"))}, Filename: "sample.csv"}
	conn := &ConnectionDefinition{Schema: 1, Directory: "/inbox", Destination: secure.SSHDestination{Address: "127.0.0.1:2222", User: "synthetic", KeyFile: "/private/reference", Host: secure.SSHPublic{Fingerprint: "SHA256:synthetic"}}}
	spec := delivery.Definition{Schema: 1, Source: run.Source, Destination: conn.Destination, Directory: conn.Directory, Filename: step.Filename, StorageID: run.StorageID, Root: run.Root, Authority: run.Authority, Binding: &store.ExecutionBinding{WorkflowID: run.WorkflowID, WorkflowVersion: run.WorkflowVersion, WorkflowHash: run.WorkflowHash, RunID: run.ID, StepID: step.ID, ConnectionID: step.Connection.ID, ConnectionVersion: step.Connection.Version, ConnectionHash: step.Connection.Hash}}
	data, hash, err := digest(spec)
	if err != nil {
		t.Fatal(err)
	}
	observation, _ := json.Marshal(exchangeReceipt{Code: "remote_file_integrity_observed", SHA256: run.Source.SHA256, Size: run.Source.Size, Host: conn.Destination.Host.Fingerprint, FileFsync: true, Business: "unknown", DirectoryDurability: "not established"})
	intent := &store.Delivery{ID: secure.NewID(), FileID: run.FileID, Definition: data, DefinitionHash: hash, State: "succeeded", Revision: 5, Observation: observation}
	return p, &RunView{Run: run, ObservedState: "succeeded"}, step, conn, intent
}

func TestOnboardingExchangeNeverPromotesIntegrityToBusinessAcceptance(t *testing.T) {
	p, run, step, conn, intent := exchangeFixture(t)
	for _, required := range []string{"transport", "integrity", "business"} {
		var out OnboardingExchangeSnapshot
		reason, err := assessExchange(required, p, run, step, conn, intent, nil, &out)
		want := "recorded_evidence_matches"
		if required == "business" {
			want = "business_receipt_missing"
		}
		if err != nil || reason != want || out.ObservedReceipt != "integrity" || out.TransferSHA256 != run.Run.Source.SHA256 {
			t.Fatal(required, reason, err)
		}
	}
	// Reconciliation proves observed integrity but cannot invent fsync acknowledgment.
	var receipt exchangeReceipt
	_ = json.Unmarshal(intent.Observation, &receipt)
	receipt.Reconciled = true
	receipt.FileFsync = false
	intent.Observation, _ = json.Marshal(receipt)
	var out OnboardingExchangeSnapshot
	if reason, err := assessExchange("integrity", p, run, step, conn, intent, nil, &out); err != nil || reason != "recorded_evidence_matches" || out.FileFsync || !out.Reconciled {
		t.Fatal(reason, err)
	}
}

func TestOnboardingExchangeRejectsUnfinishedOrUnrelatedEvidence(t *testing.T) {
	for _, change := range []string{"probe", "probe_flags", "workflow", "delivery", "source", "binding", "destination", "hash", "receipt", "business", "fsync"} {
		t.Run(change, func(t *testing.T) {
			p, run, step, conn, intent := exchangeFixture(t)
			var out OnboardingExchangeSnapshot
			switch change {
			case "probe":
				p.State = "running"
			case "probe_flags":
				p.Observation.Directory = false
			case "workflow":
				run.ObservedState = "attention"
			case "delivery":
				intent.State = "ambiguous"
			case "source":
				run.Run.Source.SHA256 = secure.Digest([]byte("other"))
			case "binding":
				step.Connection.Version++
			case "destination":
				conn.Directory = "/different"
			case "hash":
				intent.DefinitionHash = secure.Digest([]byte("forged"))
			default:
				var r exchangeReceipt
				_ = json.Unmarshal(intent.Observation, &r)
				switch change {
				case "receipt":
					r.SHA256 = secure.Digest([]byte("other"))
				case "business":
					r.Business = "accepted"
				case "fsync":
					r.FileFsync = false
				}
				intent.Observation, _ = json.Marshal(r)
			}
			reason, err := assessExchange("integrity", p, run, step, conn, intent, nil, &out)
			if err == nil && reason == "recorded_evidence_matches" {
				t.Fatal("unrelated or insufficient evidence accepted", change)
			}
		})
	}
}

func TestOnboardingExchangeEncryptedReceiptMustBindCiphertextAndSource(t *testing.T) {
	p, run, step, conn, intent := exchangeFixture(t)
	policy := store.EncryptionPolicy{Key: store.PGPReference{ID: secure.NewID(), Version: 1, Hash: secure.Digest([]byte("recipient"))}, Profile: "seipd-v1-aes256"}
	step.Encryption = &policy
	var spec delivery.Definition
	_ = json.Unmarshal(intent.Definition, &spec)
	spec.Encryption = &policy
	intent.Definition, intent.DefinitionHash, _ = digest(spec)
	cipher := &store.DeliveryCiphertext{DeliveryID: intent.ID, SourceID: run.Run.FileID, SourceSHA256: run.Run.Source.SHA256, StorageID: run.Run.StorageID, DefinitionHash: intent.DefinitionHash, Policy: policy, Size: 321, SHA256: secure.Digest([]byte("ciphertext"))}
	var r exchangeReceipt
	_ = json.Unmarshal(intent.Observation, &r)
	r.SHA256 = cipher.SHA256
	r.Size = cipher.Size
	intent.Observation, _ = json.Marshal(r)
	var out OnboardingExchangeSnapshot
	if reason, err := assessExchange("integrity", p, run, step, conn, intent, cipher, &out); err != nil || reason != "recorded_evidence_matches" || out.TransferSHA256 != cipher.SHA256 {
		t.Fatal(reason, err)
	}
	cipher.SourceID = secure.NewID()
	if _, err := assessExchange("integrity", p, run, step, conn, intent, cipher, &out); err == nil {
		t.Fatal("ciphertext for another source accepted")
	}
}

func TestOnboardingExchangeGoAndBrowserShareCanonicalSnapshot(t *testing.T) {
	data, err := os.ReadFile("../../web/tests/fixtures/onboarding-exchange-review.json")
	if err != nil {
		t.Fatal(err)
	}
	var review OnboardingExchangeReview
	if json.Unmarshal(data, &review) != nil {
		t.Fatal("cross-language fixture")
	}
	_, hash, err := digest(review.Snapshot)
	if err != nil || hash != review.Hash || !validExchangeRequest(review.Snapshot.Selection) {
		t.Fatal("browser snapshot hash differs from Go", hash, review.Hash, err)
	}
}
