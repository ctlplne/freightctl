//go:build integration && (linux || darwin)

package workflow

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/delivery"
	"github.com/ctlplne/freightctl/internal/store"
)

// The source and encrypted FTPS receiver are ordinary native service fixtures.
// OpenSSH and GnuPG independently verify their respective output contracts.
// This does not establish an independent FTPS source or business acceptance.
func TestFTPSCollectionRoutesStockSFTPAndEncryptedFTPSWithSeparateConsent(t *testing.T) {
	binary := routingKeyCLI(t)
	for _, implicit := range []bool{false, true} {
		t.Run(fmt.Sprintf("implicit-source-%t", implicit), func(t *testing.T) {
			f, sender, reviewer, account := outboundFixture(t)
			originalFixtureFile := f.file.ID
			producer, sourceSpec, sourceListener := governedFTPSReceiver(t, implicit)
			sourceConnection := registeredFTPSConnection(t, f, sourceSpec)
			receiver, receiverSpec, receiverListener := governedFTPSReceiver(t, !implicit)
			// The source registration key may only recover its original source;
			// it cannot register this different receiver in the same estate.
			if _, err := f.s.RegisterConnection(f.ctx, f.scope, "registered-ftps", ConnectionRequest{Directory: "/inbox", FTPS: &receiverSpec}); !errors.Is(err, store.ErrConflict) {
				t.Fatal("source registration key accepted a different receiver", err)
			}
			receiverConnection := registeredFTPSConnectionForOperation(t, f, receiverSpec, "registered-mixed-ftps-receiver")
			ssh := newMixedStockReceiver(t, f)
			key, peer, keyDirectory := ftpsRecipient(t, f, binary, "recipient")
			ref := func(c ConnectionView) Reference { return Reference{ID: c.ID, Version: c.Version, Hash: c.Hash} }
			source := collectionTestSource()
			source.Kind, source.Directory, source.Connection = "ftps.collect", "/", ref(sourceConnection)
			policy := &store.EncryptionPolicy{Key: store.PGPReference{ID: key.ID, Version: key.Version, Hash: key.Hash}, Profile: secure.PGPEncryptMDC}
			steps := []Step{
				{ID: "stock-ssh", Kind: "sftp.deliver", Connection: ref(ssh.connection), Filename: "collected.csv"},
				{ID: "encrypted-ftp", Kind: "ftps.deliver", Connection: ref(receiverConnection), Filename: "collected.pgp", Encryption: policy},
			}
			definition := Definition{Schema: 1, Name: "Collected FTPS settlement with two separately governed receivers", Source: &source, Steps: steps}
			configuration := f.approved(t, definition)
			tx, err := f.s.Custody.DB.Begin(f.ctx, f.scope)
			if err != nil {
				t.Fatal(err)
			}
			authority := tx.AuthorityRevision
			tx.Tx.Rollback(f.ctx)
			x := ftpsCollectionSetup{f: f, producer: producer, connection: sourceConnection, source: source,
				workflow: Reference{ID: configuration.ID, Version: configuration.Version, Hash: configuration.Hash}, listener: sourceListener}
			x.selection = CollectionSelection{Workflow: x.workflow, Timeout: 120, Authority: authority}
			producerFile := publishFTPSCollectionObject(t, x, "one.csv", []byte("abc"))
			publishFTPSCollectionManifest(t, x, source.Manifest, []CollectionFile{{Name: "one.csv", Size: 3, SHA256: producerFile.SHA256}})
			job, _ := startCollection(t, f, x.selection, "mixed-collection-start")
			if sourceListener.contacts.Load() != 0 || receiverListener.contacts.Load() != 0 || ssh.sessions(t) != 0 {
				t.Fatal("source approval or queue contacted a source or receiver")
			}
			capture, err := f.s.WorkCollection(f.ctx, f.scope, job.ID, "mixed-source-worker", CollectionWorkRequest{Hash: job.Hash})
			if err != nil {
				t.Fatal(err)
			}
			captured := requireCollectedFTPSBytes(t, x, job.ID, []byte("abc"))
			if captured.Job.Attempts != 1 || captured.Job.Fence != 1 || sourceListener.contacts.Load() != 1 || captured.Inputs[0].FileID == nil || captured.Inputs[0].RunID != nil {
				t.Fatal("capture duplicated a source acquisition or prematurely queued output")
			}
			file, reader, err := f.s.Custody.Download(f.ctx, f.scope, *captured.Inputs[0].FileID)
			if err != nil {
				t.Fatal(err)
			}
			reader.Close()
			if file.ID == originalFixtureFile || file.ID == producerFile.ID || file.ID != captured.Inputs[0].ObjectID {
				t.Fatal("collected workflow substituted another immutable file")
			}
			f.file = file
			decision := Decision{Hash: captured.Job.Hash, Revision: captured.Job.Revision}
			admitted, err := f.s.RefreshCollection(f.ctx, f.scope, job.ID, "mixed-admit", decision)
			if err != nil {
				t.Fatal(err)
			}
			again, err := f.s.RefreshCollection(f.ctx, f.scope, job.ID, "mixed-admit", decision)
			if err != nil || !again.Replayed || !bytes.Equal(admitted.Resource, again.Resource) {
				t.Fatal("collection admission changed its original receipt", err)
			}
			view, err := f.s.CollectionStatus(f.ctx, f.scope, job.ID)
			if err != nil || len(view.Inputs) != 1 || view.Inputs[0].RunID == nil || view.Inputs[0].FileID == nil || *view.Inputs[0].FileID != file.ID {
				t.Fatal("collected output run lost exact input lineage", err)
			}
			run := *view.Inputs[0].RunID
			status, err := f.s.Status(f.ctx, f.scope, run)
			if err != nil || status.Run.FileID != file.ID || status.Run.Source != *file || len(status.Steps) != 2 || status.Steps[0].ID != steps[0].ID || status.Steps[1].ID != steps[1].ID {
				t.Fatal("mixed collected run lost its source or approved order", err)
			}
			intents := make([]*store.Delivery, 2)
			for index, step := range status.Steps {
				intents[index], err = sender.Status(f.ctx, f.scope, step.DeliveryID)
				var spec delivery.Definition
				if err != nil || json.Unmarshal(intents[index].Definition, &spec) != nil || spec.Source != *file || spec.Binding == nil || spec.Binding.RunID != run || spec.Binding.WorkflowHash != configuration.Hash || spec.Binding.ConnectionHash != steps[index].Connection.Hash {
					t.Fatal("mixed intent substituted source, workflow or receiver", err)
				}
			}
			if _, err = f.s.Work(f.ctx, f.scope, run, "mixed-first"); !errors.Is(err, store.ErrDispatchApproval) {
				t.Fatal("source collection approval authorized a receiver", err)
			}
			if receiverListener.contacts.Load() != 0 || ssh.sessions(t) != 0 || sourceListener.contacts.Load() != 1 {
				t.Fatal("unapproved sending contacted a peer")
			}
			requireNoFTPSCiphertext(t, f, intents[1].ID)
			_, firstReview, _ := proposeDispatch(t, f, sender, intents[0], account.ID, "collected-ssh-review")
			if _, _, err = decideDispatch(t, f, sender, reviewer, firstReview, "approve", "collected-ssh-consent"); err != nil {
				t.Fatal(err)
			}
			first, err := f.s.Work(f.ctx, f.scope, run, "mixed-first")
			if err != nil || !first.Replayed || first.Status.Steps[0].State != "succeeded" || first.Status.Steps[1].State != "queued" || receiverListener.contacts.Load() != 0 {
				t.Fatal("first receiver consent advanced encrypted sending", err)
			}
			ssh.requireBytes(t, f, intents[0].ID+"-collected.csv")
			sshSessions := ssh.sessions(t)
			if _, err = f.s.Work(f.ctx, f.scope, run, "mixed-second"); !errors.Is(err, store.ErrDispatchApproval) || ssh.sessions(t) != sshSessions || receiverListener.contacts.Load() != 0 {
				t.Fatal("first receiver consent authorized the encrypted receiver", err)
			}
			requireNoFTPSCiphertext(t, f, intents[1].ID)
			review := approveFTPS(t, f, sender, intents[1], reviewer, account)
			reviewView, err := sender.DispatchReview(f.ctx, reviewer, review.ID)
			if err != nil || reviewView.Definition.Effect.Encryption == nil || *reviewView.Definition.Effect.Encryption != *policy || reviewView.Definition.Effect.RecipientFingerprint != key.Fingerprint {
				t.Fatal("encrypted collected review lost exact recipient", err)
			}
			second, err := f.s.Work(f.ctx, f.scope, run, "mixed-second")
			if err != nil || !second.Replayed || second.Status.ObservedState != "succeeded" {
				t.Fatal("approved encrypted collected workflow did not finish", err)
			}
			ciphertext := ftpsCiphertext(t, f, intents[1].ID)
			if ciphertext.SourceID != file.ID || ciphertext.SourceSHA256 != file.SHA256 || ciphertext.Policy != *policy || ciphertext.DefinitionHash != intents[1].DefinitionHash {
				t.Fatal("ciphertext is detached from captured file or recipient")
			}
			decryptFTPSReceiver(t, receiver, "/inbox/"+intents[1].ID+"-collected.pgp", "recipient", peer, keyDirectory, ciphertext)
			for index, intent := range intents {
				current, err := sender.Status(f.ctx, f.scope, intent.ID)
				if err != nil || current.Attempts != 1 || current.Fence != 1 {
					t.Fatal("mixed collected sending duplicated attempts", err)
				}
				if index == 1 {
					requireFTPSArtifactReceipt(t, current, ciphertext, false)
				} else {
					var receipt map[string]any
					if json.Unmarshal(current.Observation, &receipt) != nil || receipt["business_acceptance"] != "unknown" || receipt["file_fsync_acknowledged"] != true || receipt["sha256"] != file.SHA256 {
						t.Fatal("stock SFTP collected receipt lost source or inflated business acceptance")
					}
				}
			}
			receiverContacts := receiverListener.contacts.Load()
			for _, key := range []string{"mixed-first", "mixed-second"} {
				replay, err := f.s.Work(f.ctx, f.scope, run, key)
				if err != nil || !replay.Replayed || replay.Status.ObservedState != "succeeded" || ssh.sessions(t) != sshSessions || receiverListener.contacts.Load() != receiverContacts || sourceListener.contacts.Load() != 1 {
					t.Fatal("completed saved worker key resent or recollected bytes", err)
				}
			}
			replay, err := f.s.WorkCollection(f.ctx, f.scope, job.ID, "mixed-source-worker", CollectionWorkRequest{Hash: job.Hash})
			if err != nil || !replay.Replayed || !reflect.DeepEqual(replay.Resource, capture.Resource) || sourceListener.contacts.Load() != 1 {
				t.Fatal("saved source key recollected or changed its original receipt", err)
			}
		})
	}
}
