package delivery

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/pkg/sftp"
)

// packetStream bounds server-controlled packet lengths before the SFTP library
// allocates its packet. One request at a time bounds outstanding payload buffers.
type packetStream struct {
	io.ReadWriteCloser
	header    [4]byte
	pending   []byte
	remaining uint32
}

func (s *packetStream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(s.pending) > 0 {
		n := copy(p, s.pending)
		s.pending = s.pending[n:]
		return n, nil
	}
	if s.remaining == 0 {
		if _, err := io.ReadFull(s.ReadWriteCloser, s.header[:]); err != nil {
			return 0, err
		}
		size := binary.BigEndian.Uint32(s.header[:])
		if size < 1 || size > 256<<10 {
			return 0, errors.New("receiver packet exceeds budget")
		}
		s.remaining = size
		s.pending = s.header[:]
		return s.Read(p)
	}
	if uint32(len(p)) > s.remaining {
		p = p[:s.remaining]
	}
	n, err := s.ReadWriteCloser.Read(p)
	s.remaining -= uint32(n)
	return n, err
}
func connect(ctx context.Context, spec *Definition) (*sftp.Client, io.Closer, error) {
	stream, err := secure.DialSFTP(ctx, spec.Destination)
	if err != nil {
		return nil, nil, err
	}
	client, err := sftp.NewClientPipe(&packetStream{ReadWriteCloser: stream}, stream, sftp.MaxPacket(32<<10), sftp.UseConcurrentReads(false), sftp.UseConcurrentWrites(false))
	if err != nil {
		stream.Close()
		return nil, nil, err
	}
	return client, stream, nil
}
func remoteDirectory(client *sftp.Client, directory string) error {
	current := "/"
	for _, part := range strings.Split(strings.TrimPrefix(directory, "/"), "/") {
		if part != "" {
			current = path.Join(current, part)
		}
		st, err := client.Lstat(current)
		if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return errors.New("approved remote directory is unavailable or unsafe")
		}
	}
	return nil
}
func verifyRemote(ctx context.Context, client *sftp.Client, name string, spec *Definition, check func() error) error {
	st, err := client.Lstat(name)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Size() != spec.Source.Size {
		return errors.New("remote file differs")
	}
	f, err := client.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err = f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() != spec.Source.Size {
		return errors.New("remote descriptor differs")
	}
	hash := secure.NewDigest()
	buffer := make([]byte, 32<<10)
	var offset int64
	for offset < spec.Source.Size {
		if err = ctx.Err(); err != nil {
			return err
		}
		if err = check(); err != nil {
			return err
		}
		want := min(int64(len(buffer)), spec.Source.Size-offset)
		n, readErr := io.ReadFull(f, buffer[:want])
		if n > 0 {
			hash.Write(buffer[:n])
			offset += int64(n)
		}
		if readErr != nil {
			return readErr
		}
	}
	var tail [1]byte
	if n, readErr := f.Read(tail[:]); n != 0 || readErr != io.EOF {
		return errors.New("remote file extended")
	}
	if fmt.Sprintf("%x", hash.Sum(nil)) != spec.Source.SHA256 {
		return errors.New("remote digest differs")
	}
	return f.Close()
}
func receipt(d *store.Delivery, spec *Definition, reconciled bool) json.RawMessage {
	value := map[string]any{"code": "remote_file_integrity_observed", "path": finalPath(d, spec), "size_bytes": spec.Source.Size, "sha256": spec.Source.SHA256, "host_fingerprint": spec.Destination.Host.Fingerprint, "file_fsync_acknowledged": !reconciled, "reconciled": reconciled, "business_acceptance": "unknown", "directory_power_loss_durability": "not established"}
	if a := spec.Transfer; a != nil {
		value["encryption"] = map[string]any{"key": a.Policy.Key, "profile": a.Policy.Profile, "primary_fingerprint": a.Proof.PrimaryFingerprint, "encryption_fingerprint": a.Proof.EncryptionFingerprint, "ciphertext_object_id": a.ObjectID, "source_file_id": a.SourceID, "source_sha256": a.SourceSHA256, "cipher": a.Proof.Cipher, "compression": a.Proof.Compression}
	}
	result, _ := json.Marshal(value)
	return result
}

// Work executes one intent, with one leased stream. It never scans unrelated
// actors or retries an uncertain publication. Calls may be safely scheduled again.
func (s *Service) Work(ctx context.Context, scope store.Scope, id string) (*store.Delivery, error) {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	admission, _, planned, err := s.begin(ctx, scope, id, false)
	if err != nil {
		return nil, err
	}
	if err = admission.CheckExecutionBinding(ctx, planned.Binding); err != nil {
		admission.Tx.Rollback(ctx)
		return nil, err
	}
	if err = admission.CheckOutboundDispatch(ctx, id); err != nil {
		admission.Tx.Rollback(ctx)
		return nil, err
	}
	if err = admission.Tx.Commit(ctx); err != nil {
		return nil, err
	}
	slot := s.Custody.DB.DeliveryWorkerSlot
	if planned.Encryption != nil {
		slot = s.Custody.DB.EncryptionWorkerSlot
	}
	slotCheck, release, err := slot(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		if release != nil {
			release()
		}
	}()
	owner := secure.NewID()
	d, spec, err := s.Claim(ctx, scope, id, owner)
	if err != nil {
		return nil, err
	}
	if d.State != "staging" {
		return d, nil
	}
	fence := d.Fence
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, err := s.transition(ctx, scope, id, owner, fence, "renew", nil); err != nil {
					cancel()
					return
				}
			}
		}
	}()
	defer func() { close(stop); cancel(); <-done }()
	check := func() error {
		if err := slotCheck(); err != nil {
			return err
		}
		return s.checkLease(ctx, scope, id, owner, fence)
	}
	// Keep stage failures retryable only before the external publication intent.
	stageFailure := func(code string) (*store.Delivery, error) {
		return s.transition(ctx, scope, id, owner, fence, "retry", observation(code))
	}
	if spec.Source.Size > s.Custody.MaxFile {
		return s.transition(ctx, scope, id, owner, fence, "blocked", observation("file_budget_exceeded"))
	}
	var source *os.File
	if spec.Encryption != nil {
		spec, source, err = s.prepareCiphertext(ctx, scope, d, spec, check)
		if err != nil {
			return stageFailure("encryption_preparation_unavailable")
		}
		release()
		release = nil
		slotCheck, release, err = s.Custody.DB.DeliveryWorkerSlot(ctx)
		if err != nil {
			source.Close()
			return stageFailure("delivery_capacity_unavailable")
		}
	} else {
		_, source, err = s.Custody.Download(ctx, scope, d.FileID)
		if err != nil {
			return s.transition(ctx, scope, id, owner, fence, "blocked", observation("source_not_verified"))
		}
	}
	defer source.Close()
	client, stream, err := connect(ctx, spec)
	if err != nil {
		return stageFailure("receiver_connection_failed")
	}
	defer stream.Close()
	defer client.Close()
	if err = remoteDirectory(client, spec.Directory); err != nil {
		return stageFailure("receiver_directory_unsafe")
	}
	if value, ok := client.HasExtension("fsync@openssh.com"); !ok || value != "1" {
		return stageFailure("receiver_fsync_required")
	}
	if value, ok := client.HasExtension("hardlink@openssh.com"); !ok || value != "1" {
		return stageFailure("receiver_atomic_link_required")
	}
	final := finalPath(d, spec)
	if _, err = client.Lstat(final); !os.IsNotExist(err) {
		return s.transition(ctx, scope, id, owner, fence, "blocked", observation("reserved_destination_exists_or_unreadable"))
	}
	temp := path.Join(spec.Directory, ".freightctl-"+id+"-"+strconv.FormatInt(fence, 10)+".partial")
	remote, err := client.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return stageFailure("receiver_stage_open_failed")
	}
	defer remote.Close() // Sealed or uncertain remote temporary files are retained, never guessed away.
	if err = remote.Chmod(0600); err != nil {
		return stageFailure("receiver_stage_mode_failed")
	}
	hash := secure.NewDigest()
	buffer := make([]byte, 32<<10)
	var offset int64
	for offset < spec.Source.Size {
		if err = check(); err != nil {
			return nil, err
		}
		n, readErr := io.ReadFull(source, buffer[:min(int64(len(buffer)), spec.Source.Size-offset)])
		if readErr != nil {
			return stageFailure("source_read_failed")
		}
		hash.Write(buffer[:n])
		written, writeErr := remote.Write(buffer[:n])
		if writeErr != nil || written != n {
			return stageFailure("receiver_stage_write_failed")
		}
		offset += int64(n)
	}
	if fmt.Sprintf("%x", hash.Sum(nil)) != spec.Source.SHA256 {
		return s.transition(ctx, scope, id, owner, fence, "blocked", observation("source_changed_during_delivery"))
	}
	if err = remote.Sync(); err != nil {
		return stageFailure("receiver_file_sync_failed")
	}
	if err = remote.Close(); err != nil {
		return stageFailure("receiver_stage_close_failed")
	}
	if err = verifyRemote(ctx, client, temp, spec, check); err != nil {
		return stageFailure("receiver_stage_integrity_failed")
	}
	// The committed publishing transition comes BEFORE the first visible effect.
	// A lost acknowledgment or worker lease now requires read-only reconciliation.
	d, err = s.transition(ctx, scope, id, owner, fence, "publishing", observation("atomic_publication_pending"))
	if err != nil {
		// No final operation has been attempted by this invocation. Record a
		// stage failure only if the locked durable row is still staging under
		// this live owner/fence. A lost commit acknowledgment may instead have
		// left it publishing; transition refuses to move that state to retry.
		// Preserve the original error even when failure recording succeeds.
		if failed, recordErr := stageFailure("publication_intent_not_confirmed"); recordErr == nil {
			return failed, err
		}
		return nil, err
	}
	if err = check(); err != nil {
		return nil, err
	}
	// OpenSSH's hardlink extension fails atomically if the final name exists. This
	// narrow profile deliberately requires it instead of overwrite-capable rename.
	if err = client.Link(temp, final); err != nil {
		return s.transition(ctx, scope, id, owner, fence, "ambiguous", observation("publication_outcome_uncertain"))
	}
	if err = verifyRemote(ctx, client, final, spec, check); err != nil {
		return s.transition(ctx, scope, id, owner, fence, "ambiguous", observation("publication_receipt_uncertain"))
	}
	// Removing the staging link cannot remove the final link. Failure retains it.
	_ = client.Remove(temp)
	return s.transition(ctx, scope, id, owner, fence, "succeeded", receipt(d, spec, false))
}

// Reconcile never sends, creates, renames or removes remote bytes. A missing file
// cannot prove the receiver never consumed it; ambiguity is retained in that case.
func (s *Service) Reconcile(ctx context.Context, scope store.Scope, id string) (*store.Delivery, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	t, d, spec, err := s.begin(ctx, scope, id, true)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if err = require(t, true); err != nil {
		return nil, err
	}
	if err = t.CheckExecutionObservationBinding(ctx, spec.Binding); err != nil {
		return nil, err
	}
	if err = s.storage(spec); err != nil {
		return nil, err
	}
	if spec.Encryption != nil {
		artifact, err := t.DeliveryCiphertext(ctx, id)
		if err != nil {
			return nil, err
		}
		spec, err = encryptedDefinition(spec, artifact)
		if err != nil {
			return nil, err
		}
	}
	now, err := t.DatabaseTime(ctx)
	if err != nil {
		return nil, err
	}
	if d.State == "succeeded" {
		return d, t.Tx.Commit(ctx)
	}
	if d.State != "ambiguous" && !(d.State == "publishing" && d.LeaseUntil != nil && !d.LeaseUntil.After(now)) {
		return nil, store.ErrState
	}
	if d.State == "publishing" {
		previous := d.Revision
		d.Revision++
		d.State = "ambiguous"
		clearLease(d)
		d.Observation = observation("worker_lost_during_publication")
		if err = t.SaveDelivery(ctx, d, previous); err != nil {
			return nil, err
		}
	}
	// Hold the intent row only during the bounded observation. Authority is checked
	// again for every read without opening another transaction on the same row.
	check := func() error {
		if err := t.Reauthorize(ctx); err != nil {
			return err
		}
		if err := require(t, true); err != nil {
			return err
		}
		if err := t.CheckExecutionObservationBinding(ctx, spec.Binding); err != nil {
			return err
		}
		if err := t.FileAccessible(ctx, d.FileID); err != nil {
			return err
		}
		return s.storage(spec)
	}
	client, stream, err := connect(ctx, spec)
	if err == nil {
		defer stream.Close()
		defer client.Close()
		if err = remoteDirectory(client, spec.Directory); err == nil {
			err = verifyRemote(ctx, client, finalPath(d, spec), spec, check)
		}
	}
	if err != nil { // Observation failure is itself retained, without inventing a receipt.
		if err = check(); err != nil {
			return nil, err
		}
		if _, err = t.Append(ctx, "DeliveryReconciliationObserved", d.ID, map[string]any{"definition_hash": d.DefinitionHash, "state": d.State, "code": "remote_postcondition_not_confirmed", "fence": d.Fence}); err != nil {
			return nil, err
		}
		// The previous publishing->ambiguous transition, if any, still commits.
		return d, t.Tx.Commit(ctx)
	}
	if err = check(); err != nil {
		return nil, err
	}
	previous := d.Revision
	d.Revision++
	d.State = "succeeded"
	d.Observation = receipt(d, spec, true)
	if err = t.SaveDelivery(ctx, d, previous); err != nil {
		return nil, err
	}
	return d, t.Tx.Commit(ctx)
}
