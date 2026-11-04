package delivery

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path"
	"regexp"
	"strings"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/ftpsclient"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/vpath"
)

// FTPSDefinition is a distinct schema2 delivery profile. It deliberately cannot
// inherit SFTP's exclusive hardlink or fsync guarantees. Registered workflows
// retain their exact execution binding; recipient encryption remains refused.
type FTPSDefinition struct {
	Destination      secure.FTPSDestination     `json:"destination"`
	StagingDirectory string                     `json:"staging_directory"`
	ReceiverContract store.FTPSReceiverContract `json:"receiver_contract"`
}

func ValidFTPSFilename(name string) bool {
	// The immutable final name has a UUID prefix, but a trailing dot still
	// violates the same virtual-path rule used by the wire adapter. Refuse it
	// before admitting a draft instead of stranding bytes after STOR.
	return namePattern.MatchString(name) && !strings.HasSuffix(name, ".")
}

// Valid checks only the immutable configuration. It opens no file or socket;
// the worker must still check the live references and execution authority.
func (f *FTPSDefinition) Valid(directory string) bool { return validFTPSDefinition(f, directory) }

var ftpsStepPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

func validFTPSBinding(b *store.ExecutionBinding) bool {
	return b == nil || (store.ValidID(b.WorkflowID) && b.WorkflowVersion > 0 && dispatchHashPattern.MatchString(b.WorkflowHash) && store.ValidID(b.RunID) && ftpsStepPattern.MatchString(b.StepID) && store.ValidID(b.ConnectionID) && b.ConnectionVersion > 0 && dispatchHashPattern.MatchString(b.ConnectionHash))
}

func validFTPSDefinition(f *FTPSDefinition, finalDirectory string) bool {
	if f == nil || secure.ValidateFTPSDestination(f.Destination) != nil {
		return false
	}
	for _, name := range []string{f.StagingDirectory, finalDirectory} {
		canonical, err := vpath.Canonical(name)
		if err != nil || canonical != name || len(name) > 768 || vpath.ControlPath(name) {
			return false
		}
	}
	// Separate approved trees prevent a staging path from being mistaken for a
	// final path. The receiver contract must also hide the stage from consumers.
	if vpath.Within(f.StagingDirectory, finalDirectory) || vpath.Within(finalDirectory, f.StagingDirectory) {
		return false
	}
	c := f.ReceiverContract
	return c.Schema == 1 && dispatchHashPattern.MatchString(c.DocumentSHA256) && c.StagingVisibility == "receiver-private" && c.Rename == "may-replace" && c.Duplicates == "receiver-deduplicates-delivery-id" && c.Receipt == "exact-readback"
}

func validProtocolDefinition(d *Definition) bool {
	if d.Schema == 1 {
		return d.FTPS == nil
	}
	ssh := d.Destination
	return d.Schema == 2 && ValidFTPSFilename(d.Filename) && d.Encryption == nil && validFTPSBinding(d.Binding) && d.Transfer == nil && ssh.Address == "" && ssh.User == "" && len(ssh.Host.Wire) == 0 && ssh.Host.Fingerprint == "" && ssh.KeyFile == "" && ssh.KeyFingerprint == "" && validFTPSDefinition(d.FTPS, d.Directory)
}

func ftpsStagingPath(d *store.Delivery, spec *Definition) string {
	return path.Join(spec.FTPS.StagingDirectory, ".freightctl-"+d.ID+".partial")
}

func ftpsEffect(d *store.Delivery, spec *Definition) *store.OutboundDispatchEffect {
	f := spec.FTPS
	dest := f.Destination
	return &store.OutboundDispatchEffect{Protocol: "ftps", Address: dest.Address, User: dest.User, Directory: spec.Directory, Filename: spec.Filename, FinalPath: finalPath(d, spec), Workflow: spec.Binding, FTPS: &store.OutboundFTPSEffect{Mode: dest.Mode, ServerName: dest.ServerName, CASHA256: dest.CASHA256, CAReferenceHash: secure.Digest([]byte(dest.CAFile)), PasswordReferenceHash: secure.Digest([]byte(dest.PasswordFile)), StagingPath: ftpsStagingPath(d, spec), ReceiverContract: f.ReceiverContract}}
}

func ftpsReceipt(d *store.Delivery, spec *Definition, reconciled bool) json.RawMessage {
	result, _ := json.Marshal(map[string]any{"code": "remote_file_integrity_observed", "protocol": "ftps", "path": finalPath(d, spec), "size_bytes": spec.Source.Size, "sha256": spec.Source.SHA256, "ca_sha256": spec.FTPS.Destination.CASHA256, "receiver_contract_sha256": spec.FTPS.ReceiverContract.DocumentSHA256, "upload_completion_acknowledged": !reconciled, "readback_completion_acknowledged": true, "rename_acknowledged": !reconciled, "file_fsync_acknowledged": false, "reconciled": reconciled, "business_acceptance": "unknown", "directory_power_loss_durability": "not established"})
	return result
}

// workFTPS shares Work's lease, worker slot, exact custody handle and authority
// checks. Commit publishing BEFORE STOR, not merely before RNTO: once bytes may
// have left, every failure is ambiguous and automatic sending cannot restart.
func (s *Service) workFTPS(ctx context.Context, scope store.Scope, d *store.Delivery, spec *Definition, owner string, fence int64, check func() error, source *os.File) (*store.Delivery, error) {
	client, err := ftpsclient.New(ctx, spec.FTPS.Destination, check)
	if err != nil {
		return s.transition(ctx, scope, d.ID, owner, fence, "retry", observation("receiver_connection_failed"))
	}
	defer client.Close()
	d, err = s.transition(ctx, scope, d.ID, owner, fence, "publishing", observation("ftps_write_intent_committed"))
	if err != nil {
		// An unconfirmed commit may already be publishing. Never try to convert
		// that uncertainty into retry or send bytes without confirmed intent.
		return nil, err
	}
	ambiguous := func(code string) (*store.Delivery, error) {
		return s.transition(ctx, scope, d.ID, owner, fence, "ambiguous", observation(code))
	}
	stage := ftpsStagingPath(d, spec)
	if _, err = client.StoreStage(stage, source, spec.Source.Size, 0, spec.Source.SHA256); err != nil {
		return ambiguous("ftps_stage_outcome_uncertain")
	}
	if err = client.RetrieveToStage(stage, io.Discard, spec.Source.Size, spec.Source.SHA256); err != nil {
		return ambiguous("ftps_stage_integrity_uncertain")
	}
	if err = client.Rename(stage, finalPath(d, spec)); err != nil {
		return ambiguous("ftps_rename_outcome_uncertain")
	}
	if err = client.RetrieveToStage(finalPath(d, spec), io.Discard, spec.Source.Size, spec.Source.SHA256); err != nil {
		return ambiguous("ftps_final_integrity_uncertain")
	}
	return s.transition(ctx, scope, d.ID, owner, fence, "succeeded", ftpsReceipt(d, spec, false))
}

func observeFTPS(ctx context.Context, d *store.Delivery, spec *Definition, check func() error) error {
	client, err := ftpsclient.New(ctx, spec.FTPS.Destination, check)
	if err != nil {
		return err
	}
	defer client.Close()
	// Retrieval has no file-mutating command. Missing/mismatched bytes leave the
	// old outcome ambiguous; even matching bytes do not invent an RNTO reply.
	return client.RetrieveToStage(finalPath(d, spec), io.Discard, spec.Source.Size, spec.Source.SHA256)
}
