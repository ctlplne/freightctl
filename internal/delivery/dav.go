package delivery

import (
	"context"
	"encoding/json"
	"os"
	"path"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/vpath"
)

// DAVDefinition is a distinct schema3 direct-delivery profile. Read-only DAV
// collection connections cannot be selected here. Registered workflow/encryption
// support requires its own exact bindings and is refused by this first profile.
type DAVDefinition struct {
	Destination      secure.HTTPSReadDestination `json:"destination"`
	StagingDirectory string                      `json:"staging_directory"`
	ReceiverContract store.DAVReceiverContract   `json:"receiver_contract"`
}

func (d *DAVDefinition) Valid(directory string) bool {
	if d == nil || secure.ValidateHTTPSReadDestination(d.Destination) != nil {
		return false
	}
	for _, p := range []string{directory, d.StagingDirectory} {
		canonical, err := vpath.Canonical(p)
		if err != nil || canonical != p || len(p) > 768 || vpath.ControlPath(p) {
			return false
		}
	}
	if vpath.Within(directory, d.StagingDirectory) || vpath.Within(d.StagingDirectory, directory) {
		return false
	}
	c := d.ReceiverContract
	return c.Schema == 1 && dispatchHashPattern.MatchString(c.DocumentSHA256) && c.StagingVisibility == "receiver-private" && c.Put == "exclusive-create" && c.Move == "source-etag-no-overwrite" && c.Duplicates == "receiver-deduplicates-delivery-id" && c.Receipt == "exact-readback"
}

func davStagingPath(d *store.Delivery, spec *Definition) string {
	return path.Join(spec.DAV.StagingDirectory, ".freightctl-"+d.ID+".partial")
}

func davEffect(d *store.Delivery, spec *Definition) *store.OutboundDispatchEffect {
	dest := spec.DAV.Destination
	proof := &store.OutboundDAVEffect{Profile: "freightctl-webdav-delivery-v1", Authentication: "bearer", ServerName: dest.ServerName, CASHA256: dest.CASHA256, CAReferenceHash: secure.Digest([]byte(dest.CAFile)), StagingPath: davStagingPath(d, spec), ReceiverContract: spec.DAV.ReceiverContract}
	if dest.Authentication == "basic" {
		proof.Authentication, proof.PasswordReferenceHash = "basic", secure.Digest([]byte(dest.PasswordFile))
	} else {
		proof.TokenReferenceHash = secure.Digest([]byte(dest.TokenFile))
	}
	return &store.OutboundDispatchEffect{Protocol: "webdav", Address: dest.Address, User: dest.User, Directory: spec.Directory, Filename: spec.Filename, FinalPath: finalPath(d, spec), DAV: proof}
}

func davReceipt(d *store.Delivery, spec *Definition, reconciled bool) json.RawMessage {
	value := map[string]any{"code": "remote_file_integrity_observed", "protocol": "webdav", "path": finalPath(d, spec), "size_bytes": spec.Source.Size, "sha256": spec.Source.SHA256, "ca_sha256": spec.DAV.Destination.CASHA256, "receiver_contract_sha256": spec.DAV.ReceiverContract.DocumentSHA256, "upload_completion_acknowledged": !reconciled, "readback_completion_acknowledged": true, "move_acknowledged": !reconciled, "source_etag_conditioned": !reconciled, "overwrite": "F", "file_fsync_acknowledged": false, "reconciled": reconciled, "business_acceptance": "unknown", "directory_power_loss_durability": "not established"}
	result, _ := json.Marshal(value)
	return result
}

// Commit publishing before PUT,not merely before MOVE. Once any stage bytes
// may have left,every failure stays ambiguous. Ordinary Work owns the exact
// immutable descriptor,worker slot,renewing lease,fence and live dispatch checks.
func (s *Service) workDAV(ctx context.Context, scope store.Scope, d *store.Delivery, spec *Definition, owner string, fence int64, check func() error, source *os.File) (*store.Delivery, error) {
	client, err := secure.NewDAVDeliveryClient(ctx, spec.DAV.Destination, davStagingPath(d, spec), finalPath(d, spec), spec.Source.Size, spec.Source.SHA256, check)
	if err != nil {
		return s.transition(ctx, scope, d.ID, owner, fence, "retry", observation("dav_receiver_identity_unavailable"))
	}
	defer client.Close()
	d, err = s.transition(ctx, scope, d.ID, owner, fence, "publishing", observation("dav_write_intent_committed"))
	if err != nil {
		return nil, err
	}
	ambiguous := func(code string) (*store.Delivery, error) {
		return s.transition(ctx, scope, d.ID, owner, fence, "ambiguous", observation(code))
	}
	if err = client.PutStage(ctx, source); err != nil {
		return ambiguous("dav_stage_outcome_uncertain")
	}
	if err = client.VerifyStage(ctx); err != nil {
		return ambiguous("dav_stage_integrity_uncertain")
	}
	if err = client.Publish(ctx); err != nil {
		return ambiguous("dav_move_outcome_uncertain")
	}
	if err = client.VerifyFinal(ctx); err != nil {
		return ambiguous("dav_final_integrity_uncertain")
	}
	return s.transition(ctx, scope, d.ID, owner, fence, "succeeded", davReceipt(d, spec, false))
}

func observeDAV(ctx context.Context, d *store.Delivery, spec *Definition, check func() error) error {
	client, err := secure.NewDAVDeliveryClient(ctx, spec.DAV.Destination, davStagingPath(d, spec), finalPath(d, spec), spec.Source.Size, spec.Source.SHA256, check)
	if err != nil {
		return err
	}
	defer client.Close()
	// Only the exact final GET is performed. No stage write,MOVE or cleanup is
	// reachable through this function,including after missing/mismatched bytes.
	return client.VerifyFinal(ctx)
}
