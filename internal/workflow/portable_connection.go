package workflow

import (
	"context"
	"io"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/delivery"
	"github.com/ctlplne/freightctl/internal/store"
)

const PortableConnectionProfile = "freightctl-portable-connection-v1"

type PortableConnection struct {
	SchemaVersion      int               `json:"schema_version"`
	Profile            string            `json:"profile"`
	SourceTenant       string            `json:"source_tenant_id"`
	SourcePartner      string            `json:"source_partner_id"`
	Source             Reference         `json:"source"`
	ObservedState      string            `json:"observed_state"`
	Protocol           string            `json:"protocol"`
	Registration       ConnectionRequest `json:"destination_registration"`
	RequiredBindings   []string          `json:"required_bindings"`
	SourceSSHHostPin   string            `json:"source_ssh_host_fingerprint,omitempty"`
	SourceSSHClientPin string            `json:"source_ssh_client_fingerprint,omitempty"`
}

// portableConnectionRegistration copies an explicit allowlist. Credential
// paths and credential-byte hashes cannot flow into the destination template.
func portableConnectionRegistration(d ConnectionDefinition) PortableConnection {
	result := PortableConnection{Registration: ConnectionRequest{Directory: d.Directory}}
	switch d.Schema {
	case 1:
		result.Protocol = "sftp"
		result.Registration.Address, result.Registration.User = d.Destination.Address, d.Destination.User
		result.SourceSSHHostPin, result.SourceSSHClientPin = d.Destination.Host.Fingerprint, d.Destination.KeyFingerprint
		result.RequiredBindings = []string{"host_public_file", "key_file", "key_public_file"}
	case 2:
		result.Protocol = "ftps"
		ftps := d.FTPS
		result.Registration.FTPS = &delivery.FTPSDefinition{
			Destination: secure.FTPSDestination{
				Address: ftps.Destination.Address, ServerName: ftps.Destination.ServerName, Mode: ftps.Destination.Mode,
				User: ftps.Destination.User, CASHA256: ftps.Destination.CASHA256,
			},
			StagingDirectory: ftps.StagingDirectory, ReceiverContract: ftps.ReceiverContract,
		}
		result.RequiredBindings = []string{"ftps.destination.ca_reference", "ftps.destination.password_reference", "ftps.destination.password_sha256"}
	case 3:
		result.Protocol = "local"
		result.Registration.Local = &delivery.LocalCollectionSource{Schema: d.Local.Schema}
		result.RequiredBindings = []string{"local.root_reference", "local.configuration_sha256", "local.root_fingerprint"}
	case 4:
		result.Protocol = "webdav"
		dav := d.DAV.Destination
		result.Registration.DAV = &delivery.DAVCollectionSource{
			Schema: d.DAV.Schema,
			Destination: secure.HTTPSReadDestination{
				Address: dav.Address, ServerName: dav.ServerName, CASHA256: dav.CASHA256,
				Authentication: dav.Authentication, User: dav.User,
			},
		}
		result.RequiredBindings = []string{"dav.destination.ca_reference"}
		if dav.Authentication == "basic" {
			result.RequiredBindings = append(result.RequiredBindings, "dav.destination.password_reference", "dav.destination.password_sha256")
		} else {
			result.RequiredBindings = append(result.RequiredBindings, "dav.destination.token_reference", "dav.destination.token_sha256")
		}
	}
	return result
}

func (s *Service) PreparePortableConnection(ctx context.Context, scope store.Scope, ref Reference, output io.Writer) (*PortableExportReceipt, error) {
	if !store.ValidID(ref.ID) || ref.Version < 1 || !hashPattern.MatchString(ref.Hash) {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer tx.Tx.Rollback(ctx)
	if !tx.Has("connections_manage") && !tx.Has("workflow_manage") && !tx.Has("workflow_approve") && !tx.Has("workflow_execute") {
		return nil, store.ErrForbidden
	}
	stored, err := tx.Configuration(ctx, true, ref.ID, ref.Version, false)
	if err != nil {
		return nil, err
	}
	if stored.Hash != ref.Hash {
		return nil, store.ErrRevision
	}
	definition, err := connectionDefinitionSnapshot(stored)
	if err != nil {
		return nil, err
	}
	manifest := portableConnectionRegistration(*definition)
	manifest.SchemaVersion, manifest.Profile = 1, PortableConnectionProfile
	manifest.SourceTenant, manifest.SourcePartner = scope.Tenant, scope.Partner
	manifest.Source, manifest.ObservedState = ref, stored.State
	return writePortableExport(ctx, tx, "PortableConnectionExportPrepared", ref, manifest, output)
}
