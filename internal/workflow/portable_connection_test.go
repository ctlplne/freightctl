package workflow

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/delivery"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestPortableConnectionSnapshotSurvivesMissingSSHCredential(t *testing.T) {
	dir := t.TempDir()
	private, public := filepath.Join(dir, "client.key"), filepath.Join(dir, "client.pub")
	if err := secure.GenerateSSHHostIdentity(private, public); err != nil {
		t.Fatal(err)
	}
	identity, err := secure.ReadSSHPublic(public)
	if err != nil {
		t.Fatal(err)
	}
	definition := ConnectionDefinition{Schema: 1, Directory: "/proof", Destination: secure.SSHDestination{
		Address: "127.0.0.1:9", User: "receiver", Host: identity, KeyFile: private, KeyFingerprint: identity.Fingerprint,
	}}
	raw, hash, err := digest(definition)
	if err != nil {
		t.Fatal(err)
	}
	stored := &store.Configuration{Definition: raw, Hash: hash}
	if _, err = connectionDefinition(stored); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(private); err != nil {
		t.Fatal(err)
	}
	if _, err = connectionDefinition(stored); !errors.Is(err, store.ErrState) {
		t.Fatalf("ordinary validation with missing private key: %v", err)
	}
	snapshot, err := connectionDefinitionSnapshot(stored)
	if err != nil || snapshot.Destination.Host.Fingerprint != identity.Fingerprint {
		t.Fatalf("stored public identity was lost: %v", err)
	}
	definition.Destination.Host.Fingerprint = "SHA256:substituted"
	stored.Definition, stored.Hash, err = digest(definition)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = connectionDefinitionSnapshot(stored); !errors.Is(err, store.ErrState) {
		t.Fatalf("snapshot validation with invalid host identity: %v", err)
	}
}

func TestPortableConnectionRegistrationOmitsCredentialReferencesAndDigests(t *testing.T) {
	const reference = "/private/original-credential"
	const secretDigest = "1111111111111111111111111111111111111111111111111111111111111111"
	const certificate = "2222222222222222222222222222222222222222222222222222222222222222"
	for _, test := range []struct {
		protocol string
		bindings int
		source   ConnectionDefinition
	}{
		{"sftp", 3, ConnectionDefinition{Schema: 1, Directory: "/proof",
			Destination: secure.SSHDestination{Address: "127.0.0.1:9", User: "test", KeyFile: reference}}},
		{"ftps", 3, ConnectionDefinition{Schema: 2, Directory: "/proof",
			FTPS: &delivery.FTPSDefinition{StagingDirectory: "/temporary", Destination: secure.FTPSDestination{
				CASHA256: certificate, CAFile: reference, PasswordFile: reference, PasswordSHA256: secretDigest,
			}}}},
		{"local", 3, ConnectionDefinition{Schema: 3, Directory: "/",
			Local: &delivery.LocalCollectionSource{Schema: 1, Reference: reference, SHA256: secretDigest, RootFingerprint: secretDigest}}},
		{"webdav", 3, ConnectionDefinition{Schema: 4, Directory: "/proof",
			DAV: &delivery.DAVCollectionSource{Schema: 1, Destination: secure.HTTPSReadDestination{
				CASHA256: certificate, CAFile: reference, TokenSHA256: secretDigest, TokenFile: reference,
			}}}},
		{"webdav", 3, ConnectionDefinition{Schema: 4, Directory: "/proof",
			DAV: &delivery.DAVCollectionSource{Schema: 2, Destination: secure.HTTPSReadDestination{
				Authentication: "basic", User: "operator", CASHA256: certificate, CAFile: reference,
				PasswordSHA256: secretDigest, PasswordFile: reference,
			}}}},
	} {
		export := portableConnectionRegistration(test.source)
		raw, err := json.Marshal(export)
		if err != nil || export.Protocol != test.protocol || len(export.RequiredBindings) != test.bindings ||
			export.Registration.ID != "" || export.Registration.ExpectedVersion != 0 ||
			strings.Contains(string(raw), reference) || strings.Contains(string(raw), secretDigest) {
			t.Fatalf("portable %s plan flows a private reference or changed meaning: %v", test.protocol, err)
		}
		if (test.protocol == "ftps" || test.protocol == "webdav") && !strings.Contains(string(raw), certificate) {
			t.Fatalf("portable %s plan lost the public trust pin", test.protocol)
		}
	}
}
