package workflow

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/delivery"
	"github.com/ctlplne/freightctl/internal/store"
)

func ftpsConnectionContract() ConnectionDefinition {
	refs := filepath.Join(os.TempDir(), "freightctl-connection-contract")
	return ConnectionDefinition{Schema: 2, Directory: "/inbox", FTPS: &delivery.FTPSDefinition{
		Destination:      secure.FTPSDestination{Address: "127.0.0.1:990", ServerName: "localhost", Mode: "implicit", User: "receiver", CAFile: filepath.Join(refs, "ca.pem"), CASHA256: strings.Repeat("a", 64), PasswordFile: filepath.Join(refs, "password"), PasswordSHA256: strings.Repeat("b", 64)},
		StagingDirectory: "/private-stage", ReceiverContract: store.FTPSReceiverContract{Schema: 1, DocumentSHA256: strings.Repeat("c", 64), StagingVisibility: "receiver-private", Rename: "may-replace", Duplicates: "receiver-deduplicates-delivery-id", Receipt: "exact-readback"}}}
}

func connectionContractRow(t *testing.T, d ConnectionDefinition) *store.Configuration {
	t.Helper()
	data, hash, err := digest(d)
	if err != nil {
		t.Fatal(err)
	}
	return &store.Configuration{ID: "00000000-0000-0000-0000-000000000001", Version: 1, Hash: hash, Definition: data, State: "active", Revision: 1}
}

func TestFTPSConnectionViewBindsCanonicalVersionAndRedactsCredentialProof(t *testing.T) {
	d := ftpsConnectionContract()
	row := connectionContractRow(t, d)
	v, err := viewConnection(row)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(v)
	for _, secret := range []string{d.FTPS.Destination.CAFile, d.FTPS.Destination.PasswordFile, d.FTPS.Destination.PasswordSHA256, "password_sha256", "password_reference\""} {
		if strings.Contains(string(data), secret) {
			t.Fatal("connection view exposed a local reference or password proof")
		}
	}
	if v.Protocol != "ftps" || v.Address != d.FTPS.Destination.Address || v.User != d.FTPS.Destination.User || v.FTPS.PasswordReferenceHash != secure.Digest([]byte(d.FTPS.Destination.PasswordFile)) || v.HostFingerprint != "" || v.KeyFingerprint != "" || v.FTPS.StagingDirectory != "/private-stage" {
		t.Fatal("wrong registered FTPS review metadata")
	}
	row.Hash = strings.Repeat("f", 64)
	if _, err = viewConnection(row); err != store.ErrState {
		t.Fatal("connection definition checksum was not enforced", err)
	}
}

func TestFTPSConnectionDefinitionRejectsMixedProtocolAndUnsafeContract(t *testing.T) {
	for name, change := range map[string]func(*ConnectionDefinition){
		"legacy schema":    func(d *ConnectionDefinition) { d.Schema = 1 },
		"missing protocol": func(d *ConnectionDefinition) { d.FTPS = nil },
		"mixed SSH":        func(d *ConnectionDefinition) { d.Destination.Address = "127.0.0.1:22" },
		"external address": func(d *ConnectionDefinition) { d.FTPS.Destination.Address = "192.0.2.1:990" },
		"stage exposed":    func(d *ConnectionDefinition) { d.FTPS.StagingDirectory = "/inbox/stage" },
		"invented receipt": func(d *ConnectionDefinition) { d.FTPS.ReceiverContract.Receipt = "fsync" },
	} {
		t.Run(name, func(t *testing.T) {
			d := ftpsConnectionContract()
			change(&d)
			if _, err := connectionDefinition(connectionContractRow(t, d)); err != store.ErrState {
				t.Fatal("unsafe connection definition accepted", err)
			}
		})
	}
}

func TestFTPSWorkflowCannotSmuggleReferencesOrUnqualifiedEncryption(t *testing.T) {
	d := Definition{Schema: 1, Name: "FTPS", Steps: []Step{{ID: "send", Kind: "ftps.deliver", Filename: "settlement.csv", Connection: Reference{ID: "00000000-0000-0000-0000-000000000001", Version: 1, Hash: strings.Repeat("a", 64)}}}}
	for _, change := range []func(*Step){func(s *Step) { s.Filename = "settlement." }, func(s *Step) { s.Kind = "ftps.execute_shell" }, func(s *Step) { s.Encryption = &store.EncryptionPolicy{} }} {
		v := d
		v.Steps = append([]Step(nil), d.Steps...)
		change(&v.Steps[0])
		if _, err := Normalize(v); err == nil {
			t.Fatal("unsupported FTPS step accepted")
		}
	}
	var request PreviewRequest
	if Decode([]byte(`{"definition":{"schema_version":1,"name":"FTPS","steps":[{"id":"send","kind":"ftps.deliver","password_reference":"/private/password"}]}}`), &request) == nil {
		t.Fatal("raw secret reference accepted in workflow")
	}
}
