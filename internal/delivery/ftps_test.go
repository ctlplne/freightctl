package delivery

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

func contractDefinition() Definition {
	refs := filepath.Join(os.TempDir(), "freightctl-contract-fixture")
	return Definition{Schema: 2, Source: store.File{ID: "00000000-0000-0000-0000-000000000001", Size: 3, SHA256: secure.Digest([]byte("abc"))}, Directory: "/inbox", Filename: "payroll.csv", FTPS: &FTPSDefinition{Destination: secure.FTPSDestination{Address: "127.0.0.1:990", ServerName: "localhost", Mode: "implicit", User: "receiver", CAFile: filepath.Join(refs, "receiver-ca.pem"), CASHA256: strings.Repeat("a", 64), PasswordFile: filepath.Join(refs, "receiver-password"), PasswordSHA256: strings.Repeat("b", 64)}, StagingDirectory: "/private-stage", ReceiverContract: store.FTPSReceiverContract{Schema: 1, DocumentSHA256: strings.Repeat("c", 64), StagingVisibility: "receiver-private", Rename: "may-replace", Duplicates: "receiver-deduplicates-delivery-id", Receipt: "exact-readback"}}}
}

func TestFTPSDefinitionFreezesDistinctReceiverContractAndRefusesMixedAuthority(t *testing.T) {
	good := contractDefinition()
	if !validProtocolDefinition(&good) {
		t.Fatal("valid contract refused")
	}
	_, originalHash, _ := dispatchDigest(good)
	for name, change := range map[string]func(*Definition){
		"legacy schema":               func(d *Definition) { d.Schema = 1 },
		"mixed SSH":                   func(d *Definition) { d.Destination.Address = "127.0.0.1:22" },
		"frozen filename escape":      func(d *Definition) { d.Filename = "../../outside.csv" },
		"unusable trailing dot":       func(d *Definition) { d.Filename = "payroll." },
		"unqualified encryption":      func(d *Definition) { d.Encryption = &store.EncryptionPolicy{} },
		"unqualified workflow":        func(d *Definition) { d.Binding = &store.ExecutionBinding{} },
		"visible staging":             func(d *Definition) { d.FTPS.StagingDirectory = "/inbox/stage" },
		"stage ancestor":              func(d *Definition) { d.FTPS.StagingDirectory = "/" },
		"noncanonical stage":          func(d *Definition) { d.FTPS.StagingDirectory = "/stage/../private" },
		"fsync promise":               func(d *Definition) { d.FTPS.ReceiverContract.Receipt = "fsync" },
		"exclusive rename promise":    func(d *Definition) { d.FTPS.ReceiverContract.Rename = "no-replace" },
		"no duplicate contract":       func(d *Definition) { d.FTPS.ReceiverContract.Duplicates = "none" },
		"no contract identity":        func(d *Definition) { d.FTPS.ReceiverContract.DocumentSHA256 = "" },
		"external destination":        func(d *Definition) { d.FTPS.Destination.Address = "192.0.2.1:990" },
		"plaintext mode":              func(d *Definition) { d.FTPS.Destination.Mode = "ftp" },
		"missing credential identity": func(d *Definition) { d.FTPS.Destination.PasswordSHA256 = "" },
	} {
		t.Run(name, func(t *testing.T) {
			d := contractDefinition()
			change(&d)
			if validProtocolDefinition(&d) {
				t.Fatal("unsafe or unsupported contract admitted")
			}
			_, hash, _ := dispatchDigest(d)
			if hash == originalHash {
				t.Fatal("changed contract retained approval hash")
			}
		})
	}
	for _, change := range []func(*Definition){
		func(d *Definition) { d.FTPS.Destination.PasswordFile += "-rotated" },
		func(d *Definition) { d.FTPS.Destination.PasswordSHA256 = strings.Repeat("d", 64) },
		func(d *Definition) { d.FTPS.Destination.CASHA256 = strings.Repeat("d", 64) },
		func(d *Definition) { d.FTPS.Destination.Mode = "explicit" },
		func(d *Definition) { d.FTPS.ReceiverContract.DocumentSHA256 = strings.Repeat("d", 64) },
	} {
		d := contractDefinition()
		change(&d)
		_, hash, _ := dispatchDigest(d)
		if !validProtocolDefinition(&d) || hash == originalHash {
			t.Fatal("valid changed meaning did not require new approval")
		}
	}
}

func TestFTPSEffectRedactsLocalReferencesAndPasswordDigest(t *testing.T) {
	spec := contractDefinition()
	d := &store.Delivery{ID: "00000000-0000-0000-0000-000000000002"}
	effect := ftpsEffect(d, &spec)
	b, _ := json.Marshal(effect)
	for _, value := range []string{spec.FTPS.Destination.CAFile, spec.FTPS.Destination.PasswordFile, spec.FTPS.Destination.PasswordSHA256, "password_sha256"} {
		if strings.Contains(string(b), value) {
			t.Fatal("private reference or dictionary-attack digest disclosed")
		}
	}
	if effect.Protocol != "ftps" || effect.KeyReferenceHash != "" || effect.FTPS.StagingPath != "/private-stage/.freightctl-"+d.ID+".partial" || effect.FTPS.PasswordReferenceHash == "" {
		t.Fatal("wrong typed effect")
	}
	for _, reconciled := range []bool{false, true} {
		var receipt map[string]any
		if json.Unmarshal(ftpsReceipt(d, &spec, reconciled), &receipt) != nil || receipt["file_fsync_acknowledged"] != false || receipt["business_acceptance"] != "unknown" || receipt["rename_acknowledged"] != !reconciled {
			t.Fatal("receipt invents receiver guarantee", receipt)
		}
	}
}

func TestFTPSRequestNeverCombinesSSHAndPasswordReferences(t *testing.T) {
	d := contractDefinition()
	r := Request{Directory: d.Directory, Filename: d.Filename, FTPS: d.FTPS}
	if _, ftps, err := requestDestination(r); err != nil || ftps == nil {
		t.Fatal(err)
	}
	r.Filename = "payroll."
	if _, _, err := requestDestination(r); err != ErrInput {
		t.Fatal("unusable final path admitted before draft", err)
	}
	r.Filename = d.Filename
	r.KeyFile = "/private/client-key"
	if _, _, err := requestDestination(r); err != ErrInput {
		t.Fatal("mixed request admitted", err)
	}
}
