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

func TestDAVDeliveryRequestRequiresDistinctExactReceiverContract(t *testing.T) {
	private := t.TempDir()
	raw, err := json.Marshal(map[string]any{
		"directory": "/inbox", "filename": "input.dat",
		"dav": map[string]any{
			"destination":       secure.HTTPSReadDestination{Address: "127.0.0.1:9443", ServerName: "localhost", CAFile: filepath.Join(private, "ca"), CASHA256: strings.Repeat("a", 64), TokenFile: filepath.Join(private, "token"), TokenSHA256: strings.Repeat("b", 64)},
			"staging_directory": "/private-stage",
			"receiver_contract": map[string]any{"schema_version": 1, "document_sha256": strings.Repeat("c", 64), "staging_visibility": "receiver-private", "put": "exclusive-create", "move": "source-etag-no-overwrite", "duplicates": "receiver-deduplicates-delivery-id", "receipt": "exact-readback"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var request Request
	if json.Unmarshal(raw, &request) != nil {
		t.Fatal("DAV request shape unavailable")
	}
	if _, _, err = requestDestination(request); err != nil {
		t.Fatal("ordinary direct delivery cannot admit the distinct approved DAV receiver contract")
	}
}

func davContractDefinition(t *testing.T) Definition {
	t.Helper()
	private := t.TempDir()
	return Definition{Schema: 3, Directory: "/inbox", Filename: "input.dat", DAV: &DAVDefinition{Destination: secure.HTTPSReadDestination{Address: "127.0.0.1:9443", ServerName: "localhost", CAFile: filepath.Join(private, "ca"), CASHA256: strings.Repeat("a", 64), TokenFile: filepath.Join(private, "token"), TokenSHA256: strings.Repeat("b", 64)}, StagingDirectory: "/private-stage", ReceiverContract: store.DAVReceiverContract{Schema: 1, DocumentSHA256: strings.Repeat("c", 64), StagingVisibility: "receiver-private", Put: "exclusive-create", Move: "source-etag-no-overwrite", Duplicates: "receiver-deduplicates-delivery-id", Receipt: "exact-readback"}}}
}

func TestDAVDeliveryRefusesMixedAuthorityAndBindsEveryReviewedMeaning(t *testing.T) {
	for name, change := range map[string]func(*Definition){
		"legacy schema":                        func(d *Definition) { d.Schema = 1 },
		"FTP schema":                           func(d *Definition) { d.Schema = 2 },
		"SSH identity":                         func(d *Definition) { d.Destination.Address = "127.0.0.1:22" },
		"FTP identity":                         func(d *Definition) { d.FTPS = &FTPSDefinition{} },
		"source-only mixed credential":         func(d *Definition) { d.DAV.Destination.Authentication = "basic" },
		"encryption without qualified binding": func(d *Definition) { d.Encryption = &store.EncryptionPolicy{} },
		"workflow without qualified binding":   func(d *Definition) { d.Binding = &store.ExecutionBinding{} },
		"retained wire artifact":               func(d *Definition) { d.Transfer = &store.DeliveryCiphertext{} },
		"stage contains final":                 func(d *Definition) { d.DAV.StagingDirectory = "/" },
		"visible stage":                        func(d *Definition) { d.DAV.StagingDirectory = "/inbox/stage" },
		"stage aliases":                        func(d *Definition) { d.DAV.StagingDirectory = "/stage/../private" },
		"stage control path":                   func(d *Definition) { d.DAV.StagingDirectory = "/.freightctl" },
		"replace final":                        func(d *Definition) { d.DAV.ReceiverContract.Move = "may-replace" },
		"replace stage":                        func(d *Definition) { d.DAV.ReceiverContract.Put = "replace" },
		"invent fsync":                         func(d *Definition) { d.DAV.ReceiverContract.Receipt = "fsync" },
		"no deduplication promise":             func(d *Definition) { d.DAV.ReceiverContract.Duplicates = "none" },
		"no document identity":                 func(d *Definition) { d.DAV.ReceiverContract.DocumentSHA256 = "" },
		"unsafe filename":                      func(d *Definition) { d.Filename = "input." },
	} {
		t.Run(name, func(t *testing.T) {
			d := davContractDefinition(t)
			if !validProtocolDefinition(&d) {
				t.Fatal("exact new DAV definition refused")
			}
			change(&d)
			if validProtocolDefinition(&d) {
				t.Fatal("unqualified or mixed protocol meaning admitted")
			}
		})
	}
	for _, change := range []func(*Definition){
		func(d *Definition) { d.DAV.Destination.TokenFile += "-rotated" },
		func(d *Definition) { d.DAV.Destination.TokenSHA256 = strings.Repeat("d", 64) },
		func(d *Definition) { d.DAV.Destination.CASHA256 = strings.Repeat("d", 64) },
		func(d *Definition) { d.DAV.StagingDirectory = "/new-stage" },
		func(d *Definition) { d.DAV.ReceiverContract.DocumentSHA256 = strings.Repeat("d", 64) },
	} {
		d := davContractDefinition(t)
		_, before, _ := dispatchDigest(d)
		change(&d)
		_, after, _ := dispatchDigest(d)
		if !validProtocolDefinition(&d) || before == after {
			t.Fatal("changed valid receiver meaning reused approval hash")
		}
	}
}

func TestDAVDeliveryReviewAndObservationDoNotDiscloseReferencesOrInventAcceptance(t *testing.T) {
	for _, basic := range []bool{false, true} {
		spec := davContractDefinition(t)
		if basic {
			d := &spec.DAV.Destination
			d.Authentication, d.User, d.PasswordFile, d.PasswordSHA256 = "basic", "writer", d.TokenFile, d.TokenSHA256
			d.TokenFile, d.TokenSHA256 = "", ""
		}
		delivery := &store.Delivery{ID: "00000000-0000-4000-8000-000000000001"}
		effect := davEffect(delivery, &spec)
		raw, _ := json.Marshal(effect)
		dest := spec.DAV.Destination
		for _, private := range []string{dest.CAFile, dest.TokenFile, dest.PasswordFile, dest.TokenSHA256, dest.PasswordSHA256} {
			if private != "" && strings.Contains(string(raw), private) {
				t.Fatal("review disclosed credential digest or reference value")
			}
		}
		if effect.Protocol != "webdav" || effect.DAV == nil || effect.DAV.StagingPath != "/private-stage/.freightctl-"+delivery.ID+".partial" || effect.FTPS != nil || effect.Workflow != nil || effect.Encryption != nil {
			t.Fatal("review gained unrelated authority")
		}
		for _, reconciled := range []bool{false, true} {
			var value map[string]any
			if json.Unmarshal(davReceipt(delivery, &spec, reconciled), &value) != nil || value["file_fsync_acknowledged"] != false || value["business_acceptance"] != "unknown" || value["move_acknowledged"] != !reconciled || value["upload_completion_acknowledged"] != !reconciled || value["source_etag_conditioned"] != !reconciled || value["overwrite"] != "F" || value["directory_power_loss_durability"] != "not established" {
				t.Fatal("DAV observation invented an acknowledgement or business guarantee")
			}
		}
	}
}

func TestDAVDeliveryGoBrowserCanonicalPublicMetadata(t *testing.T) {
	raw, err := os.ReadFile("../../web/tests/fixtures/dav-dispatch.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures map[string]struct {
		Definition      store.OutboundDispatchDefinition `json:"definition"`
		Hash            string                           `json:"definition_hash"`
		PublicReference string                           `json:"public_reference_input"`
	}
	if json.Unmarshal(raw, &fixtures) != nil || len(fixtures) != 2 {
		t.Fatal("both public credential profiles required")
	}
	for mode, f := range fixtures {
		if f.Definition.Schema != 3 || f.Definition.Effect.Protocol != "webdav" || f.Definition.Effect.DAV == nil || f.Definition.Effect.DAV.Authentication != mode {
			t.Fatal("canonical public fixture lost protocol identity")
		}
		if mode == "basic" {
			if f.PublicReference != "/synthetic/dav-password-reference" || f.Definition.Effect.DAV.PasswordReferenceHash != "" {
				t.Fatal("public fixture reference input differs")
			}
			f.Definition.Effect.DAV.PasswordReferenceHash = secure.Digest([]byte(f.PublicReference))
		}
		_, hash, err := dispatchDigest(f.Definition)
		if err != nil || hash != f.Hash {
			t.Fatal("Go/browser canonical DAV review meaning differs")
		}
	}
}
