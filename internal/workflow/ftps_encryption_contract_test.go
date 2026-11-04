package workflow

import (
	"strings"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

// This contract opens no key, database, model or receiver. It requires a typed
// proposal to preserve the exact recipient, independently of transport TLS.
func TestRegisteredFTPSWorkflowBindsExactRecipientEncryption(t *testing.T) {
	for _, profile := range []string{secure.PGPEncryptMDC, secure.PGPEncryptAEAD} {
		t.Run(profile, func(t *testing.T) {
			policy := &store.EncryptionPolicy{Key: store.PGPReference{ID: "00000000-0000-0000-0000-000000000002", Version: 1, Hash: strings.Repeat("b", 64)}, Profile: profile}
			d := Definition{Schema: 1, Name: "Encrypted FTPS settlement", Steps: []Step{{ID: "send", Kind: "ftps.deliver", Connection: Reference{ID: "00000000-0000-0000-0000-000000000001", Version: 1, Hash: strings.Repeat("a", 64)}, Filename: "settlement.pgp", Encryption: policy}}}
			normalized, err := Normalize(d)
			if err != nil {
				t.Fatalf("recipient-encrypted FTPS is missing from the typed workflow: %v", err)
			}
			if normalized.Steps[0].Encryption == policy || *normalized.Steps[0].Encryption != *policy {
				t.Fatal("recipient policy was aliased or changed")
			}
			_, original, err := digest(normalized)
			if err != nil {
				t.Fatal(err)
			}
			for _, mutate := range []func(*store.EncryptionPolicy){
				func(p *store.EncryptionPolicy) { p.Key.Version++ },
				func(p *store.EncryptionPolicy) { p.Key.Hash = strings.Repeat("c", 64) },
				func(p *store.EncryptionPolicy) { p.Profile = "invalid" },
			} {
				changed, err := Normalize(d)
				if err != nil {
					t.Fatal(err)
				}
				mutate(changed.Steps[0].Encryption)
				_, next, err := digest(changed)
				if err != nil || next == original {
					t.Fatal("changed recipient meaning kept its hash", err)
				}
				if changed.Steps[0].Encryption.Profile == "invalid" {
					if _, err := Normalize(changed); err == nil {
						t.Fatal("unknown encryption profile admitted")
					}
				}
			}
		})
	}
}
