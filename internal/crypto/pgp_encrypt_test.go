package crypto

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"slices"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
)

func TestPGPEncryptionProfilesBindExactRecipientBytesAndIntegrity(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		now := time.Now().UTC().Truncate(time.Second)
		config := &packet.Config{Algorithm: packet.PubKeyAlgoEd25519, V6Keys: v6, KeyLifetimeSecs: 86400, AEADConfig: &packet.AEADConfig{DefaultMode: packet.AEADModeOCB}, DefaultCipher: packet.CipherAES256, Time: func() time.Time { return now.Add(-time.Minute) }}
		entity, err := openpgp.NewEntity("synthetic recipient", "", "", config)
		if err != nil {
			t.Fatal(err)
		}
		var public bytes.Buffer
		if err = entity.Serialize(&public); err != nil {
			t.Fatal(err)
		}
		key, err := ParsePGPRecipient(context.Background(), public.Bytes(), hex.EncodeToString(entity.PrimaryKey.Fingerprint), now)
		if err != nil {
			t.Fatal(err)
		}
		if key.Purpose != "encrypt" || key.Recipient == nil || !slices.Contains(key.Recipient.Profiles, PGPEncryptAEAD) {
			t.Fatal(key)
		}
		source := bytes.Repeat([]byte("account,amount\r\n0000123,100.01\r\n"), 4096)
		for _, profile := range key.Recipient.Profiles {
			var ciphertext bytes.Buffer
			proof, err := EncryptPGP(context.Background(), *key, profile, bytes.NewReader(source), int64(len(source)), Digest(source), &ciphertext, now)
			if err != nil || proof.Profile != profile || proof.EncryptionFingerprint != key.Recipient.Fingerprint || int64(ciphertext.Len()) > PGPCiphertextLimit(int64(len(source))) {
				t.Fatal(proof, err)
			}
			message, err := openpgp.ReadMessage(bytes.NewReader(ciphertext.Bytes()), openpgp.EntityList{entity}, nil, pgpConfig(now))
			if err != nil {
				t.Fatal(err)
			}
			plain, err := io.ReadAll(message.UnverifiedBody)
			if err != nil || !bytes.Equal(plain, source) {
				t.Fatal("exact plaintext not recovered", err)
			}
			if message.LiteralData.FileName != "" || message.LiteralData.Time != 0 || !message.LiteralData.IsBinary {
				t.Fatal("sensitive metadata or text normalization in literal packet")
			}
			corrupt := bytes.Clone(ciphertext.Bytes())
			corrupt[len(corrupt)-1] ^= 1
			message, err = openpgp.ReadMessage(bytes.NewReader(corrupt), openpgp.EntityList{entity}, nil, pgpConfig(now))
			if err == nil {
				_, err = io.ReadAll(message.UnverifiedBody)
			}
			if err == nil {
				t.Fatal("unauthenticated ciphertext accepted")
			}
			var wrong bytes.Buffer
			if _, err = EncryptPGP(context.Background(), *key, profile, bytes.NewReader(source), int64(len(source)), Digest([]byte("wrong")), &wrong, now); err == nil {
				t.Fatal("source digest mismatch accepted")
			}
		}
		if v6 && slices.Contains(key.Recipient.Profiles, PGPEncryptMDC) {
			t.Fatal("legacy envelope offered for v6 key")
		}
		var out bytes.Buffer
		if _, err = EncryptPGP(context.Background(), *key, "automatic", bytes.NewReader(source), int64(len(source)), Digest(source), &out, now); err == nil || out.Len() != 0 {
			t.Fatal("implicit profile fallback")
		}
		if _, err = EncryptPGP(context.Background(), *key, PGPEncryptAEAD, bytes.NewReader(source), int64(len(source)), Digest(source), &out, now.Add(48*time.Hour)); err == nil {
			t.Fatal("expired recipient key accepted")
		}
	}
}
