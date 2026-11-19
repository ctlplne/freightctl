//go:build cmspeer

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/ctlplne/freightctl/internal/as2"
	secure "github.com/ctlplne/freightctl/internal/crypto"
)

func TestNativeAS2EncryptedMessage(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	ssl := func(args ...string) {
		t.Helper()
		command := exec.CommandContext(ctx, "openssl", args...)
		command.Dir = dir
		if err := command.Run(); err != nil {
			t.Fatalf("independent OpenSSL %s failed: %v", args[0], err)
		}
	}
	read := func(name string) []byte {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	write := func(name string, data []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	certificate := func(name, usage string) {
		t.Helper()
		ssl("req", "-new", "-newkey", "rsa:3072", "-noenc", "-x509", "-sha256", "-days", "1",
			"-subj", "/CN=freightctl-AS2-"+name, "-addext", "basicConstraints=critical,CA:FALSE",
			"-addext", "keyUsage=critical,"+usage, "-addext", "extendedKeyUsage=emailProtection",
			"-keyout", name+".key", "-out", name+".pem")
		ssl("x509", "-in", name+".pem", "-outform", "DER", "-out", name+".der")
		ssl("pkcs8", "-topk8", "-nocrypt", "-in", name+".key", "-outform", "DER", "-out", name+".pkcs8")
	}
	certificate("sender", "digitalSignature")
	certificate("recipient", "keyEncipherment")
	certificate("other", "digitalSignature")
	entity := []byte("Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: binary\r\n\r\nAS2 fixture\x00\xff\r\n")
	write("source.mime", entity)
	ssl("cms", "-sign", "-binary", "-crlfeol", "-in", "source.mime", "-signer", "sender.pem",
		"-inkey", "sender.key", "-md", "sha256", "-outform", "SMIME", "-out", "signed.mime")
	encrypt := func(source, destination, scheme, maskHash string) {
		t.Helper()
		ssl("cms", "-encrypt", "-binary", "-in", source, "-outform", "DER", "-out", destination, scheme,
			"-recip", "recipient.pem", "-keyopt", "rsa_padding_mode:oaep",
			"-keyopt", "rsa_oaep_md:sha256", "-keyopt", "rsa_mgf1_md:"+maskHash)
	}
	encrypt("signed.mime", "envelope.der", "-aes-256-gcm", "sha256")
	ssl("cms", "-decrypt", "-binary", "-inform", "DER", "-in", "envelope.der", "-recip", "recipient.pem",
		"-inkey", "recipient.key", "-out", "peer-opened.mime")
	if !bytes.Equal(read("peer-opened.mime"), read("signed.mime")) {
		t.Fatal("independent encrypted fixture did not retain the signed MIME entity")
	}
	request := as2.OpenMessageRequest{Schema: 1,
		RecipientPin: secure.Digest(read("recipient.der")), SignerPin: secure.Digest(read("sender.der"))}
	saveRequest := func(value as2.OpenMessageRequest) {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		write("request.json", data)
	}
	saveRequest(request)
	args := func(message, signer, key, output string) []string {
		return []string{
			"--request-file", filepath.Join(dir, "request.json"), "--message-file", filepath.Join(dir, message),
			"--recipient-certificate-file", filepath.Join(dir, "recipient.der"), "--recipient-key-file", filepath.Join(dir, key),
			"--signer-certificate-file", filepath.Join(dir, signer), "--output", filepath.Join(dir, output),
		}
	}
	native := append([]string{"-test.run=^TestAS2CommandProcess$", "--", "as2-message-open"},
		args("envelope.der", "sender.der", "recipient.pkcs8", "published.mime")...)
	result, err := exec.CommandContext(ctx, os.Args[0], native...).Output()
	var observed as2.OpenedMessage
	if err != nil || json.Unmarshal(result, &observed) != nil || observed.Profile != as2.EncryptedMessageProfile ||
		observed.EnvelopeSHA != secure.Digest(read("envelope.der")) || observed.EntitySHA != secure.Digest(entity) ||
		observed.EntitySize != int64(len(entity)) || observed.RecipientPin != request.RecipientPin || observed.SignerPin != request.SignerPin {
		t.Fatalf("native CLI did not bind the encrypted message to both certificate pins and the exact signed MIME entity: %v", err)
	}
	published := filepath.Join(dir, "published.mime")
	info, err := os.Stat(published)
	if err != nil || info.Mode().Perm() != 0400 || !bytes.Equal(read("published.mime"), entity) || bytes.Contains(result, []byte("AS2 fixture")) {
		t.Fatal("verified output was not an exact owner-read-only MIME entity")
	}
	refused := func(message, signer, key string) {
		t.Helper()
		out := new(bytes.Buffer)
		if err := openAS2Message(ctx, args(message, signer, key, "refused.mime"), out); err == nil || out.Len() != 0 {
			t.Fatal("refused encryption or signature produced success output")
		}
		if _, err := os.Lstat(filepath.Join(dir, "refused.mime")); !os.IsNotExist(err) {
			t.Fatal("refused ciphertext or signature published a file")
		}
	}
	tampered := read("envelope.der")
	tampered[len(tampered)-1] ^= 1
	write("changed-tag.der", tampered)
	refused("changed-tag.der", "sender.der", "recipient.pkcs8")
	write("trailing.der", append(read("envelope.der"), 0))
	refused("trailing.der", "sender.der", "recipient.pkcs8")
	refused("envelope.der", "sender.der", "other.pkcs8")
	changed := request
	changed.SignerPin = secure.Digest(read("other.der"))
	saveRequest(changed)
	refused("envelope.der", "other.der", "recipient.pkcs8")
	saveRequest(request)
	damaged := bytes.Replace(read("signed.mime"), []byte("AS2 fixture"), []byte("AS2 changed"), 1)
	write("changed-signed.mime", damaged)
	encrypt("changed-signed.mime", "valid-envelope-bad-signature.der", "-aes-256-gcm", "sha256")
	refused("valid-envelope-bad-signature.der", "sender.der", "recipient.pkcs8")
	for _, alternate := range []struct{ scheme, maskHash string }{
		{"-aes-128-gcm", "sha256"}, {"-aes-256-cbc", "sha256"}, {"-aes-256-gcm", "sha1"},
	} {
		encrypt("signed.mime", "unsupported.der", alternate.scheme, alternate.maskHash)
		refused("unsupported.der", "sender.der", "recipient.pkcs8")
	}
	out := new(bytes.Buffer)
	if err := openAS2Message(ctx, args("envelope.der", "sender.der", "recipient.pkcs8", "published.mime"), out); err == nil ||
		out.Len() != 0 || !bytes.Equal(read("published.mime"), entity) {
		t.Fatal("opening a second time overwrote or misreported the protected output")
	}
	t.Log("independent OpenSSL envelope opened as the exact signed MIME entity, with no output for an invalid seal or signer")
}
