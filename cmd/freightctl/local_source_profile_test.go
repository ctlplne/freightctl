package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/delivery"
	"github.com/ctlplne/freightctl/internal/protectedfs"
)

func TestLocalSourceProfilePublishesExactProtectedConfigurationWithoutHostPathDisclosure(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "PRIVATE_PRODUCER_ROOT")
	outputDirectory := filepath.Join(t.TempDir(), "configuration")
	for _, p := range []string{directory, outputDirectory} {
		if err := protectedfs.EnsureDirectory(p); err != nil {
			t.Fatal(err)
		}
	}
	output := filepath.Join(outputDirectory, "source.json")
	checks := 0
	receipt, err := writeLocalSourceProfile(t.Context(), directory, output, func() error { checks++; return nil })
	if err != nil {
		t.Fatal("actual operator profile unavailable", err)
	}
	secret, err := secure.ReadSecret(output, 32<<10)
	if err != nil {
		t.Fatal("new configuration was not protected", err)
	}
	defer secret.Close()
	if receipt.ConfigurationHash != secure.Digest(secret.Bytes) || receipt.ReferenceHash != secure.Digest([]byte(output)) || checks < 3 || !receipt.ReadOnly {
		t.Fatal("configuration bytes or authority checks differ")
	}
	definition := &delivery.LocalCollectionSource{Schema: 1, Reference: output, SHA256: receipt.ConfigurationHash, RootFingerprint: receipt.RootFingerprint}
	peer, err := delivery.OpenConfiguredLocalCollectionPeer(t.Context(), definition, func() error { return nil })
	if err != nil {
		t.Fatal("published profile cannot open exact read-only root", err)
	}
	peer.Close()
	wire, err := json.Marshal(receipt)
	if err != nil || bytes.Contains(wire, []byte(directory)) || bytes.Contains(wire, []byte(output)) || bytes.Contains(wire, []byte("PRIVATE_PRODUCER_ROOT")) {
		t.Fatal("host reference entered stdout metadata", err)
	}
	if entries, err := os.ReadDir(directory); err != nil || len(entries) != 0 {
		t.Fatal("profile preparation mutated the producer", err)
	}
	if entries, err := os.ReadDir(outputDirectory); err != nil || len(entries) != 1 {
		t.Fatal("profile left unpublished private staging", err)
	}
	if _, err = writeLocalSourceProfile(t.Context(), directory, output, func() error { return nil }); err == nil {
		t.Fatal("profile creator overwrote an existing configuration")
	}
	current, err := os.ReadFile(output)
	if err != nil || !bytes.Equal(current, secret.Bytes) {
		t.Fatal("existing profile changed on retry", err)
	}
}

func TestLocalSourceProfileRevocationCannotPublishStagedConfiguration(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "producer")
	outputDirectory := filepath.Join(t.TempDir(), "configuration")
	for _, p := range []string{directory, outputDirectory} {
		if err := protectedfs.EnsureDirectory(p); err != nil {
			t.Fatal(err)
		}
	}
	output := filepath.Join(outputDirectory, "source.json")
	denied := errors.New("synthetic current authority refused")
	calls := 0
	if _, err := writeLocalSourceProfile(t.Context(), directory, output, func() error {
		calls++
		if calls >= 3 {
			return denied
		}
		return nil
	}); !errors.Is(err, denied) {
		t.Fatal("revoked profile preparation was published", err)
	}
	if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("revoked profile acquired a public name", err)
	}
	if entries, err := os.ReadDir(outputDirectory); err != nil || len(entries) != 0 {
		t.Fatal("refused profile leaked staging", err)
	}
}

func TestLocalSourceProfileRefusesProducerOutputAndSubstitutedPhysicalRoot(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "producer")
	child := filepath.Join(directory, "nested")
	outputDirectory := filepath.Join(t.TempDir(), "configuration")
	for _, p := range []string{directory, child, outputDirectory} {
		if err := protectedfs.EnsureDirectory(p); err != nil {
			t.Fatal(err)
		}
	}
	for _, output := range []string{filepath.Join(directory, "source.json"), filepath.Join(child, "source.json"), "relative-source.json"} {
		if _, err := writeLocalSourceProfile(t.Context(), directory, output, func() error { return nil }); !errors.Is(err, delivery.ErrLocalSource) {
			t.Fatal("profile preparation wrote in producer or accepted relative output", err)
		}
	}
	output := filepath.Join(outputDirectory, "source.json")
	calls := 0
	_, err := writeLocalSourceProfile(t.Context(), directory, output, func() error {
		calls++
		if calls == 3 {
			if err := os.Rename(directory, directory+"-retained"); err != nil {
				t.Fatal(err)
			}
			if err := protectedfs.EnsureDirectory(directory); err != nil {
				t.Fatal(err)
			}
		}
		return nil
	})
	if !errors.Is(err, delivery.ErrLocalSource) {
		t.Fatal("substituted physical root acquired a profile", err)
	}
	if entries, err := os.ReadDir(outputDirectory); err != nil || len(entries) != 0 {
		t.Fatal("changed root left a published or staged configuration", err)
	}
}
