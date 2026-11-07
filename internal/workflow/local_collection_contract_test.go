package workflow

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/delivery"
	"github.com/ctlplne/freightctl/internal/store"
)

func localConnectionContract(t *testing.T) (ConnectionDefinition, *store.Configuration) {
	t.Helper()
	d := ConnectionDefinition{Schema: 3, Directory: "/", Local: &delivery.LocalCollectionSource{Schema: 1, Reference: filepath.Join(t.TempDir(), "PRIVATE_LOCAL_REFERENCE.json"), SHA256: strings.Repeat("a", 64), RootFingerprint: strings.Repeat("b", 64)}}
	raw, hash, err := digest(d)
	if err != nil {
		t.Fatal(err)
	}
	return d, &store.Configuration{ID: secure.NewID(), Version: 1, Definition: raw, Hash: hash, State: "active", Revision: 1}
}

func TestLocalCollectionConnectionBindsReadOnlyRoleAndRedactsHostReferences(t *testing.T) {
	d, c := localConnectionContract(t)
	view, err := viewConnection(c)
	if err != nil || view.Protocol != "local" || view.Local == nil || !view.Local.ReadOnly || view.Local.Profile != delivery.LocalCollectionProfile || view.Local.RootReferenceHash != secure.Digest([]byte(d.Local.Reference)) || view.Local.ConfigurationHash != d.Local.SHA256 || view.Local.RootFingerprint != d.Local.RootFingerprint || view.FTPS != nil || view.Address != "" || view.User != "" {
		t.Fatal("read-only local public metadata differs", err)
	}
	wire, err := json.Marshal(view)
	if err != nil || bytes.Contains(wire, []byte("PRIVATE_LOCAL_REFERENCE")) || bytes.Contains(wire, []byte(d.Local.Reference)) || bytes.Contains(wire, []byte("root_reference\"")) {
		t.Fatal("local host reference escaped into review metadata", err)
	}
	source := collectionTestSource()
	source.Kind = "local.collect"
	source.Connection = Reference{ID: c.ID, Version: c.Version, Hash: c.Hash}
	if _, _, err := collectionSourceConnection(source, c); err != nil {
		t.Fatal("typed local source rejected", err)
	}
	if _, err := Normalize(Definition{Schema: 1, Name: "Local source only", Steps: []Step{}, Source: &source}); err != nil {
		t.Fatal("ordinary local-only workflow rejected", err)
	}
	for _, kind := range []string{"sftp.collect", "ftps.collect"} {
		changed := source
		changed.Kind = kind
		if _, _, err := collectionSourceConnection(changed, c); !errors.Is(err, store.ErrState) {
			t.Fatal("local connection reinterpreted as a network protocol", kind, err)
		}
	}
	for _, mutate := range []func(*ConnectionDefinition){
		func(d *ConnectionDefinition) { d.Schema = 1 },
		func(d *ConnectionDefinition) { d.Schema = 2 },
		func(d *ConnectionDefinition) { d.Directory = "/other" },
		func(d *ConnectionDefinition) { d.Destination.Address = "127.0.0.1:22" },
		func(d *ConnectionDefinition) { d.Local.RootFingerprint = "invalid" },
	} {
		var changed ConnectionDefinition
		if json.Unmarshal(c.Definition, &changed) != nil {
			t.Fatal("fixture")
		}
		mutate(&changed)
		raw, hash, _ := digest(changed)
		forged := *c
		forged.Definition = raw
		forged.Hash = hash
		if _, err := connectionDefinition(&forged); !errors.Is(err, store.ErrState) {
			t.Fatal("rehashed mixed source meaning accepted", err)
		}
	}
	source.Contract = ScheduledCollectionContract
	if err := normalizeCollectionSource(source); !errors.Is(err, ErrInput) {
		t.Fatal("unimplemented local calendar contract admitted", err)
	}
}

func TestLocalSourceIdentityBindsPhysicalRootAndPreservesLegacyWireMeaning(t *testing.T) {
	_, c := localConnectionContract(t)
	view, err := viewConnection(c)
	if err != nil {
		t.Fatal(err)
	}
	first := collectionSourceIdentity(view)
	view.Local.RootFingerprint = strings.Repeat("c", 64)
	if first == collectionSourceIdentity(view) {
		t.Fatal("different physical producer root reused prior input identity")
	}
	for _, protocol := range []string{"", "ftps"} {
		legacy := ConnectionView{ID: c.ID, Directory: "/incoming", Protocol: protocol}
		if got := collectionSourceIdentity(legacy); got != secure.Digest([]byte(c.ID+":/incoming")) {
			t.Fatal("existing source identity changed")
		}
	}
}

func TestLocalSourceConnectionCannotBeOpenedThroughNetworkPeerFactories(t *testing.T) {
	d, _ := localConnectionContract(t)
	for _, kind := range []string{"sftp.collect", "ftps.collect"} {
		calls := 0
		if p, err := openCollectionSourcePeer(t.Context(), &d, kind, func() error { calls++; return nil }); !errors.Is(err, ErrInput) || calls != 0 {
			if p != nil {
				p.Close()
			}
			t.Fatal("source-only local connection reached network setup", kind, err, calls)
		}
	}
}
