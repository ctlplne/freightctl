package delivery

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
)

func localConfiguredFixture(t *testing.T) (*LocalCollectionSource, []byte) {
	t.Helper()
	directory, identity := localSourceFixture(t)
	profile, err := json.Marshal(map[string]any{"schema_version": 1, "profile": LocalCollectionProfile, "directory": directory, "root_fingerprint": identity})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(filepath.Dir(directory), "source.json")
	localSourceWrite(t, path, profile)
	body := []byte("configured source exact private bytes\n")
	localSourceWrite(t, filepath.Join(directory, "data.csv"), body)
	return &LocalCollectionSource{Schema: 1, Reference: path, SHA256: secure.Digest(profile), RootFingerprint: identity}, body
}

func TestLocalCollectionProfileRefusesRehashedAmbiguousOrInventedMeaning(t *testing.T) {
	definition, _ := localConfiguredFixture(t)
	valid := []byte(`{"schema_version":1,"profile":"` + LocalCollectionProfile + `","directory":`)
	directory := filepath.Join(filepath.Dir(definition.Reference), "producer")
	encoded, _ := json.Marshal(directory)
	valid = append(valid, encoded...)
	valid = append(valid, []byte(`,"root_fingerprint":"`+definition.RootFingerprint+`"}`)...)
	if got, err := localCollectionDirectory(valid, definition.RootFingerprint); err != nil || got != directory {
		t.Fatal("exact private profile refused", err)
	}
	for _, wire := range [][]byte{
		bytes.Replace(valid, []byte(`"schema_version":1`), []byte(`"schema_version":1,"schema_version":1`), 1),
		bytes.Replace(valid, []byte(`"schema_version":1`), []byte(`"schema_version":1.0`), 1),
		bytes.Replace(valid, []byte(`"schema_version":1`), []byte(`"schema_version":true`), 1),
		bytes.Replace(valid, []byte(`"schema_version"`), []byte(`"SCHEMA_VERSION"`), 1),
		bytes.Replace(valid, []byte(`"profile":"`+LocalCollectionProfile+`"`), []byte(`"profile":{}`), 1),
		bytes.Replace(valid, []byte(LocalCollectionProfile), []byte("unapproved-filesystem-source"), 1),
		bytes.Replace(valid, encoded, []byte(`"../unapproved"`), 1),
		bytes.Replace(valid, encoded, []byte(`"/unapproved\u0000path"`), 1),
		append(append([]byte{}, valid...), []byte(`{}`)...),
		append([]byte(`{"forward":true,`), valid[1:]...),
		append([]byte{0xff}, valid...),
		bytes.Repeat([]byte("x"), (32<<10)+1),
	} {
		// Rehashing proves that byte integrity cannot grant an unknown meaning.
		path := filepath.Join(filepath.Dir(definition.Reference), secure.NewID()+".json")
		localSourceWrite(t, path, wire)
		changed := *definition
		changed.Reference = path
		changed.SHA256 = secure.Digest(wire)
		if p, err := OpenConfiguredLocalCollectionPeer(t.Context(), &changed, func() error { return nil }); !errors.Is(err, ErrLocalSource) {
			if p != nil {
				p.Close()
			}
			t.Fatal("rehashed untrusted source configuration acquired a reader", err)
		}
	}
	for _, mutate := range []func(*LocalCollectionSource){
		func(d *LocalCollectionSource) { d.Reference = "relative.json" },
		func(d *LocalCollectionSource) { d.Reference += "\x00" },
		func(d *LocalCollectionSource) { d.SHA256 = strings.Repeat("A", 64) },
		func(d *LocalCollectionSource) { d.RootFingerprint = "" },
	} {
		changed := *definition
		mutate(&changed)
		if changed.Valid() {
			t.Fatal("unsafe private profile reference admitted")
		}
	}
}

func TestConfiguredLocalCollectionRequiresExactPrivateProfileAndRoot(t *testing.T) {
	definition, body := localConfiguredFixture(t)
	if !definition.Valid() {
		t.Fatal("actual private source profile shape rejected")
	}
	p, err := OpenConfiguredLocalCollectionPeer(t.Context(), definition, func() error { return nil })
	if err != nil {
		t.Fatal("reviewed exact private source profile unavailable", err)
	}
	defer p.Close()
	var held bytes.Buffer
	if err = p.CopyVerified(t.Context(), "data.csv", int64(len(body)), secure.Digest(body), &held, func() error { return nil }); err != nil || !bytes.Equal(held.Bytes(), body) {
		t.Fatal("configured source bytes differ", err)
	}
	for _, mutate := range []func(*LocalCollectionSource){
		func(d *LocalCollectionSource) { d.Schema++ },
		func(d *LocalCollectionSource) { d.SHA256 = secure.Digest([]byte("changed profile bytes")) },
		func(d *LocalCollectionSource) { d.RootFingerprint = secure.Digest([]byte("other physical root")) },
		func(d *LocalCollectionSource) { d.Reference = filepath.Join(filepath.Dir(d.Reference), "absent.json") },
	} {
		changed := *definition
		mutate(&changed)
		if mistaken, err := OpenConfiguredLocalCollectionPeer(t.Context(), &changed, func() error { return nil }); err == nil {
			mistaken.Close()
			t.Fatal("changed profile or root adopted original approval")
		}
	}
	denied := errors.New("synthetic current local source authority refused")
	if mistaken, err := OpenConfiguredLocalCollectionPeer(t.Context(), definition, func() error { return denied }); !errors.Is(err, denied) {
		if mistaken != nil {
			mistaken.Close()
		}
		t.Fatal("configured source bypassed current authority", err)
	}
}
