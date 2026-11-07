//go:build integration

package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/namespaceprops"
	"github.com/ctlplne/freightctl/internal/store"
)

func qualifyNamespacePropertiesCLI(t *testing.T, ctx context.Context, service *custody.Service, scope store.Scope, manager, ordinaryWriter string, command func(string, string, ...string) ([]byte, error), requestFile func(any) string) {
	t.Helper()
	create := requestFile(store.PathCommand{Operation: "mkdir", Path: "/cli-properties"})
	raw, err := command(manager, "namespace", "-request-file", create, "-idempotency-key", "cli-property-dir")
	var directory store.PathResult
	if err != nil || json.Unmarshal(raw, &directory) != nil {
		t.Fatal("CLI property directory not created", err)
	}
	changes, err := namespaceprops.ParseUpdate(strings.NewReader(`<propertyupdate xmlns="DAV:" xmlns:x="urn:example"><set><prop><x:label xml:lang="fr">CLI inert data</x:label></prop></set></propertyupdate>`))
	if err != nil {
		t.Fatal(err)
	}
	selection := store.PathCommand{Operation: "properties", Path: directory.Entry.Path, ExpectedEntryID: directory.Entry.ID, ExpectedRevision: &directory.Entry.Revision, PropertyChanges: changes}
	input := requestFile(selection)
	if _, err = command(ordinaryWriter, "namespace", "-request-file", input, "-idempotency-key", "cli-property-no-management"); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("ordinary CLI write gained metadata management", err)
	}
	raw, err = command(manager, "namespace", "-request-file", input, "-idempotency-key", "cli-property-original")
	var result store.PathResult
	if err != nil || json.Unmarshal(raw, &result) != nil || result.Replayed || result.Entry.ID != directory.Entry.ID || result.Entry.Revision != directory.Entry.Revision+1 || result.Entry.Mode != directory.Entry.Mode || !result.Entry.Modified.Equal(directory.Entry.Modified) {
		t.Fatal("CLI properties lost exact atomic metadata transition", err)
	}
	properties, err := service.ReadNamespaceProperties(ctx, scope, selection.Path, false)
	if err != nil || len(properties) != 1 || properties[0].Properties["{urn:example}label"] != changes[0].Property {
		t.Fatal("independent CLI property readback differs", err)
	}
	for _, token := range []string{manager, ordinaryWriter} {
		raw, err = command(token, "namespace-properties", "-path", selection.Path)
		var snapshot custody.NamespacePropertySnapshot
		if err != nil || json.Unmarshal(raw, &snapshot) != nil || snapshot.Profile != "namespace-properties-v1" || snapshot.Observation != "authorized-snapshot-at-read" || snapshot.Entry != result.Entry || len(snapshot.Properties) != 1 || snapshot.Properties["{urn:example}label"] != changes[0].Property {
			t.Fatal("actual explicit CLI read lost authorized content,exact entry or observation", err)
		}
	}
	raw, err = command(manager, "namespace", "-request-file", input, "-idempotency-key", "cli-property-original")
	var replay store.PathResult
	if err != nil || json.Unmarshal(raw, &replay) != nil || !replay.Replayed || replay.Entry != result.Entry {
		t.Fatal("CLI property recovery repeated effects", err)
	}
	if _, err = command(manager, "namespace", "-request-file", input, "-idempotency-key", "cli-property-stale"); !errors.Is(err, store.ErrRevision) {
		t.Fatal("CLI stale namespace revision accepted", err)
	}
	selection.PropertyChanges[0].Property = `<label xmlns="urn:example">changed meaning</label>`
	if _, err = command(manager, "namespace", "-request-file", requestFile(selection), "-idempotency-key", "cli-property-original"); !errors.Is(err, store.ErrConflict) {
		t.Fatal("CLI changed XML reused original key", err)
	}
}
