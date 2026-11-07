//go:build integration

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/namespaceprops"
	"github.com/ctlplne/freightctl/internal/store"
)

func qualifyNamespaceTreeOverwriteCLI(t *testing.T, ctx context.Context, service *custody.Service, adminScope, managerScope store.Scope, manager, ordinaryWriter string, command func(string, string, ...string) ([]byte, error), requestFile func(any) string) {
	t.Helper()
	apply := func(key string, c store.PathCommand) *store.PathResult {
		t.Helper()
		raw, err := command(manager, "namespace", "-request-file", requestFile(c), "-idempotency-key", key)
		var result store.PathResult
		if err != nil || json.Unmarshal(raw, &result) != nil {
			t.Fatal("CLI overwrite fixture failed", err)
		}
		return &result
	}
	source := apply("cli-overwrite-source", store.PathCommand{Operation: "mkdir", Path: "/cli-overwrite-source"})
	apply("cli-overwrite-nested", store.PathCommand{Operation: "mkdir", Path: "/cli-overwrite-source/nested"})
	data := []byte("CLI overwrite keeps source custody and every explicit identity\n")
	file, _, err := service.AcceptAt(ctx, adminScope, "cli-overwrite-source-file", int64(len(data)), secure.Digest(data), bytes.NewReader(data), custody.UploadTarget{Path: "/cli-overwrite-source/nested/data.dat"})
	if err != nil {
		t.Fatal(err)
	}
	property := namespaceprops.Change{Operation: "set", Property: `<label xmlns="urn:example">inert CLI overwrite property</label>`}
	source = apply("cli-overwrite-property", store.PathCommand{Operation: "properties", Path: source.Entry.Path, ExpectedEntryID: source.Entry.ID, ExpectedRevision: &source.Entry.Revision, PropertyChanges: []namespaceprops.Change{property}})
	for _, operation := range []string{"copy_tree", "copy_dir", "move_tree"} {
		target := apply("cli-overwrite-target-"+operation, store.PathCommand{Operation: "mkdir", Path: "/cli-overwrite-" + operation})
		oldData := []byte("old CLI destination remains in retained custody\n")
		mode := uint32(0660)
		oldFile, _, err := service.AcceptAt(ctx, adminScope, "cli-overwrite-old-"+operation, int64(len(oldData)), secure.Digest(oldData), bytes.NewReader(oldData), custody.UploadTarget{Path: target.Entry.Path + "/old.dat", Mode: &mode})
		if err != nil {
			t.Fatal(err)
		}
		selection := store.PathCommand{Operation: operation, Path: source.Entry.Path, Target: target.Entry.Path, ExpectedEntryID: source.Entry.ID, ExpectedRevision: &source.Entry.Revision, Replace: true, TargetEntryID: target.Entry.ID, TargetRevision: &target.Entry.Revision}
		input := requestFile(selection)
		if _, err = command(ordinaryWriter, "namespace", "-request-file", input, "-idempotency-key", "cli-overwrite-denied-"+operation); !errors.Is(err, store.ErrForbidden) {
			t.Fatal("ordinary writer gained collection replacement management", err)
		}
		key := "cli-overwrite-original-" + operation
		raw, err := command(manager, "namespace", "-request-file", input, "-idempotency-key", key)
		var result store.PathResult
		changed := 5
		if operation == "copy_dir" {
			changed = 3
		}
		if err != nil || json.Unmarshal(raw, &result) != nil || result.Replayed || result.Changed != changed || result.Entry.ID == target.Entry.ID || (operation == "move_tree" && result.Entry.ID != source.Entry.ID) || (operation != "move_tree" && result.Entry.ID == source.Entry.ID) {
			t.Fatal("CLI collection replacement lost exact source/target identities or complete result", err)
		}
		if _, err = service.StatPath(ctx, adminScope, target.Entry.Path+"/old.dat"); !errors.Is(err, store.ErrNotFound) {
			t.Fatal("CLI collection replacement merged old destination members", err)
		}
		properties, err := service.ReadNamespacePropertySnapshot(ctx, managerScope, target.Entry.Path)
		if err != nil || properties.Properties["{urn:example}label"] != property.Property {
			t.Fatal("CLI replacement lost source property snapshot", err)
		}
		if operation == "copy_dir" {
			if _, err = service.StatPath(ctx, adminScope, target.Entry.Path+"/nested"); !errors.Is(err, store.ErrNotFound) {
				t.Fatal("CLI shallow replacement included a source child", err)
			}
		} else {
			actual, reader, err := service.DownloadPath(ctx, managerScope, target.Entry.Path+"/nested/data.dat")
			if err != nil {
				t.Fatal(err)
			}
			received, err := io.ReadAll(reader)
			reader.Close()
			if err != nil || actual.ID != file.ID || !bytes.Equal(received, data) {
				t.Fatal("CLI replacement member custody differs", err)
			}
		}
		_, reader, err := service.Download(ctx, adminScope, oldFile.ID)
		if err != nil {
			t.Fatal(err)
		}
		retained, err := io.ReadAll(reader)
		reader.Close()
		if err != nil || !bytes.Equal(retained, oldData) {
			t.Fatal("CLI overwrite erased old destination custody", err)
		}
		raw, err = command(manager, "namespace-receipt", "-request-file", input, "-idempotency-key", key)
		var receipt store.PathCommandReceipt
		if err != nil || json.Unmarshal(raw, &receipt) != nil || receipt.Observation != "original-commit-not-current-state" || receipt.Result.Entry != result.Entry || receipt.Result.Changed != changed || receipt.Result.Replayed {
			t.Fatal("CLI replacement lost exact historical commit recovery", err)
		}
		if operation != "move_tree" {
			current, err := service.StatPath(ctx, managerScope, source.Entry.Path)
			if err != nil || current.ID != source.Entry.ID || current.Revision != source.Entry.Revision {
				t.Fatal("CLI replacement copy changed source", err)
			}
		} else if _, err = service.StatPath(ctx, adminScope, source.Entry.Path); !errors.Is(err, store.ErrNotFound) {
			t.Fatal("CLI replacement move retained old source", err)
		}
	}
}
