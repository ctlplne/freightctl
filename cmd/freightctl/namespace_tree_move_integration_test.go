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

func qualifyNamespaceTreeMoveCLI(t *testing.T, ctx context.Context, service *custody.Service, adminScope, managerScope store.Scope, manager, ordinaryWriter string, command func(string, string, ...string) ([]byte, error), requestFile func(any) string) {
	t.Helper()
	apply := func(key string, c store.PathCommand) *store.PathResult {
		t.Helper()
		raw, err := command(manager, "namespace", "-request-file", requestFile(c), "-idempotency-key", key)
		var result store.PathResult
		if err != nil || json.Unmarshal(raw, &result) != nil {
			t.Fatal("CLI tree fixture command failed", err)
		}
		return &result
	}
	root := apply("cli-tree-source", store.PathCommand{Operation: "mkdir", Path: "/cli-tree"})
	apply("cli-tree-nested", store.PathCommand{Operation: "mkdir", Path: "/cli-tree/nested"})
	data := []byte("CLI whole-tree movement retains exact immutable data\n")
	file, _, err := service.AcceptAt(ctx, adminScope, "cli-tree-file", int64(len(data)), secure.Digest(data), bytes.NewReader(data), custody.UploadTarget{Path: "/cli-tree/nested/data.dat"})
	if err != nil {
		t.Fatal(err)
	}
	property := namespaceprops.Change{Operation: "set", Property: `<label xmlns="urn:example">inert CLI tree property</label>`}
	root = apply("cli-tree-property", store.PathCommand{Operation: "properties", Path: root.Entry.Path, ExpectedEntryID: root.Entry.ID, ExpectedRevision: &root.Entry.Revision, PropertyChanges: []namespaceprops.Change{property}})
	selection := store.PathCommand{Operation: "move_tree", Path: root.Entry.Path, Target: "/cli-tree-moved", ExpectedEntryID: root.Entry.ID, ExpectedRevision: &root.Entry.Revision}
	input := requestFile(selection)
	if _, err = command(ordinaryWriter, "namespace", "-request-file", input, "-idempotency-key", "cli-tree-no-management"); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("ordinary write granted whole-tree management", err)
	}
	raw, err := command(manager, "namespace", "-request-file", input, "-idempotency-key", "cli-tree-original")
	var result store.PathResult
	if err != nil || json.Unmarshal(raw, &result) != nil || result.Replayed || result.Changed != 3 || result.Entry.ID != root.Entry.ID || result.Entry.Revision != root.Entry.Revision+1 {
		t.Fatal("CLI tree move lost complete atomic result", err)
	}
	observed, err := service.ReadNamespacePropertySnapshot(ctx, managerScope, "/cli-tree-moved")
	if err != nil || observed.Entry.ID != root.Entry.ID || observed.Properties["{urn:example}label"] != property.Property {
		t.Fatal("CLI moved root lost its identity or inert XML", err)
	}
	actual, reader, err := service.OpenPathReader(ctx, managerScope, "/cli-tree-moved/nested/data.dat")
	if err != nil {
		t.Fatal(err)
	}
	received, err := io.ReadAll(io.NewSectionReader(reader, 0, actual.Size))
	reader.Close()
	if err != nil || actual.ID != file.ID || !bytes.Equal(received, data) {
		t.Fatal("independent CLI moved member custody differs", err)
	}
	if _, err = command(manager, "namespace", "-request-file", input, "-idempotency-key", "cli-tree-original"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("absent original source recovered a current tree assertion", err)
	}
	restored, err := service.PathCommand(ctx, adminScope, "cli-tree-restore", store.PathCommand{Operation: "rename", Path: selection.Target, Target: selection.Path, ExpectedRevision: &result.Entry.Revision})
	if err != nil {
		t.Fatal(err)
	}
	raw, err = command(manager, "namespace", "-request-file", input, "-idempotency-key", "cli-tree-original")
	var replay store.PathResult
	if err != nil || json.Unmarshal(raw, &replay) != nil || !replay.Replayed || replay.Entry != result.Entry {
		t.Fatal("CLI original tree receipt repeated movement", err)
	}
	current, err := service.StatPath(ctx, managerScope, selection.Path)
	if err != nil || current.ID != restored.Entry.ID || current.Revision != restored.Entry.Revision {
		t.Fatal("historical CLI tree receipt changed restored source", err)
	}
	selection.Target = "/cli-tree-different"
	if _, err = command(manager, "namespace", "-request-file", requestFile(selection), "-idempotency-key", "cli-tree-original"); !errors.Is(err, store.ErrConflict) {
		t.Fatal("changed CLI tree destination reused an original key", err)
	}
	// Ordinary read/list/write permits copying into a new mapping without
	// conferring management of the original collection.
	for _, test := range []struct {
		operation, target string
		changed           int
	}{{"copy_dir", "/cli-tree-shallow", 1}, {"copy_tree", "/cli-tree-copy", 3}} {
		copyCommand := store.PathCommand{Operation: test.operation, Path: restored.Entry.Path, Target: test.target, ExpectedEntryID: restored.Entry.ID, ExpectedRevision: &restored.Entry.Revision}
		input := requestFile(copyCommand)
		raw, err = command(ordinaryWriter, "namespace", "-request-file", input, "-idempotency-key", "cli-"+test.operation+"-original")
		var copied store.PathResult
		if err != nil || json.Unmarshal(raw, &copied) != nil || copied.Replayed || copied.Changed != test.changed || copied.Entry.ID == restored.Entry.ID || copied.Entry.Owner == restored.Entry.Owner || copied.Entry.Revision != 2 {
			t.Fatal("CLI tree copy lost new ownership,depth or property initialization", err)
		}
		properties, err := service.ReadNamespacePropertySnapshot(ctx, adminScope, test.target)
		if err != nil || properties.Properties["{urn:example}label"] != property.Property {
			t.Fatal("CLI copied root lost exact inert properties", err)
		}
		if test.changed == 1 {
			if _, err = service.StatPath(ctx, adminScope, test.target+"/nested"); !errors.Is(err, store.ErrNotFound) {
				t.Fatal("CLI shallow copy included a child", err)
			}
		} else {
			actual, reader, err := service.DownloadPath(ctx, adminScope, test.target+"/nested/data.dat")
			if err != nil {
				t.Fatal(err)
			}
			received, err := io.ReadAll(reader)
			reader.Close()
			if err != nil || actual.ID != file.ID || !bytes.Equal(received, data) {
				t.Fatal("CLI copied member custody differs", err)
			}
		}
		raw, err = command(ordinaryWriter, "namespace", "-request-file", input, "-idempotency-key", "cli-"+test.operation+"-original")
		var copyHistory store.PathResult
		if err != nil || json.Unmarshal(raw, &copyHistory) != nil || !copyHistory.Replayed || copyHistory.Entry != copied.Entry {
			t.Fatal("CLI copy replay repeated publication", err)
		}
	}
	remove := store.PathCommand{Operation: "remove_tree", Path: restored.Entry.Path, ExpectedEntryID: restored.Entry.ID, ExpectedRevision: &restored.Entry.Revision}
	removeInput := requestFile(remove)
	if _, err = command(ordinaryWriter, "namespace", "-request-file", removeInput, "-idempotency-key", "cli-tree-delete-denied"); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("ordinary write granted recursive collection removal", err)
	}
	raw, err = command(manager, "namespace", "-request-file", removeInput, "-idempotency-key", "cli-tree-delete-original")
	var removed store.PathResult
	if err != nil || json.Unmarshal(raw, &removed) != nil || removed.Replayed || removed.Changed != 3 || removed.Entry.ID != restored.Entry.ID || !removed.Entry.Deleted || removed.Entry.Revision != restored.Entry.Revision+1 {
		t.Fatal("CLI removal lost its atomic three-member result", err)
	}
	for _, path := range []string{"/cli-tree", "/cli-tree/nested", "/cli-tree/nested/data.dat"} {
		if _, err = service.StatPath(ctx, adminScope, path); !errors.Is(err, store.ErrNotFound) {
			t.Fatal("CLI collection removal retained a live member", err)
		}
	}
	copiedFile, copiedReader, err := service.DownloadPath(ctx, adminScope, "/cli-tree-copy/nested/data.dat")
	if err != nil {
		t.Fatal(err)
	}
	copiedBytes, err := io.ReadAll(copiedReader)
	copiedReader.Close()
	if err != nil || copiedFile.ID != file.ID || !bytes.Equal(copiedBytes, data) {
		t.Fatal("CLI copied mapping depended on removed source", err)
	}
	retained, retainedReader, err := service.Download(ctx, adminScope, file.ID)
	if err != nil {
		t.Fatal(err)
	}
	retainedBytes, err := io.ReadAll(retainedReader)
	retainedReader.Close()
	if err != nil || retained.ID != file.ID || !bytes.Equal(retainedBytes, data) {
		t.Fatal("CLI collection removal destroyed original custody", err)
	}
	if _, err = command(manager, "namespace", "-request-file", removeInput, "-idempotency-key", "cli-tree-delete-original"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("absent original collection was removed twice or asserted current", err)
	}
}
