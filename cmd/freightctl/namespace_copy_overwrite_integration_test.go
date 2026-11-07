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
	"github.com/ctlplne/freightctl/internal/store"
)

func qualifyNamespaceCopyOverwriteCLI(t *testing.T, ctx context.Context, service *custody.Service, adminScope, managerScope store.Scope, manager, ordinaryWriter string, command func(string, string, ...string) ([]byte, error), requestFile func(any) string) {
	t.Helper()
	data := []byte("exact CLI copy replacement source\n")
	previousBytes := []byte("retained CLI copy replacement destination\n")
	create := func(key, path string, b []byte) *store.File {
		t.Helper()
		f, _, err := service.AcceptAt(ctx, adminScope, key, int64(len(b)), secure.Digest(b), bytes.NewReader(b), custody.UploadTarget{Path: path})
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	source := create("cli-copy-replace-source", "/cli-replace-source.dat", data)
	previous := create("cli-copy-replace-previous", "/cli-replace-previous.dat", previousBytes)
	seed := requestFile(store.PathCommand{Operation: "publish", Path: "/cli-replace-target.dat", FileID: previous.ID})
	if _, err := command(manager, "namespace", "-request-file", seed, "-idempotency-key", "cli-copy-replace-seed"); err != nil {
		t.Fatal(err)
	}
	sourceEntry, err := service.StatPath(ctx, adminScope, "/cli-replace-source.dat")
	if err != nil {
		t.Fatal(err)
	}
	targetEntry, err := service.StatPath(ctx, managerScope, "/cli-replace-target.dat")
	if err != nil {
		t.Fatal(err)
	}
	selection := store.PathCommand{Operation: "copy", Path: sourceEntry.Path, Target: targetEntry.Path, FileID: source.ID, ExpectedRevision: &sourceEntry.Revision, Replace: true, TargetRevision: &targetEntry.Revision}
	input := requestFile(selection)
	if _, err = command(ordinaryWriter, "namespace", "-request-file", input, "-idempotency-key", "cli-copy-replace-no-management"); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("ordinary copy write granted target removal", err)
	}
	raw, err := command(manager, "namespace", "-request-file", input, "-idempotency-key", "cli-copy-replace-commit")
	var result store.PathResult
	if err != nil || json.Unmarshal(raw, &result) != nil || result.Replayed || result.Changed != 2 || result.Entry.ID == targetEntry.ID || result.Entry.FileID != source.ID {
		t.Fatal("ordinary CLI replacement lost exact new mapping or atomic outcome", err)
	}
	for _, path := range []string{sourceEntry.Path, targetEntry.Path} {
		file, reader, err := service.OpenPathReader(ctx, managerScope, path)
		if err != nil {
			t.Fatal(err)
		}
		actual, err := io.ReadAll(io.NewSectionReader(reader, 0, file.Size))
		reader.Close()
		if err != nil || file.ID != source.ID || !bytes.Equal(actual, data) {
			t.Fatal("CLI replacement independent exact readback differs", err)
		}
	}
	raw, err = command(manager, "namespace", "-request-file", input, "-idempotency-key", "cli-copy-replace-commit")
	var replay store.PathResult
	if err != nil || json.Unmarshal(raw, &replay) != nil || !replay.Replayed || replay.Entry != result.Entry {
		t.Fatal("CLI replacement repeated its original command", err)
	}
	changed := selection
	revision := *selection.TargetRevision + 1
	changed.TargetRevision = &revision
	if _, err = command(manager, "namespace", "-request-file", requestFile(changed), "-idempotency-key", "cli-copy-replace-commit"); !errors.Is(err, store.ErrConflict) {
		t.Fatal("CLI target revision reused an old replacement key", err)
	}
	old, reader, err := service.OpenPathReader(ctx, adminScope, "/cli-replace-previous.dat")
	if err != nil {
		t.Fatal(err)
	}
	actual, err := io.ReadAll(io.NewSectionReader(reader, 0, old.Size))
	reader.Close()
	if err != nil || old.ID != previous.ID || !bytes.Equal(actual, previousBytes) {
		t.Fatal("CLI replacement destroyed old custody", err)
	}
}
