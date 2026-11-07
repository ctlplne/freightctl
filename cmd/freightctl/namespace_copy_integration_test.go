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

func qualifyNamespaceCopyCLI(t *testing.T, ctx context.Context, service *custody.Service, adminScope, writerScope store.Scope, writer, reader string, command func(string, string, ...string) ([]byte, error), requestFile func(any) string) {
	t.Helper()
	data := []byte("CLI copy requires read and destination write;no forwarding or execution\n")
	file, _, err := service.AcceptAt(ctx, adminScope, "cli-namespace-copy-source", int64(len(data)), secure.Digest(data), bytes.NewReader(data), custody.UploadTarget{Path: "/cli-copy-source.dat"})
	if err != nil {
		t.Fatal("CLI copy source acceptance failed", err)
	}
	entry, err := service.StatPath(ctx, adminScope, "/cli-copy-source.dat")
	if err != nil {
		t.Fatal(err)
	}
	input := requestFile(store.PathCommand{Operation: "copy", Path: entry.Path, Target: "/cli-copied.dat", FileID: file.ID, ExpectedRevision: &entry.Revision})
	if _, err := command(reader, "namespace", "-request-file", input, "-idempotency-key", "cli-copy-reader-denied"); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("read-only CLI participant gained copy authority", err)
	}
	raw, err := command(writer, "namespace", "-request-file", input, "-idempotency-key", "cli-namespace-copy")
	var copied store.PathResult
	if err != nil || json.Unmarshal(raw, &copied) != nil || copied.Replayed || copied.Entry.ID == entry.ID || copied.Entry.FileID != file.ID || copied.Entry.Path != "/cli-copied.dat" {
		t.Fatal("actual namespace CLI did not copy the exact immutable source", err)
	}
	for _, path := range []string{entry.Path, copied.Entry.Path} {
		actual, opened, err := service.OpenPathReader(ctx, writerScope, path)
		if err != nil {
			t.Fatal(err)
		}
		body, readErr := io.ReadAll(io.NewSectionReader(opened, 0, actual.Size))
		opened.Close()
		if readErr != nil || actual.ID != file.ID || !bytes.Equal(body, data) {
			t.Fatal("independent CLI source/copied-path readback differs", readErr)
		}
	}
	raw, err = command(writer, "namespace", "-request-file", input, "-idempotency-key", "cli-namespace-copy")
	var replay store.PathResult
	if err != nil || json.Unmarshal(raw, &replay) != nil || !replay.Replayed || replay.Entry != copied.Entry {
		t.Fatal("CLI copy original-key receipt differs", err)
	}
	changed := requestFile(store.PathCommand{Operation: "copy", Path: entry.Path, Target: "/cli-other-copy.dat", FileID: file.ID, ExpectedRevision: &entry.Revision})
	if _, err := command(writer, "namespace", "-request-file", changed, "-idempotency-key", "cli-namespace-copy"); !errors.Is(err, store.ErrConflict) {
		t.Fatal("CLI copy reused a key for another target", err)
	}
}
