//go:build integration

package custody_test

import (
	"bytes"
	"errors"
	"sync"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestTusStrictOffsetDoesNotReplayStaleOffsetOrChangeOrdinaryReceipts(t *testing.T) {
	f := setup(t)
	f.service.NamespaceMaxEntries = 100
	data := bytes.Repeat([]byte("a"), int(custody.MinUploadChunk)+3)
	created, err := f.service.CreateUpload(f.ctx, f.a, "strict-ticket", custody.CreateUpload{Path: "/strict-offset.dat", Size: int64(len(data)), SHA256: secure.Digest(data)})
	if err != nil {
		t.Fatal(err)
	}
	first := data[:custody.MinUploadChunk]
	original, err := f.service.AppendUpload(f.ctx, f.a, created.Upload.ID, "original-chunk", 0, int64(len(first)), secure.Digest(first), bytes.NewReader(first))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.service.AppendUploadAtCurrentOffset(f.ctx, f.a, created.Upload.ID, "original-chunk", 0, int64(len(first)), secure.Digest(first), bytes.NewReader(first)); !errors.Is(err, store.ErrRevision) {
		t.Fatal("tus accepted a stale offset through original receipt", err)
	}
	replay, err := f.service.AppendUpload(f.ctx, f.a, created.Upload.ID, "original-chunk", 0, int64(len(first)), secure.Digest(first), bytes.NewReader(first))
	if err != nil || !replay.Replayed || replay.Upload.Offset != original.Upload.Offset || replay.Upload.Chunks != 1 {
		t.Fatal("strict transport changed ordinary replay semantics", err)
	}
	last := data[len(first):]
	if _, err = f.service.AppendUploadAtCurrentOffset(f.ctx, f.a, created.Upload.ID, "strict-final", int64(len(first)), int64(len(last)), secure.Digest(last), bytes.NewReader(last)); err != nil {
		t.Fatal(err)
	}
	completed, err := f.service.CompleteUpload(f.ctx, f.a, created.Upload.ID, "separate-ordinary-completion")
	if err != nil || completed.File == nil || completed.File.SHA256 != created.Upload.ExpectedSHA256 {
		t.Fatal("strict checkpoints changed ordinary verified acceptance", err)
	}
}

func TestTusConcurrentStrictOffsetsAcceptExactlyOneCheckpoint(t *testing.T) {
	f := setup(t)
	f.service.NamespaceMaxEntries = 100
	data := bytes.Repeat([]byte("b"), int(custody.MinUploadChunk)+1)
	created, err := f.service.CreateUpload(f.ctx, f.a, "concurrent-strict-ticket", custody.CreateUpload{Path: "/concurrent-strict.dat", Size: int64(len(data)), SHA256: secure.Digest(data)})
	if err != nil {
		t.Fatal(err)
	}
	chunk := data[:custody.MinUploadChunk]
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, key := range []string{"strict-concurrent-a", "strict-concurrent-b"} {
		wg.Add(1)
		go func(key string) {
			defer wg.Done()
			_, err := f.service.AppendUploadAtCurrentOffset(f.ctx, f.a, created.Upload.ID, key, 0, int64(len(chunk)), secure.Digest(chunk), bytes.NewReader(chunk))
			results <- err
		}(key)
	}
	wg.Wait()
	close(results)
	accepted, conflicts := 0, 0
	for err := range results {
		if err == nil {
			accepted++
		} else if errors.Is(err, store.ErrRevision) {
			conflicts++
		} else {
			t.Fatal("unexpected concurrent result", err)
		}
	}
	if accepted != 1 || conflicts != 1 {
		t.Fatal("strict offsets admitted competing effects", accepted, conflicts)
	}
	status, err := f.service.UploadStatus(f.ctx, f.a, created.Upload.ID)
	if err != nil || status.Chunks != 1 || status.Offset != int64(len(chunk)) || status.FileID != "" {
		t.Fatal("conflicting offset changed durable checkpoint count or published bytes", err)
	}
}
