package custody

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

// UploadWriter buffers at most one checkpoint. Durable progress is the SQL
// offset, never the unflushed buffer length. Disconnect preserves committed
// chunks while dropping this handle's unacknowledged tail.
type UploadWriter struct {
	mu                   sync.Mutex
	service              *Service
	ctx                  context.Context
	scope                store.Scope
	id                   string
	start, end, expected int64
	buffer               []byte
	threshold            int
	closed               bool
	appendOnly           bool
	failure              error
}

func (s *Service) OpenUploadWriter(ctx context.Context, scope store.Scope, id string, options WriteOptions) (*UploadWriter, error) {
	u, err := s.WritableUploadStatus(ctx, scope, id)
	if err != nil {
		return nil, err
	}
	if u.State != "open" {
		return nil, store.ErrState
	}
	if options.Exclusive || options.Append && options.Truncate || options.Truncate && u.Offset > 0 {
		return nil, store.ErrState
	}
	threshold := s.UploadCheckpointBytes
	if threshold == 0 {
		threshold = 1 << 20
	}
	if threshold < int(MinUploadChunk) || threshold > int(MaxUploadChunk) {
		return nil, ErrInput
	}
	return &UploadWriter{service: s, ctx: ctx, scope: scope, id: id, start: u.Offset, end: u.Offset, expected: u.ExpectedSize, threshold: threshold, buffer: make([]byte, 0, threshold), appendOnly: options.Append}, nil
}
func (w *UploadWriter) fail(err error) error {
	if w.failure == nil {
		w.failure = err
	}
	return err
}
func (w *UploadWriter) flush() error {
	if len(w.buffer) == 0 {
		return nil
	}
	digest := secure.Digest(w.buffer)
	key := "sftp-chunk-" + secure.Digest([]byte(fmt.Sprintf("%s:%d:%s", w.id, w.start, digest)))
	result, err := w.service.AppendUpload(w.ctx, w.scope, w.id, key, w.start, int64(len(w.buffer)), digest, bytes.NewReader(w.buffer))
	if err != nil {
		return w.fail(err)
	}
	w.start = result.Upload.Offset
	secure.Clear(w.buffer)
	w.buffer = w.buffer[:0]
	return nil
}
func (w *UploadWriter) WriteAt(p []byte, offset int64) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, os.ErrClosed
	}
	if w.failure != nil {
		return 0, w.failure
	}
	u, err := w.service.WritableUploadStatus(w.ctx, w.scope, w.id)
	if err != nil {
		return 0, w.fail(err)
	}
	if u.State != "open" || u.Offset != w.start {
		return 0, w.fail(store.ErrRevision)
	}
	if w.appendOnly {
		offset = w.end
	}
	if offset != w.end || offset < 0 || len(p) > 256<<10 || int64(len(p)) > w.expected-offset {
		return 0, w.fail(ErrInput)
	}
	n := 0
	for len(p) > 0 {
		count := w.threshold - len(w.buffer)
		if count > len(p) {
			count = len(p)
		}
		w.buffer = append(w.buffer, p[:count]...)
		w.end += int64(count)
		n += count
		p = p[count:]
		if len(w.buffer) == w.threshold {
			if err = w.flush(); err != nil {
				return n, err
			}
		}
	}
	return n, nil
}
func (w *UploadWriter) TransferError(err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.closed {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		w.fail(err)
	}
}
func (w *UploadWriter) Stat() (*store.PathEntry, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil, os.ErrClosed
	}
	u, err := w.service.UploadStatus(w.ctx, w.scope, w.id)
	if err != nil {
		return nil, err
	}
	return &store.PathEntry{ID: u.ID, Path: u.SFTPPath, Kind: "file", Mode: 0600, Size: u.Offset, Owner: w.scope.Actor, Modified: u.Modified, Revision: u.Revision}, nil
}
func (w *UploadWriter) SetAttributes(size *int64, mode *uint32, modified *time.Time) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return os.ErrClosed
	}
	if mode != nil || modified != nil {
		return store.ErrState
	}
	if size == nil || *size != w.expected || w.end != w.expected {
		return store.ErrState
	}
	_, err := w.service.UploadStatus(w.ctx, w.scope, w.id)
	return err
}
func (w *UploadWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return w.failure
	}
	w.closed = true
	defer func() { secure.Clear(w.buffer); w.buffer = nil }()
	if w.failure != nil {
		return w.failure
	}
	if len(w.buffer) > 0 {
		if int64(len(w.buffer)) < MinUploadChunk && w.end < w.expected {
			return w.fail(store.ErrRevision)
		}
		if err := w.flush(); err != nil {
			return err
		}
	}
	_, err := w.service.CompleteUpload(w.ctx, w.scope, w.id, "sftp-complete-"+w.id)
	if err != nil {
		return w.fail(err)
	}
	return nil
}
