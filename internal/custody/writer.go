package custody

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"sort"
	"sync"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/protectedfs"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/vpath"
)

type WriteOptions struct {
	Create, Truncate, Exclusive, Append bool
	Mode                                *uint32
	Modified                            *time.Time
}
type span struct{ start, end int64 }

// RevisionWriter stages a separate object. Only an explicit successful Close
// may seal and publish it. A transport must call TransferError before cleanup
// Close when a client disconnects with the handle open.
type RevisionWriter struct {
	mu                         sync.Mutex
	service                    *Service
	tx                         *store.Transaction
	ctx                        context.Context
	data                       *os.File
	name, key, path            string
	target                     UploadTarget
	file                       store.File
	old                        *store.PathEntry
	end                        int64
	coverage                   []span
	appendOnly, closed, sealed bool
	failure                    error
}

func (s *Service) OpenRevisionWriter(ctx context.Context, scope store.Scope, virtual string, options WriteOptions) (*RevisionWriter, error) {
	canonical, err := vpath.Canonical(virtual)
	if err != nil || canonical == "/" || vpath.ControlPath(canonical) {
		return nil, vpath.ErrPath
	}
	if options.Mode != nil && *options.Mode > 0777 || options.Exclusive && !options.Create || options.Append && options.Truncate || s.MaxFile < 1 {
		return nil, ErrInput
	}
	admission, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	t, err := s.DB.Begin(admission, scope)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = t.Tx.Rollback(context.Background())
		}
	}()
	if err = t.Require("write"); err != nil {
		return nil, err
	}
	if err = t.NamespaceLock(admission); err != nil {
		return nil, err
	}
	actual, err := vpath.Resolve(t.Root, canonical)
	if err != nil {
		return nil, err
	}
	if err = t.ParentWritable(admission, actual); err != nil {
		return nil, err
	}
	old, err := t.Entry(admission, actual)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	target := UploadTarget{Path: canonical, Mode: options.Mode, Modified: options.Modified}
	if old != nil {
		if old.Kind != "file" {
			return nil, store.ErrState
		}
		if options.Exclusive {
			return nil, store.ErrExists
		}
		if err = t.EntryMode(old, 2); err != nil {
			return nil, err
		}
		if options.Mode != nil && old.Owner != t.Actor && !t.Has("admin") {
			return nil, store.ErrForbidden
		}
		revision := old.Revision
		target.ExpectedRevision = &revision
	} else if !options.Create {
		return nil, store.ErrNotFound
	}
	if _, err = t.Tx.Exec(admission, `SELECT pg_advisory_xact_lock(721815034)`); err != nil {
		return nil, err
	}
	// The initial serialized profile reserves one complete maximum revision.
	if err = s.Disk.Capacity(s.MaxFile, s.MaxStored); err != nil {
		return nil, err
	}
	if err = t.Reauthorize(admission); err != nil {
		return nil, err
	}
	id := secure.NewID()
	name := Name(scope.Tenant, scope.Partner, id)
	data, err := protectedfs.CreateAt(s.Disk.root, name)
	if err != nil {
		return nil, err
	}
	w := &RevisionWriter{service: s, tx: t, ctx: ctx, data: data, name: name, key: "sftp-" + id, path: canonical, target: target, old: old, file: store.File{ID: id, Policy: "integrity-only-v1"}, appendOnly: options.Append}
	defer func() {
		if !ok {
			_ = data.Close()
			_ = s.Disk.root.Remove(name)
			_ = s.Disk.sync()
		}
	}()
	if err = t.ConfigureIntakeFile(admission, &w.file); err != nil {
		return nil, err
	}
	if old != nil && !options.Truncate {
		if err = t.FileAvailable(admission, old.FileID); err != nil {
			return nil, err
		}
		previous, err := t.File(admission, old.FileID)
		if err != nil {
			return nil, err
		}
		if previous.Size > s.MaxFile {
			return nil, ErrCapacity
		}
		original, err := s.Disk.VerifiedContext(admission, Name(scope.Tenant, scope.Partner, previous.ID), previous.Size, previous.SHA256)
		if err != nil {
			return nil, err
		}
		n, copyErr := io.CopyBuffer(data, contextReader{ctx: admission, reader: original}, make([]byte, 32<<10))
		original.Close()
		if copyErr != nil {
			return nil, copyErr
		}
		if n != previous.Size {
			return nil, ErrIntegrity
		}
		w.end = n
		if n > 0 {
			w.coverage = []span{{0, n}}
		}
	}
	ok = true
	return w, nil
}
func (w *RevisionWriter) fail(err error) error {
	if w.failure == nil {
		w.failure = err
	}
	return err
}
func (w *RevisionWriter) authority() error {
	if err := w.ctx.Err(); err != nil {
		return err
	}
	if err := w.tx.Reauthorize(w.ctx); err != nil {
		return err
	}
	return w.tx.Require("write")
}
func (w *RevisionWriter) WriteAt(p []byte, offset int64) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, os.ErrClosed
	}
	if w.failure != nil {
		return 0, w.failure
	}
	if err := w.authority(); err != nil {
		return 0, w.fail(err)
	}
	if w.appendOnly {
		offset = w.end
	}
	if offset < 0 || len(p) > 256<<10 || int64(len(p)) > w.service.MaxFile || offset > w.service.MaxFile-int64(len(p)) {
		return 0, w.fail(ErrInput)
	}
	if len(p) == 0 {
		return 0, nil
	}
	spans := append(append([]span{}, w.coverage...), span{offset, offset + int64(len(p))})
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	merged := make([]span, 0, len(spans))
	for _, s := range spans {
		if len(merged) > 0 && s.start <= merged[len(merged)-1].end {
			if s.end > merged[len(merged)-1].end {
				merged[len(merged)-1].end = s.end
			}
		} else {
			merged = append(merged, s)
		}
	}
	if len(merged) > 1024 {
		return 0, w.fail(store.ErrLimit)
	}
	n, err := w.data.WriteAt(p, offset)
	if err != nil {
		return n, w.fail(err)
	}
	if n != len(p) {
		return n, w.fail(io.ErrShortWrite)
	}
	w.coverage = merged
	if end := offset + int64(n); end > w.end {
		w.end = end
	}
	return n, nil
}
func (w *RevisionWriter) TransferError(err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.closed {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		w.fail(err)
	}
}
func (w *RevisionWriter) SetAttributes(size *int64, mode *uint32, modified *time.Time) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return os.ErrClosed
	}
	if w.failure != nil {
		return w.failure
	}
	if err := w.authority(); err != nil {
		return w.fail(err)
	}
	if err := w.tx.Require("manage_paths"); err != nil {
		return err
	}
	if w.old != nil && w.old.Owner != w.tx.Actor && !w.tx.Has("admin") {
		return store.ErrForbidden
	}
	if mode != nil {
		if *mode > 0777 {
			return ErrInput
		}
		value := *mode
		w.target.Mode = &value
	}
	if modified != nil {
		value := modified.UTC().Truncate(time.Microsecond)
		w.target.Modified = &value
	}
	if size != nil {
		if *size < 0 || *size > w.end {
			return ErrInput
		}
		if err := w.data.Truncate(*size); err != nil {
			return w.fail(err)
		}
		spans := w.coverage[:0]
		for _, s := range w.coverage {
			if s.start >= *size {
				continue
			}
			if s.end > *size {
				s.end = *size
			}
			spans = append(spans, s)
		}
		w.coverage = spans
		w.end = *size
	}
	return nil
}
func (w *RevisionWriter) Stat() (*store.PathEntry, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil, os.ErrClosed
	}
	if err := w.authority(); err != nil {
		return nil, err
	}
	if err := w.tx.Require("list"); err != nil {
		return nil, err
	}
	e := store.PathEntry{Path: w.path, Kind: "file", Owner: w.tx.Actor, Mode: 0640, Size: w.end, Modified: time.Now().UTC()}
	if w.old != nil {
		e = *w.old
		e.Path = w.path
		e.Size = w.end
	}
	if w.target.Mode != nil {
		e.Mode = *w.target.Mode
	}
	if w.target.Modified != nil {
		e.Modified = *w.target.Modified
	}
	return &e, nil
}
func (w *RevisionWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return w.failure
	}
	w.closed = true
	cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	defer w.tx.Tx.Rollback(cleanup)
	defer func() {
		_ = w.data.Close()
		if !w.sealed {
			_ = w.service.Disk.root.Remove(w.name)
			_ = w.service.Disk.sync()
		}
	}()
	if w.failure != nil {
		return w.failure
	}
	if err := w.authority(); err != nil {
		return w.fail(err)
	}
	if w.end > 0 && (len(w.coverage) != 1 || w.coverage[0].start != 0 || w.coverage[0].end != w.end) {
		return w.fail(ErrIntegrity)
	}
	if err := w.data.Truncate(w.end); err != nil {
		return w.fail(err)
	}
	if _, err := w.data.Seek(0, io.SeekStart); err != nil {
		return w.fail(err)
	}
	h := secure.NewDigest()
	n, err := io.CopyBuffer(h, contextReader{ctx: w.ctx, reader: io.LimitReader(w.data, w.end+1)}, make([]byte, 32<<10))
	if err != nil {
		return w.fail(err)
	}
	if n != w.end {
		return w.fail(ErrIntegrity)
	}
	w.file.Size = w.end
	w.file.SHA256 = hex.EncodeToString(h.Sum(nil))
	if err = protectedfs.SealReadOnly(w.data); err != nil {
		return w.fail(err)
	}
	if err = w.data.Sync(); err != nil {
		return w.fail(err)
	}
	if err = w.data.Close(); err != nil {
		return w.fail(err)
	}
	if err = w.service.Disk.sync(); err != nil {
		return w.fail(err)
	}
	// Any subsequent SQL uncertainty retains the sealed bytes for reconciliation.
	w.sealed = true
	meaning := pathMeaning(w.file.Size, w.file.SHA256, w.path, &w.target)
	if err = w.tx.Accept(w.ctx, w.key, meaning, &w.file); err != nil {
		return w.fail(err)
	}
	command := targetCommand(&w.target, w.file.ID)
	held, err := w.tx.BindIntake(w.ctx, &w.file, w.service.Disk.Identity(), &command)
	if err != nil {
		return w.fail(err)
	}
	if !held {
		if _, err = w.tx.ApplyPathCommand(w.ctx, w.key, command, w.service.NamespaceMaxEntries); err != nil {
			return w.fail(err)
		}
	}
	if err = w.tx.Reauthorize(w.ctx); err != nil {
		return w.fail(err)
	}
	if err = w.tx.Tx.Commit(w.ctx); err != nil {
		return w.fail(err)
	}
	return nil
}

// RevisionReader rechecks current key/account/mount/mode authority for each
// bounded read from the verified immutable descriptor.
type RevisionReader struct {
	mu         sync.Mutex
	service    *Service
	ctx        context.Context
	scope      store.Scope
	file       *store.File
	data       *os.File
	closed     bool
	exchangeID string
}

func (s *Service) OpenRevisionReader(ctx context.Context, scope store.Scope, virtual string) (*RevisionReader, error) {
	_, reader, err := s.OpenPathReader(ctx, scope, virtual)
	return reader, err
}

func (s *Service) OpenFileReader(ctx context.Context, scope store.Scope, id string) (*store.File, *RevisionReader, error) {
	file, data, err := s.Download(ctx, scope, id)
	if err != nil {
		return nil, nil, err
	}
	return file, &RevisionReader{service: s, ctx: ctx, scope: scope, file: file, data: data}, nil
}

func (s *Service) OpenPathReader(ctx context.Context, scope store.Scope, virtual string) (*store.File, *RevisionReader, error) {
	file, data, err := s.DownloadPath(ctx, scope, virtual)
	if err != nil {
		return nil, nil, err
	}
	return file, &RevisionReader{service: s, ctx: ctx, scope: scope, file: file, data: data}, nil
}
func (r *RevisionReader) ReadAt(p []byte, offset int64) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return 0, os.ErrClosed
	}
	if len(p) > 256<<10 || offset < 0 {
		return 0, ErrInput
	}
	readContext := r.ctx
	if r.exchangeID != "" {
		var cancel context.CancelFunc
		readContext, cancel = context.WithTimeout(r.ctx, 10*time.Second)
		defer cancel()
	}
	t, err := r.service.DB.Begin(readContext, r.scope)
	if err != nil {
		return 0, err
	}
	defer t.Tx.Rollback(readContext)
	if err = t.Require("read"); err != nil {
		return 0, err
	}
	if r.exchangeID != "" {
		err = r.checkExchangeRead(readContext, t)
	} else {
		err = t.FileAccessible(readContext, r.file.ID)
	}
	if err != nil {
		return 0, err
	}
	if r.exchangeID == "" {
		if err = t.Reauthorize(readContext); err != nil {
			return 0, err
		}
	}
	if err = readContext.Err(); err != nil {
		return 0, err
	}
	// Hold the authorization transaction until this bounded read finishes.
	n, err := r.data.ReadAt(p, offset)
	if err != nil && err != io.EOF {
		return n, err
	}
	if commitErr := t.Tx.Commit(readContext); commitErr != nil {
		return 0, commitErr
	}
	return n, err
}
func (r *RevisionReader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	return r.data.Close()
}
