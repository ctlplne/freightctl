package ftpsd

import (
	"errors"
	"io"
	"os"
	"path"
	"sync"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/vpath"
	ftp "github.com/fclairamb/ftpserverlib"
	"github.com/spf13/afero"
)

type filesystem struct {
	driver *sessionDriver
	scope  store.Scope
	mu     sync.Mutex
	closed bool
	open   map[*transfer]struct{}
}

func publicError(err error) error {
	if err == nil || errors.Is(err, io.EOF) {
		return err
	}
	switch {
	case errors.Is(err, store.ErrNotFound):
		return os.ErrNotExist
	case errors.Is(err, store.ErrUnauthorized), errors.Is(err, store.ErrForbidden), errors.Is(err, os.ErrPermission):
		return os.ErrPermission
	case errors.Is(err, store.ErrExists):
		return os.ErrExist
	default:
		return errSession
	}
}
func virtual(name string) error {
	_, err := vpath.Canonical(name)
	if err != nil || vpath.ControlPath(name) {
		return os.ErrPermission
	}
	return nil
}
func (f *filesystem) failure(err error) error {
	if errors.Is(err, store.ErrUnauthorized) || errors.Is(err, store.ErrForbidden) || errors.Is(err, custody.ErrStorageIdentity) {
		f.driver.cancel()
		_ = f.driver.listener.Close()
	}
	return publicError(err)
}
func (f *filesystem) Name() string { return "freightctl-custody" }

// Transfers and listings use the explicit bounded extensions below. No afero
// host filesystem, fallback file handle or arbitrary host path is exposed.
func (*filesystem) Create(string) (afero.File, error) { return nil, os.ErrPermission }
func (*filesystem) Open(string) (afero.File, error)   { return nil, os.ErrPermission }
func (*filesystem) OpenFile(string, int, os.FileMode) (afero.File, error) {
	return nil, os.ErrPermission
}
func (*filesystem) MkdirAll(string, os.FileMode) error         { return os.ErrPermission }
func (*filesystem) RemoveAll(string) error                     { return os.ErrPermission }
func (*filesystem) Chown(string, int, int) error               { return os.ErrPermission }
func (*filesystem) Chmod(string, os.FileMode) error            { return os.ErrPermission }
func (*filesystem) Chtimes(string, time.Time, time.Time) error { return os.ErrPermission }

func (f *filesystem) Stat(name string) (os.FileInfo, error) {
	if err := virtual(name); err != nil {
		return nil, err
	}
	e, err := f.driver.server.custody.StatPath(f.driver.ctx, f.scope, name)
	if err != nil {
		return nil, f.failure(err)
	}
	return entryInfo{*e}, nil
}
func (f *filesystem) ReadDir(name string) ([]os.FileInfo, error) {
	if err := virtual(name); err != nil {
		return nil, err
	}
	var out []os.FileInfo
	after := ""
	for {
		page, err := f.driver.server.custody.ListPath(f.driver.ctx, f.scope, name, after, 100)
		if err != nil {
			return nil, f.failure(err)
		}
		if len(out)+len(page.Entries) > f.driver.server.options.ListLimit {
			return nil, errSession
		}
		for _, e := range page.Entries {
			out = append(out, entryInfo{e})
		}
		if page.Next == "" {
			return out, nil
		}
		if page.Next == after {
			return nil, errSession
		}
		after = page.Next
	}
}
func (f *filesystem) command(c store.PathCommand) error {
	if err := virtual(c.Path); err != nil {
		return err
	}
	if c.Target != "" {
		if err := virtual(c.Target); err != nil {
			return err
		}
	}
	if c.Operation != "mkdir" {
		e, err := f.driver.server.custody.StatPath(f.driver.ctx, f.scope, c.Path)
		if err != nil {
			return f.failure(err)
		}
		c.ExpectedRevision = &e.Revision
	}
	_, err := f.driver.server.custody.PathCommand(f.driver.ctx, f.scope, "ftps-"+secure.NewID(), c)
	return f.failure(err)
}
func (f *filesystem) Mkdir(name string, mode os.FileMode) error {
	m := uint32(mode.Perm())
	return f.command(store.PathCommand{Operation: "mkdir", Path: name, Mode: &m})
}
func (f *filesystem) Remove(name string) error {
	return f.command(store.PathCommand{Operation: "remove", Path: name})
}
func (f *filesystem) RemoveDir(name string) error {
	return f.command(store.PathCommand{Operation: "rmdir", Path: name})
}
func (f *filesystem) Rename(old, next string) error {
	return f.command(store.PathCommand{Operation: "rename", Path: old, Target: next})
}

func (f *filesystem) GetHandle(name string, flags int, offset int64) (ftp.FileTransfer, error) {
	if err := virtual(name); err != nil {
		return nil, err
	}
	if offset < 0 || offset > f.driver.server.custody.MaxFile {
		return nil, errSession
	}
	if flags != os.O_RDONLY && flags != os.O_WRONLY|os.O_CREATE && flags != os.O_WRONLY|os.O_CREATE|os.O_TRUNC && flags != os.O_WRONLY|os.O_CREATE|os.O_APPEND {
		return nil, os.ErrPermission
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed || len(f.open) >= 2 {
		return nil, errSession
	}
	t := &transfer{fs: f}
	if flags == os.O_RDONLY {
		file, reader, err := f.driver.server.custody.OpenPathReader(f.driver.ctx, f.scope, name)
		if err != nil {
			return nil, f.failure(err)
		}
		t.reader, t.size = reader, file.Size
	} else {
		select {
		case f.driver.server.writers <- struct{}{}:
		default:
			return nil, errSession
		}
		w, err := f.driver.server.custody.OpenRevisionWriter(f.driver.ctx, f.scope, name, custody.WriteOptions{Create: true, Truncate: flags&os.O_TRUNC != 0, Append: flags&os.O_APPEND != 0})
		if err != nil {
			<-f.driver.server.writers
			return nil, f.failure(err)
		}
		t.writer = w
		if flags&os.O_APPEND != 0 {
			e, err := w.Stat()
			if err != nil {
				w.TransferError(err)
				_ = w.Close()
				<-f.driver.server.writers
				return nil, f.failure(err)
			}
			t.offset, t.size = e.Size, e.Size
		}
	}
	f.open[t] = struct{}{}
	return t, nil
}
func (f *filesystem) abort() {
	f.mu.Lock()
	f.closed = true
	var open []*transfer
	for t := range f.open {
		open = append(open, t)
	}
	f.mu.Unlock()
	for _, t := range open {
		t.TransferError(io.ErrUnexpectedEOF)
		_ = t.Close()
	}
}

type entryInfo struct{ entry store.PathEntry }

func (e entryInfo) Name() string { return path.Base(e.entry.Path) }
func (e entryInfo) Size() int64  { return e.entry.Size }
func (e entryInfo) Mode() os.FileMode {
	m := os.FileMode(e.entry.Mode)
	if e.entry.Kind == "dir" {
		m |= os.ModeDir
	}
	return m
}
func (e entryInfo) ModTime() time.Time { return e.entry.Modified }
func (e entryInfo) IsDir() bool        { return e.entry.Kind == "dir" }
func (e entryInfo) Sys() any           { return nil }

type transfer struct {
	fs           *filesystem
	mu           sync.Mutex
	reader       *custody.RevisionReader
	writer       *custody.RevisionWriter
	offset, size int64
	closed       bool
	failure      error
}

func (t *transfer) Read(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.reader == nil {
		return 0, os.ErrPermission
	}
	if len(p) > 256<<10 {
		p = p[:256<<10]
	}
	n, err := t.reader.ReadAt(p, t.offset)
	t.offset += int64(n)
	return n, t.fs.failure(err)
}
func (t *transfer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.writer == nil {
		return 0, os.ErrPermission
	}
	n, err := t.writer.WriteAt(p, t.offset)
	t.offset += int64(n)
	if t.offset > t.size {
		t.size = t.offset
	}
	return n, t.fs.failure(err)
}
func (t *transfer) Seek(offset int64, whence int) (int64, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return 0, os.ErrClosed
	}
	base := int64(0)
	switch whence {
	case io.SeekStart:
	case io.SeekCurrent:
		base = t.offset
	case io.SeekEnd:
		base = t.size
	default:
		return 0, t.badSeek()
	}
	if offset < -base || (offset > 0 && base > int64(^uint64(0)>>1)-offset) {
		return 0, t.badSeek()
	}
	next := base + offset
	if next < 0 || (t.reader != nil && next > t.size) || (t.writer != nil && next > t.fs.driver.server.custody.MaxFile) {
		return 0, t.badSeek()
	}
	t.offset = next
	return next, nil
}
func (t *transfer) badSeek() error {
	if t.writer != nil {
		t.writer.TransferError(errSession)
	}
	t.failure = errSession
	return errSession
}
func (t *transfer) TransferError(err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return
	}
	if err == nil {
		err = io.ErrUnexpectedEOF
	}
	t.failure = err
	if t.writer != nil {
		t.writer.TransferError(err)
	}
}
func (t *transfer) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return publicError(t.failure)
	}
	t.closed = true
	var err error
	if t.reader != nil {
		err = t.reader.Close()
	}
	if t.writer != nil {
		if t.fs.driver.ctx.Err() != nil {
			t.writer.TransferError(t.fs.driver.ctx.Err())
		}
		err = t.writer.Close()
		<-t.fs.driver.server.writers
	}
	t.fs.mu.Lock()
	delete(t.fs.open, t)
	t.fs.mu.Unlock()
	if err != nil {
		t.failure = err
	}
	return t.fs.failure(t.failure)
}
