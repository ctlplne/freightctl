// Package sftpd maps SFTP v3 operations to the shared custody/namespace service.
package sftpd

import (
	"context"
	"errors"
	"io"
	"os"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/vpath"
	"github.com/pkg/sftp"
)

type Service struct {
	Custody *custody.Service
	writers chan struct{}
}

var extensionsOnce sync.Once
var extensionsError error

func New(service *custody.Service, maxWriters int) (*Service, error) {
	if maxWriters < 1 || maxWriters > 4 {
		return nil, errors.New("SFTP writer budget must be 1 to 4 within the initial database pool profile")
	}
	if service.UploadCheckpointBytes != 0 && (service.UploadCheckpointBytes < int(custody.MinUploadChunk) || service.UploadCheckpointBytes > int(custody.MaxUploadChunk)) {
		return nil, custody.ErrInput
	}
	// Set once before any session starts: never advertise unsupported hardlink/statvfs.
	extensionsOnce.Do(func() { extensionsError = sftp.SetSFTPExtensions("posix-rename@openssh.com") })
	if extensionsError != nil {
		return nil, extensionsError
	}
	return &Service{Custody: service, writers: make(chan struct{}, maxWriters)}, nil
}
func (s *Service) Session(ctx context.Context, principal secure.SSHPrincipal, stream io.ReadWriteCloser) error {
	scope := store.Scope{Tenant: principal.Tenant, Partner: principal.Partner, Actor: principal.Actor, SSHKeyFingerprint: principal.Fingerprint, AuthorityRevision: principal.AuthorityRevision, SessionID: secure.NewID()}
	t, err := s.Custody.DB.Begin(ctx, scope)
	if err != nil {
		return err
	}
	_, err = t.Append(ctx, "ProtocolSessionStarted", scope.SessionID, map[string]any{"protocol": "sftp-v3", "fingerprint": principal.Fingerprint, "authority_revision": principal.AuthorityRevision})
	if err == nil {
		err = t.Tx.Commit(ctx)
	} else {
		_ = t.Tx.Rollback(ctx)
	}
	if err != nil {
		return err
	}
	// SSH owns channel close and exit-status. RequestServer cleanup must not
	// close the channel before the transport sends its final status to scp.
	view := &borrowedStream{ReadWriteCloser: stream}
	framed := newFrameStream(ctx, view)
	defer framed.Close()
	h := &handler{service: s, ctx: ctx, scope: scope, frames: framed, handles: make(chan struct{}, 8), open: make(map[string]*writer)}
	server := sftp.NewRequestServer(framed, sftp.Handlers{FileGet: h, FilePut: h, FileCmd: h, FileList: h}, sftp.WithStartDirectory("/"))
	defer server.Close()
	err = server.Serve()
	view.finished.Store(true)
	return err
}

type borrowedStream struct {
	io.ReadWriteCloser
	finished atomic.Bool
}

func (b *borrowedStream) Close() error {
	if b.finished.Load() {
		return nil
	}
	return b.ReadWriteCloser.Close()
}

type handler struct {
	service *Service
	ctx     context.Context
	scope   store.Scope
	frames  *frameStream
	handles chan struct{}
	mu      sync.Mutex
	open    map[string]*writer
}

func (h *handler) slot() error {
	select {
	case h.handles <- struct{}{}:
		return nil
	default:
		return sftp.ErrSSHFxFailure
	}
}
func (h *handler) release() { <-h.handles }
func (h *handler) transferError(err error) error {
	if errors.Is(err, store.ErrUnauthorized) || errors.Is(err, store.ErrForbidden) || errors.Is(err, custody.ErrStorageIdentity) {
		_ = h.frames.Close()
	}
	return protocolError(err)
}
func protocolError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, store.ErrUnauthorized), errors.Is(err, store.ErrForbidden):
		return sftp.ErrSSHFxPermissionDenied
	case errors.Is(err, store.ErrNotFound):
		return sftp.ErrSSHFxNoSuchFile
	default:
		return sftp.ErrSSHFxFailure
	}
}
func (h *handler) pending(p string) *writer {
	canonical, err := virtualPath(p)
	if err != nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.open[canonical]
}
func (h *handler) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	if vpath.ControlPath(r.Filepath) {
		return nil, sftp.ErrSSHFxPermissionDenied
	}
	if r.Flags & ^uint32(1) != 0 {
		return nil, sftp.ErrSSHFxOpUnsupported
	}
	if h.pending(r.Filepath) != nil {
		return nil, sftp.ErrSSHFxFailure
	}
	if err := h.slot(); err != nil {
		return nil, err
	}
	reader, err := h.service.Custody.OpenRevisionReader(h.ctx, h.scope, r.Filepath)
	if err != nil {
		h.release()
		return nil, protocolError(err)
	}
	return &readHandle{RevisionReader: reader, release: h.release, failure: h.transferError}, nil
}

type readHandle struct {
	*custody.RevisionReader
	once    sync.Once
	release func()
	failure func(error) error
}

func (r *readHandle) ReadAt(p []byte, offset int64) (int, error) {
	n, err := r.RevisionReader.ReadAt(p, offset)
	if err == io.EOF {
		return n, err
	}
	return n, r.failure(err)
}
func (r *readHandle) Close() error {
	err := r.RevisionReader.Close()
	r.once.Do(r.release)
	return protocolError(err)
}

type revisionWriter interface {
	io.WriterAt
	io.Closer
	TransferError(error)
	Stat() (*store.PathEntry, error)
	SetAttributes(*int64, *uint32, *time.Time) error
}
type writer struct {
	revisionWriter
	once    sync.Once
	cleanup func()
	failure func(error) error
}

func (w *writer) WriteAt(p []byte, offset int64) (int, error) {
	n, err := w.revisionWriter.WriteAt(p, offset)
	return n, w.failure(err)
}
func (w *writer) Close() error {
	err := w.revisionWriter.Close()
	w.once.Do(w.cleanup)
	return protocolError(err)
}
func (h *handler) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	flags := r.Pflags()
	if !flags.Write || flags.Read {
		return nil, sftp.ErrSSHFxOpUnsupported
	}
	if h.pending(r.Filepath) != nil {
		return nil, sftp.ErrSSHFxFailure
	}
	if err := h.slot(); err != nil {
		return nil, err
	}
	select {
	case h.service.writers <- struct{}{}:
	default:
		h.release()
		return nil, sftp.ErrSSHFxFailure
	}
	attrs := h.frames.Attributes()
	if attrs.size != nil && *attrs.size != 0 {
		<-h.service.writers
		h.release()
		return nil, sftp.ErrSSHFxOpUnsupported
	}
	var revision revisionWriter
	var err error
	options := custody.WriteOptions{Create: flags.Creat, Truncate: flags.Trunc, Exclusive: flags.Excl, Append: flags.Append, Mode: attrs.mode, Modified: attrs.modified}
	if id, control := uploadTicket(r.Filepath); control {
		if id == "" {
			err = store.ErrNotFound
		} else {
			revision, err = h.service.Custody.OpenUploadWriter(h.ctx, h.scope, id, options)
		}
	} else {
		revision, err = h.service.Custody.OpenRevisionWriter(h.ctx, h.scope, r.Filepath, options)
	}
	if err != nil {
		<-h.service.writers
		h.release()
		return nil, protocolError(err)
	}
	canonical, _ := virtualPath(r.Filepath)
	w := &writer{revisionWriter: revision, failure: h.transferError}
	w.cleanup = func() { h.mu.Lock(); delete(h.open, canonical); h.mu.Unlock(); <-h.service.writers; h.release() }
	h.mu.Lock()
	h.open[canonical] = w
	h.mu.Unlock()
	return w, nil
}
func (h *handler) RealPath(raw string) (string, error) {
	p, err := virtualPath(raw)
	if err != nil {
		return "", sftp.ErrSSHFxPermissionDenied
	}
	if _, control := uploadTicket(p); control {
		if _, err := h.controlStat(p); err != nil {
			return "", protocolError(err)
		}
	}
	// Even canonical-name queries recheck the key/account session revision.
	t, err := h.service.Custody.DB.Begin(h.ctx, h.scope)
	if err != nil {
		return "", protocolError(err)
	}
	defer t.Tx.Rollback(h.ctx)
	if err = t.Require("list"); err != nil {
		return "", protocolError(err)
	}
	return p, protocolError(t.Tx.Commit(h.ctx))
}
func (h *handler) Filecmd(r *sftp.Request) error     { return h.command(r, false) }
func (h *handler) PosixRename(r *sftp.Request) error { return h.command(r, true) }
func (h *handler) command(r *sftp.Request, replace bool) error {
	attrs := h.frames.Attributes()
	if pending := h.pending(r.Filepath); pending != nil {
		if r.Method != "Setstat" {
			return sftp.ErrSSHFxFailure
		}
		return protocolError(pending.SetAttributes(attrs.size, attrs.mode, attrs.modified))
	}
	if id, control := uploadTicket(r.Filepath); control && id != "" && (r.Method == "Rename" || r.Method == "PosixRename") {
		u, err := h.service.Custody.UploadStatus(h.ctx, h.scope, id)
		if err != nil {
			return protocolError(err)
		}
		target, err := virtualPath(r.Target)
		if err != nil || target != u.Path {
			return sftp.ErrSSHFxPermissionDenied
		}
		// This control-path rename finalizes the already approved target; it
		// cannot retarget an upload or expose any intermediate chunk.
		_, err = h.service.Custody.CompleteUpload(h.ctx, h.scope, id, "sftp-complete-"+id)
		return protocolError(err)
	}
	if vpath.ControlPath(r.Filepath) || vpath.ControlPath(r.Target) {
		return sftp.ErrSSHFxOpUnsupported
	}
	c := store.PathCommand{Path: r.Filepath, Target: r.Target, Mode: attrs.mode, Modified: attrs.modified}
	switch r.Method {
	case "Mkdir":
		if attrs.size != nil {
			return sftp.ErrSSHFxOpUnsupported
		}
		c.Operation = "mkdir"
	case "Rename", "PosixRename":
		c.Operation = "rename"
		c.Replace = replace
	case "Remove":
		c.Operation = "remove"
	case "Rmdir":
		c.Operation = "rmdir"
	case "Setstat":
		if attrs.size != nil {
			return sftp.ErrSSHFxOpUnsupported
		}
		c.Operation = "setstat"
	default:
		return sftp.ErrSSHFxOpUnsupported
	}
	if c.Operation != "mkdir" {
		old, err := h.service.Custody.StatPath(h.ctx, h.scope, r.Filepath)
		if err != nil {
			return protocolError(err)
		}
		c.ExpectedRevision = &old.Revision
		if replace {
			target, err := h.service.Custody.StatPath(h.ctx, h.scope, r.Target)
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				return protocolError(err)
			}
			if target != nil {
				c.TargetRevision = &target.Revision
			}
		}
	}
	_, err := h.service.Custody.PathCommand(h.ctx, h.scope, "sftp-"+secure.NewID(), c)
	return protocolError(err)
}
func (h *handler) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	switch r.Method {
	case "Stat", "Lstat":
		var entry *store.PathEntry
		var err error
		if pending := h.pending(r.Filepath); pending != nil {
			entry, err = pending.Stat()
		} else if _, control := uploadTicket(r.Filepath); control {
			entry, err = h.controlStat(r.Filepath)
		} else {
			entry, err = h.service.Custody.StatPath(h.ctx, h.scope, r.Filepath)
		}
		if err != nil {
			return nil, protocolError(err)
		}
		return singleEntry{entryInfo{*entry}}, nil
	case "List":
		if vpath.ControlPath(r.Filepath) {
			return nil, sftp.ErrSSHFxOpUnsupported
		}
		if err := h.slot(); err != nil {
			return nil, err
		}
		// Check the directory now; later pages are independently reauthorized.
		page, err := h.service.Custody.ListPath(h.ctx, h.scope, r.Filepath, "", 100)
		if err != nil {
			h.release()
			return nil, protocolError(err)
		}
		return &directory{h: h, path: r.Filepath, buffer: page.Entries, next: page.Next, release: h.release}, nil
	default:
		return nil, sftp.ErrSSHFxOpUnsupported
	}
}
func (h *handler) Lstat(r *sftp.Request) (sftp.ListerAt, error) { return h.Filelist(r) }

type entryInfo struct{ entry store.PathEntry }

func (e entryInfo) Name() string { return path.Base(e.entry.Path) }
func (e entryInfo) Size() int64  { return e.entry.Size }
func (e entryInfo) Mode() os.FileMode {
	mode := os.FileMode(e.entry.Mode)
	if e.entry.Kind == "dir" {
		mode |= os.ModeDir
	}
	return mode
}
func (e entryInfo) ModTime() time.Time { return e.entry.Modified }
func (e entryInfo) IsDir() bool        { return e.entry.Kind == "dir" }
func (e entryInfo) Sys() any           { return nil }

type singleEntry []os.FileInfo

func (s singleEntry) ListAt(out []os.FileInfo, offset int64) (int, error) {
	if offset < 0 || offset >= int64(len(s)) {
		return 0, io.EOF
	}
	n := copy(out, s[offset:])
	if n < len(out) {
		return n, io.EOF
	}
	return n, nil
}

type directory struct {
	mu         sync.Mutex
	h          *handler
	path, next string
	buffer     []store.PathEntry
	offset     int64
	closed     bool
	once       sync.Once
	release    func()
}

func (d *directory) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	d.buffer = nil
	d.once.Do(d.release)
	return nil
}
func (d *directory) ListAt(out []os.FileInfo, offset int64) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return 0, os.ErrClosed
	}
	if offset != d.offset {
		return 0, sftp.ErrSSHFxFailure
	}
	if _, err := d.h.service.Custody.ListPath(d.h.ctx, d.h.scope, d.path, "", 1); err != nil {
		return 0, protocolError(err)
	}
	n := 0
	for n < len(out) {
		if len(d.buffer) == 0 {
			if d.next == "" {
				return n, io.EOF
			}
			page, err := d.h.service.Custody.ListPath(d.h.ctx, d.h.scope, d.path, d.next, 100)
			if err != nil {
				return n, protocolError(err)
			}
			d.buffer = page.Entries
			d.next = page.Next
			if len(d.buffer) == 0 {
				return n, io.EOF
			}
		}
		out[n] = entryInfo{d.buffer[0]}
		d.buffer = d.buffer[1:]
		n++
		d.offset++
	}
	return n, nil
}

func uploadTicket(value string) (string, bool) {
	canonical, err := virtualPath(value)
	if err != nil {
		return "", false
	}
	if canonical == "/.freightctl" || canonical == "/.freightctl/uploads" {
		return "", true
	}
	const prefix = "/.freightctl/uploads/"
	if strings.HasPrefix(canonical, prefix) {
		id := strings.TrimPrefix(canonical, prefix)
		if store.ValidID(id) {
			return id, true
		}
		return "", true
	}
	if vpath.ControlPath(canonical) {
		return "", true
	}
	return "", false
}
func (h *handler) controlStat(value string) (*store.PathEntry, error) {
	id, control := uploadTicket(value)
	if !control {
		return nil, store.ErrNotFound
	}
	if id == "" {
		if value != "/.freightctl" && value != "/.freightctl/uploads" {
			return nil, store.ErrNotFound
		}
		t, err := h.service.Custody.DB.Begin(h.ctx, h.scope)
		if err != nil {
			return nil, err
		}
		defer t.Tx.Rollback(h.ctx)
		if err = t.Require("write"); err != nil {
			return nil, err
		}
		if err = t.Tx.Commit(h.ctx); err != nil {
			return nil, err
		}
		return &store.PathEntry{Path: value, Kind: "dir", Mode: 0700, Modified: time.Unix(0, 0).UTC()}, nil
	}
	u, err := h.service.Custody.UploadStatus(h.ctx, h.scope, id)
	if err != nil {
		return nil, err
	}
	return &store.PathEntry{ID: u.ID, Path: u.SFTPPath, Kind: "file", Mode: 0600, Size: u.Offset, Modified: u.Modified, Revision: u.Revision}, nil
}
