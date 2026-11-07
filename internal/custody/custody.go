// Package custody persists immutable, service-named bytes before SQL acceptance.
package custody

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/durablefs"
	"github.com/ctlplne/freightctl/internal/protectedfs"
)

var ErrIntegrity = errors.New("file length or SHA-256 does not match")
var ErrCapacity = errors.New("custody quota reached; reconcile retained bytes or increase configured capacity")

type Disk struct {
	root     *os.Root
	identity string
}

func Open(path string) (*Disk, error) {
	if err := protectedfs.EnsureDirectory(path); err != nil {
		return nil, err
	}
	return openDisk(path, true)
}

func OpenExisting(path string) (*Disk, error) { return openDisk(path, false) }
func openDisk(path string, initialize bool) (*Disk, error) {
	r, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	f, err := r.Open(".")
	if err != nil {
		r.Close()
		return nil, err
	}
	defer f.Close()
	if err = protectedfs.ValidateDirectory(f); err != nil {
		r.Close()
		return nil, errors.Join(errors.New("storage root must be private to the runtime identity"), err)
	}
	var id string
	if initialize {
		id, err = initializeIdentity(r)
	} else {
		id, err = readIdentity(r)
	}
	if err != nil {
		r.Close()
		return nil, err
	}
	return &Disk{root: r, identity: id}, nil
}
func (d *Disk) Close() error { return d.root.Close() }

// Caller holds the database custody lock. Retained orphans count against capacity.
func (d *Disk) Capacity(incoming, maximum int64) error {
	if err := d.CheckIdentity(); err != nil {
		return err
	}
	f, err := d.root.Open(".")
	if err != nil {
		return err
	}
	defer f.Close()
	remaining := maximum - incoming
	if remaining < 0 {
		return ErrCapacity
	}
	count := 0
	for {
		entries, err := f.ReadDir(128)
		if err != nil && err != io.EOF {
			return err
		}
		for _, e := range entries {
			if e.Name() == StorageIdentityName {
				continue
			}
			count++
			if count >= 10000 {
				return ErrCapacity
			}
			st, err := e.Info()
			if err != nil {
				return err
			}
			if !st.Mode().IsRegular() {
				return errors.New("unexpected non-file in custody root")
			}
			if st.Size() > remaining {
				return ErrCapacity
			}
			remaining -= st.Size()
		}
		if err == io.EOF {
			return nil
		}
	}
}
func (d *Disk) sync() error {
	f, err := d.root.Open(".")
	if err != nil {
		return err
	}
	err = durablefs.SyncDirectory(f)
	return errors.Join(err, f.Close())
}
func Name(tenant, partner, id string) string { return tenant + "_" + partner + "_" + id }
func validName(name string) bool {
	if len(name) != 110 {
		return false
	}
	parts := strings.Split(name, "_")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if len(p) != 36 {
			return false
		}
		for i, c := range p {
			if i == 8 || i == 13 || i == 18 || i == 23 {
				if c != '-' {
					return false
				}
			} else if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return false
			}
		}
	}
	return true
}
func (d *Disk) Stage(name string, src io.Reader, size int64, digest string) (err error) {
	return d.stage(name, src, size, digest, false)
}
func (d *Disk) stage(name string, src io.Reader, size int64, digest string, retainInterrupted bool) (err error) {
	if !validName(name) || size < 0 || size == int64(^uint64(0)>>1) {
		return errors.New("invalid custody identity or length")
	}
	f, err := protectedfs.CreateAt(d.root, name)
	if err != nil {
		return err
	}
	finished := false
	defer func() {
		_ = f.Close()
		if !finished && !retainInterrupted {
			_ = d.root.Remove(name)
			_ = d.sync()
		}
	}()
	h := secure.NewDigest()
	buf := make([]byte, 32*1024)
	n, err := io.CopyBuffer(io.MultiWriter(f, h), io.LimitReader(src, size+1), buf)
	if err != nil {
		return err
	}
	if n != size || hex.EncodeToString(h.Sum(nil)) != digest {
		return ErrIntegrity
	}
	if err = protectedfs.SealReadOnly(f); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = d.sync(); err != nil {
		return err
	}
	finished = true
	return nil
}
func (d *Disk) Verified(name string, size int64, digest string) (*os.File, error) {
	return d.VerifiedContext(context.Background(), name, size, digest)
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

func (d *Disk) VerifiedContext(ctx context.Context, name string, size int64, digest string) (*os.File, error) {
	if !validName(name) || size < 0 || size == int64(^uint64(0)>>1) {
		return nil, errors.New("invalid custody identity")
	}
	f, err := d.openObject(name)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			f.Close()
		}
	}()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() != size {
		return nil, ErrIntegrity
	}
	state, err := protectedfs.Protection(f)
	if err != nil || state != protectedfs.PrivateSealed {
		return nil, ErrIntegrity
	}
	h := secure.NewDigest()
	n, err := io.CopyBuffer(h, contextReader{ctx: ctx, reader: io.LimitReader(f, size+1)}, make([]byte, 32*1024))
	if err != nil {
		return nil, err
	}
	if n != size || hex.EncodeToString(h.Sum(nil)) != digest {
		return nil, ErrIntegrity
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	ok = true
	return f, nil
}

// openObject binds regular-file metadata to the exact opened revision. A flat
// custody name may not be a symlink/reparse point or change during opening.
func (d *Disk) openObject(name string) (*os.File, error) {
	before, err := d.root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, ErrIntegrity
	}
	f, err := d.root.Open(name)
	if err != nil {
		return nil, err
	}
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) {
		f.Close()
		return nil, ErrIntegrity
	}
	return f, nil
}
