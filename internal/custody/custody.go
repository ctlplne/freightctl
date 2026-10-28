// Package custody persists immutable, service-named bytes before SQL acceptance.
package custody

import (
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"

	secure "github.com/ctlplne/freightctl/internal/crypto"
)

var ErrIntegrity = errors.New("file length or SHA-256 does not match")
var ErrCapacity = errors.New("custody quota reached; reconcile retained bytes or increase configured capacity")

type Disk struct{ root *os.Root }

func Open(path string) (*Disk, error) {
	if err := os.MkdirAll(path, 0700); err != nil {
		return nil, err
	}
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
	st, err := f.Stat()
	if err != nil || st.Mode().Perm()&0077 != 0 {
		r.Close()
		return nil, errors.New("storage root must have mode 0700")
	}
	return &Disk{root: r}, nil
}
func (d *Disk) Close() error { return d.root.Close() }

// Caller holds the database custody lock. Retained orphans count against capacity.
func (d *Disk) Capacity(incoming, maximum int64) error {
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
	defer f.Close()
	return f.Sync()
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
	if !validName(name) || size < 0 || size == int64(^uint64(0)>>1) {
		return errors.New("invalid custody identity or length")
	}
	f, err := d.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	finished := false
	defer func() {
		_ = f.Close()
		if !finished {
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
	if err = f.Chmod(0400); err != nil {
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
	if !validName(name) {
		return nil, errors.New("invalid custody identity")
	}
	f, err := d.root.Open(name)
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
	h := secure.NewDigest()
	if _, err = io.CopyBuffer(h, f, make([]byte, 32*1024)); err != nil {
		return nil, err
	}
	if hex.EncodeToString(h.Sum(nil)) != digest {
		return nil, ErrIntegrity
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	ok = true
	return f, nil
}
