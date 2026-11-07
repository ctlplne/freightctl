package protectedfs

import (
	"errors"
	"os"
	"path/filepath"
)

// SocketReference pins a private pathname socket. It never reads payload bytes
// or grants a daemon permission. Windows holds the native reparse object open;
// Unix retains the exact inode and permission checks without opening its data.
type SocketReference struct {
	path   string
	info   os.FileInfo
	file   *os.File
	closed bool
}

func OpenPrivateSocket(path string) (*SocketReference, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrPrivacy
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return nil, ErrPrivacy
	}
	f, err := platformSocket(path, info)
	if err != nil {
		return nil, err
	}
	s := &SocketReference{path: path, info: info, file: f}
	if err = s.Validate(); err != nil {
		return nil, errors.Join(err, s.Close())
	}
	return s, nil
}

// Validate rechecks the same object and its current privacy. A listener at a
// replacement pathname cannot inherit the original socket's qualification.
func (s *SocketReference) Validate() error {
	if s == nil || s.closed {
		return os.ErrClosed
	}
	current, err := os.Lstat(s.path)
	if err != nil {
		return err
	}
	if !os.SameFile(s.info, current) || current.Mode()&os.ModeSocket == 0 {
		return ErrPrivacy
	}
	return platformSocketPrivacy(s.file, current)
}

func (s *SocketReference) Close() error {
	if s == nil || s.closed {
		return os.ErrClosed
	}
	s.closed = true
	if s.file != nil {
		return s.file.Close()
	}
	return nil
}
