package custody

import (
	"errors"
	"io"
	"os"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

const StorageIdentityName = ".freightctl-storage-id"

var ErrStorageIdentity = errors.New("storage identity is missing or differs from the upload's recorded store")

func readIdentity(root *os.Root) (string, error) {
	st, err := root.Lstat(StorageIdentityName)
	if err != nil || !st.Mode().IsRegular() || st.Size() != 36 || st.Mode().Perm() != 0400 {
		return "", ErrStorageIdentity
	}
	f, err := root.Open(StorageIdentityName)
	if err != nil {
		return "", ErrStorageIdentity
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 37))
	if err != nil || !store.ValidID(string(data)) {
		return "", ErrStorageIdentity
	}
	return string(data), nil
}
func initializeIdentity(root *os.Root) (string, error) {
	if _, err := root.Lstat(StorageIdentityName); err == nil {
		return readIdentity(root)
	} else if !os.IsNotExist(err) {
		return "", ErrStorageIdentity
	}
	name := ".freightctl-storage-pending-" + secure.NewID()
	id := secure.NewID()
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", err
	}
	defer f.Close()
	defer root.Remove(name)
	if _, err = f.Write([]byte(id)); err != nil {
		return "", err
	}
	if err = f.Chmod(0400); err != nil {
		return "", err
	}
	if err = f.Sync(); err != nil {
		return "", err
	}
	if err = f.Close(); err != nil {
		return "", err
	}
	// A complete synced identity becomes visible atomically; a racing initializer
	// reads the winner instead of observing a half-written marker.
	if err = root.Link(name, StorageIdentityName); err != nil && !os.IsExist(err) {
		return "", err
	}
	if err = (&Disk{root: root}).sync(); err != nil {
		return "", err
	}
	if err = root.Remove(name); err != nil {
		return "", err
	}
	if err = (&Disk{root: root}).sync(); err != nil {
		return "", err
	}
	return readIdentity(root)
}
func (d *Disk) Identity() string { return d.identity }
func (d *Disk) CheckIdentity() error {
	current, err := readIdentity(d.root)
	if err != nil || current != d.identity {
		return ErrStorageIdentity
	}
	return nil
}
func (s *Service) checkUploadStorage(u *store.UploadSession) error {
	if s.Disk == nil || u.StorageID == "" || u.StorageID != s.Disk.Identity() {
		return ErrStorageIdentity
	}
	return s.Disk.CheckIdentity()
}
