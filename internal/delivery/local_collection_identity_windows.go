//go:build windows

package delivery

import (
	"encoding/binary"
	"errors"
	"os"
	"unsafe"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"golang.org/x/sys/windows"
)

func localCollectionRootIdentity(f *os.File) (string, error) {
	connection, err := f.SyscallConn()
	if err != nil {
		return "", err
	}
	var identity struct {
		Volume uint64
		ID     [16]byte
	}
	var inspectErr error
	err = connection.Control(func(fd uintptr) {
		h := windows.Handle(fd)
		var info windows.ByHandleFileInformation
		if inspectErr = windows.GetFileInformationByHandle(h, &info); inspectErr != nil {
			return
		}
		if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			inspectErr = ErrLocalSource
			return
		}
		inspectErr = windows.GetFileInformationByHandleEx(h, windows.FileIdInfo, (*byte)(unsafe.Pointer(&identity)), uint32(unsafe.Sizeof(identity)))
	})
	if err = errors.Join(err, inspectErr); err != nil {
		return "", err
	}
	if identity.ID == [16]byte{} {
		return "", ErrLocalSource
	}
	var wire [24]byte
	binary.LittleEndian.PutUint64(wire[:8], identity.Volume)
	copy(wire[8:], identity.ID[:])
	return secure.Digest(append([]byte("freightctl-local-root-v1:windows:"), wire[:]...)), nil
}
