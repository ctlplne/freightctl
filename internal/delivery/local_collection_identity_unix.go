//go:build darwin || linux

package delivery

import (
	"encoding/binary"
	"os"
	"runtime"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"golang.org/x/sys/unix"
)

func localCollectionRootIdentity(f *os.File) (string, error) {
	connection, err := f.SyscallConn()
	if err != nil {
		return "", err
	}
	var info unix.Stat_t
	var inspectErr error
	err = connection.Control(func(fd uintptr) { inspectErr = unix.Fstat(int(fd), &info) })
	if err != nil {
		return "", err
	}
	if inspectErr != nil {
		return "", inspectErr
	}
	if info.Mode&unix.S_IFMT != unix.S_IFDIR || info.Ino == 0 {
		return "", ErrLocalSource
	}
	var identity [16]byte
	binary.LittleEndian.PutUint64(identity[:8], uint64(info.Dev))
	binary.LittleEndian.PutUint64(identity[8:], uint64(info.Ino))
	return secure.Digest(append([]byte("freightctl-local-root-v1:"+runtime.GOOS+":"), identity[:]...)), nil
}
