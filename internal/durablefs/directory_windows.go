//go:build windows

package durablefs

import (
	"errors"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const maximumDirectoryPath = 32768 // UTF-16 units including the terminator.
const normalizedVolumeGUID = 1     // FILE_NAME_NORMALIZED | VOLUME_NAME_GUID.

type directoryOperations struct {
	information func(windows.Handle, *directoryInformation) error
	finalPath   func(windows.Handle, *uint16, uint32, uint32) (uint32, error)
	open        func(*uint16, uint32, uint32, *windows.SecurityAttributes, uint32, uint32, windows.Handle) (windows.Handle, error)
	flush       func(windows.Handle) error
	close       func(windows.Handle) error
}

// FILE_ID_INFO has a64bit volume serial and128bit file ID. The legacy64bit
// BY_HANDLE_FILE_INFORMATION index is not a unique identity on every filesystem.
type fileIdentity struct {
	VolumeSerialNumber uint64
	FileID             [16]byte
}

type directoryInformation struct {
	attributes uint32
	identity   fileIdentity
}

func readDirectoryInformation(handle windows.Handle, result *directoryInformation) error {
	var attributes windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &attributes); err != nil {
		return err
	}
	var identity fileIdentity
	if err := windows.GetFileInformationByHandleEx(handle, windows.FileIdInfo,
		(*byte)(unsafe.Pointer(&identity)), uint32(unsafe.Sizeof(identity))); err != nil {
		return err
	}
	result.attributes, result.identity = attributes.FileAttributes, identity
	return nil
}

func systemDirectoryOperations() directoryOperations {
	return directoryOperations{
		information: readDirectoryInformation,
		finalPath:   windows.GetFinalPathNameByHandle,
		open:        windows.CreateFile,
		flush:       windows.FlushFileBuffers,
		close:       windows.CloseHandle,
	}
}

func syncDirectory(directory *os.File) error {
	return syncDirectoryWithOperations(directory, systemDirectoryOperations())
}

func syncDirectoryWithOperations(directory *os.File, operations directoryOperations) error {
	connection, err := directory.SyscallConn()
	if err != nil {
		return err
	}
	var operationErr error
	// RawConn.Control keeps the Go file descriptor valid across all identity,
	// open and flush operations, even if another goroutine attempts Close.
	err = connection.Control(func(fd uintptr) {
		operationErr = syncDirectoryHandle(windows.Handle(fd), operations)
	})
	return errors.Join(err, operationErr)
}

func directoryIdentity(info directoryInformation) bool {
	return info.attributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 &&
		info.attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0 &&
		info.identity.VolumeSerialNumber != 0 && info.identity.FileID != [16]byte{}
}

func syncDirectoryHandle(original windows.Handle, operations directoryOperations) (result error) {
	var before directoryInformation
	if err := operations.information(original, &before); err != nil {
		return err
	}
	if !directoryIdentity(before) {
		return ErrDirectoryIdentity
	}
	// File.Name is caller-controlled and can become stale after a rename. Resolve
	// a bounded normalized volume path from the held original handle instead.
	size, err := operations.finalPath(original, nil, 0, normalizedVolumeGUID)
	if err != nil {
		return err
	}
	if size == 0 || size >= maximumDirectoryPath {
		return ErrDirectoryIdentity
	}
	buffer := make([]uint16, size+1)
	written, err := operations.finalPath(original, &buffer[0], uint32(len(buffer)), normalizedVolumeGUID)
	if err != nil {
		return err
	}
	if written == 0 || written >= uint32(len(buffer)) {
		return ErrDirectoryIdentity
	}
	for _, unit := range buffer[:written] {
		if unit == 0 {
			return ErrDirectoryIdentity
		}
	}
	name := windows.UTF16ToString(buffer[:written])
	if !strings.HasPrefix(name, `\\?\Volume{`) || !strings.Contains(name, `}\`) {
		return ErrDirectoryIdentity
	}
	pointer, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	// An ordinary Go directory handle is read-only on Windows. Open a temporary
	// writable handle; never expose that stronger handle to callers.
	handle, err := operations.open(pointer, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_WRITE_THROUGH, 0)
	if err != nil {
		return err
	}
	if handle == original || handle == 0 || handle == windows.InvalidHandle {
		return ErrDirectoryIdentity
	}
	defer func() { result = errors.Join(result, operations.close(handle)) }()
	var opened directoryInformation
	if err = operations.information(handle, &opened); err != nil {
		return err
	}
	if !directoryIdentity(opened) || before.identity != opened.identity {
		return ErrDirectoryIdentity
	}
	// A path may have been replaced while opening. Only the object matching the
	// still-held original identity may be flushed; a replacement is never used.
	return operations.flush(handle)
}
