//go:build windows

package durablefs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

const fixtureVolumePath = `\\?\Volume{00000000-0000-0000-0000-000000000001}\freightctl-directory`

type directoryFixture struct {
	before, opened         directoryInformation
	returned               windows.Handle
	path                   string
	infoErr, pathErr       error
	openedInfoErr          error
	openErr, flushErr      error
	closeErr               error
	querySize, writtenSize uint32
	opens, flushes, closes int
}

func newDirectoryFixture() *directoryFixture {
	info := directoryInformation{attributes: windows.FILE_ATTRIBUTE_DIRECTORY,
		identity: fileIdentity{VolumeSerialNumber: 91, FileID: [16]byte{23}}}
	return &directoryFixture{before: info, opened: info, path: fixtureVolumePath, returned: 22}
}

func (f *directoryFixture) operations(t *testing.T) directoryOperations {
	t.Helper()
	return directoryOperations{
		information: func(handle windows.Handle, result *directoryInformation) error {
			if f.infoErr != nil {
				return f.infoErr
			}
			switch handle {
			case 11:
				*result = f.before
			case 22:
				if f.openedInfoErr != nil {
					return f.openedInfoErr
				}
				*result = f.opened
			default:
				t.Fatalf("information used an unowned handle: %d", handle)
			}
			return nil
		},
		finalPath: func(handle windows.Handle, pointer *uint16, capacity, flags uint32) (uint32, error) {
			if handle != 11 || flags != normalizedVolumeGUID {
				t.Fatal("final path detached from original handle or normalized volume flag")
			}
			if f.pathErr != nil {
				return 0, f.pathErr
			}
			data, err := windows.UTF16FromString(f.path)
			if err != nil {
				t.Fatal(err)
			}
			if pointer == nil {
				if capacity != 0 {
					t.Fatal("path length query received a writable buffer")
				}
				if f.querySize != 0 {
					return f.querySize, nil
				}
				return uint32(len(data)), nil
			}
			if capacity < uint32(len(data)) || capacity > maximumDirectoryPath {
				t.Fatal("path fill has an invalid buffer bound")
			}
			copy(unsafe.Slice(pointer, int(capacity)), data)
			if f.writtenSize != 0 {
				return f.writtenSize, nil
			}
			return uint32(len(data) - 1), nil
		},
		open: func(pointer *uint16, access, share uint32, attributes *windows.SecurityAttributes, disposition, flags uint32, template windows.Handle) (windows.Handle, error) {
			f.opens++
			if windows.UTF16PtrToString(pointer) != f.path || access != windows.GENERIC_READ|windows.GENERIC_WRITE ||
				share != windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE || attributes != nil ||
				disposition != windows.OPEN_EXISTING || template != 0 ||
				flags != windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_WRITE_THROUGH {
				t.Fatal("directory open changed object, rights, reparse guard or creation policy")
			}
			if f.openErr != nil {
				return windows.InvalidHandle, f.openErr
			}
			return f.returned, nil
		},
		flush: func(handle windows.Handle) error {
			if handle != 22 {
				t.Fatal("flush used the original or an unowned handle")
			}
			f.flushes++
			return f.flushErr
		},
		close: func(handle windows.Handle) error {
			if handle != 22 {
				t.Fatal("close consumed the original or an unowned handle")
			}
			f.closes++
			return f.closeErr
		},
	}
}

func TestWindowsDirectoryAdapterRequiresSameObjectBeforeFlush(t *testing.T) {
	for _, change := range []func(*directoryFixture){
		func(f *directoryFixture) { f.opened.identity.VolumeSerialNumber++ },
		func(f *directoryFixture) { f.opened.identity.FileID[0]++ },
		func(f *directoryFixture) { f.opened.identity.FileID[15]++ },
		func(f *directoryFixture) { f.opened.attributes |= windows.FILE_ATTRIBUTE_REPARSE_POINT },
		func(f *directoryFixture) { f.opened.attributes = windows.FILE_ATTRIBUTE_NORMAL },
	} {
		f := newDirectoryFixture()
		change(f)
		if err := syncDirectoryHandle(11, f.operations(t)); !errors.Is(err, ErrDirectoryIdentity) || f.opens != 1 || f.flushes != 0 || f.closes != 1 {
			t.Fatal("changed/reparse/non-directory target reached flush or leaked handle", err, f)
		}
	}
}

func TestWindowsDirectoryAdapterRefusesUnprovableOriginalOrUnboundedPath(t *testing.T) {
	for _, change := range []func(*directoryFixture){
		func(f *directoryFixture) { f.before.identity.VolumeSerialNumber = 0 },
		func(f *directoryFixture) { f.before.identity.FileID = [16]byte{} },
		func(f *directoryFixture) { f.before.attributes |= windows.FILE_ATTRIBUTE_REPARSE_POINT },
		func(f *directoryFixture) { f.querySize = maximumDirectoryPath },
		func(f *directoryFixture) { f.writtenSize = maximumDirectoryPath },
		func(f *directoryFixture) { f.path = `C:\untrusted-directory-name` },
	} {
		f := newDirectoryFixture()
		change(f)
		if err := syncDirectoryHandle(11, f.operations(t)); !errors.Is(err, ErrDirectoryIdentity) || f.opens != 0 || f.flushes != 0 || f.closes != 0 {
			t.Fatal("unprovable input opened or flushed another object", err, f)
		}
	}
}

func TestWindowsDirectoryAdapterPreservesFlushAndCloseFailures(t *testing.T) {
	flushFailure, closeFailure := errors.New("flush refused"), errors.New("close refused")
	f := newDirectoryFixture()
	f.flushErr, f.closeErr = flushFailure, closeFailure
	if err := syncDirectoryHandle(11, f.operations(t)); !errors.Is(err, flushFailure) || !errors.Is(err, closeFailure) || f.flushes != 1 || f.closes != 1 {
		t.Fatal("original persistence or cleanup failure was hidden", err)
	}
	f = newDirectoryFixture()
	f.openedInfoErr = flushFailure
	if err := syncDirectoryHandle(11, f.operations(t)); !errors.Is(err, flushFailure) || f.flushes != 0 || f.closes != 1 {
		t.Fatal("failed new-handle identity query reached flush or leaked handle", err)
	}
	for _, field := range []string{"information", "path", "open"} {
		f = newDirectoryFixture()
		switch field {
		case "information":
			f.infoErr = flushFailure
		case "path":
			f.pathErr = flushFailure
		case "open":
			f.openErr = flushFailure
		}
		if err := syncDirectoryHandle(11, f.operations(t)); !errors.Is(err, flushFailure) || f.flushes != 0 || f.closes != 0 {
			t.Fatal("failed prerequisite reached flush or closed original handle", field, err)
		}
	}
}

func TestWindowsDirectoryAdapterNeverConsumesOriginalOrInvalidReturnedHandle(t *testing.T) {
	for _, handle := range []windows.Handle{0, windows.InvalidHandle, 11} {
		f := newDirectoryFixture()
		f.returned = handle
		if err := syncDirectoryHandle(11, f.operations(t)); !errors.Is(err, ErrDirectoryIdentity) || f.flushes != 0 || f.closes != 0 {
			t.Fatal("invalid returned handle reached flush or consumed original", err)
		}
	}
}

func nativeDirectory(t *testing.T, path string) *os.File {
	t.Helper()
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(pointer, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(handle), "untrusted-label-is-not-authority")
	if file == nil {
		windows.CloseHandle(handle)
		t.Fatal("cannot wrap exact native directory handle")
	}
	t.Cleanup(func() { file.Close() })
	return file
}

func TestWindowsNativeDirectoryUsesHandleAfterRename(t *testing.T) {
	parent := t.TempDir()
	path, renamed := filepath.Join(parent, "freightctl-original"), filepath.Join(parent, "freightctl-renamed")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	file := nativeDirectory(t, path)
	if err := os.Rename(path, renamed); err != nil {
		t.Fatal("owned directory rename required for native identity proof", err)
	}
	if err := SyncDirectory(file); err != nil {
		t.Fatal("sync used a stale File.Name instead of the original handle", err)
	}
	if _, err := file.Stat(); err != nil {
		t.Fatal("native sync consumed caller's read handle", err)
	}
}

func TestWindowsNativeDirectorySwapNeverFlushesReplacement(t *testing.T) {
	for _, reparse := range []bool{false, true} {
		t.Run(map[bool]string{false: "directory", true: "reparse"}[reparse], func(t *testing.T) {
			parent := t.TempDir()
			path, saved, other := filepath.Join(parent, "freightctl-root"), filepath.Join(parent, "freightctl-saved"), filepath.Join(parent, "freightctl-other")
			for _, name := range []string{path, other} {
				if err := os.Mkdir(name, 0700); err != nil {
					t.Fatal(err)
				}
			}
			file := nativeDirectory(t, path)
			operations := systemDirectoryOperations()
			open, flush := operations.open, operations.flush
			flushes := 0
			var swapErr error
			swapped := false
			operations.open = func(name *uint16, access, share uint32, attributes *windows.SecurityAttributes, disposition, flags uint32, template windows.Handle) (windows.Handle, error) {
				if err := os.Rename(path, saved); err != nil {
					swapErr = err
					return windows.InvalidHandle, err
				}
				var err error
				if reparse {
					err = os.Symlink(other, path)
				} else {
					err = os.Mkdir(path, 0700)
				}
				if err != nil {
					swapErr = err
					return windows.InvalidHandle, err
				}
				swapped = true
				return open(name, access, share, attributes, disposition, flags, template)
			}
			operations.flush = func(handle windows.Handle) error { flushes++; return flush(handle) }
			err := syncDirectoryWithOperations(file, operations)
			if swapErr != nil || !swapped {
				t.Fatal("actual native replacement fixture did not execute", swapErr, err)
			}
			if err == nil || (!reparse && !errors.Is(err, ErrDirectoryIdentity)) || flushes != 0 {
				t.Fatal("actual replacement reached flush or required native swap was unavailable", err, flushes)
			}
			if _, err := file.Stat(); err != nil {
				t.Fatal("rejected swap consumed caller's original handle", err)
			}
		})
	}
}
