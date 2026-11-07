//go:build windows

package protectedfs

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func platformDirectory(path string) (*os.File, error) {
	leaf := filepath.Base(path)
	if leaf == "" || leaf == "." || leaf == ".." || strings.ContainsAny(leaf, ":/\\\x00") || strings.TrimRight(leaf, " .") != leaf || reservedLeaf(leaf) {
		return nil, ErrPrivacy
	}
	parent, err := os.Open(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	return createRelative(parent, leaf, path, true)
}

func platformCreateAt(root *os.Root, name string) (*os.File, error) {
	directory, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	return createRelative(directory, name, name, false)
}

func createRelative(parent *os.File, name, displayName string, directory bool) (*os.File, error) {
	connection, err := parent.SyscallConn()
	if err != nil {
		return nil, err
	}
	sd, err := ownerDescriptor()
	if err != nil {
		return nil, err
	}
	leaf, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return nil, err
	}
	var handle windows.Handle
	var createErr error
	err = connection.Control(func(fd uintptr) {
		if directory {
			var info windows.ByHandleFileInformation
			if createErr = windows.GetFileInformationByHandle(windows.Handle(fd), &info); createErr != nil {
				return
			}
			if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
				createErr = ErrPrivacy
				return
			}
		} else {
			if createErr = privateHandle(windows.Handle(fd), true); createErr != nil {
				return
			}
		}
		attributes := windows.OBJECT_ATTRIBUTES{
			Length: uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})), RootDirectory: windows.Handle(fd),
			ObjectName: leaf, Attributes: windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE,
			SecurityDescriptor: sd,
		}
		var status windows.IO_STATUS_BLOCK
		options := uint32(windows.FILE_NON_DIRECTORY_FILE | windows.FILE_OPEN_REPARSE_POINT | windows.FILE_SYNCHRONOUS_IO_NONALERT)
		share := uint32(windows.FILE_SHARE_READ)
		if directory {
			options = windows.FILE_DIRECTORY_FILE | windows.FILE_OPEN_REPARSE_POINT | windows.FILE_SYNCHRONOUS_IO_NONALERT
			share |= windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE
		}
		createErr = windows.NtCreateFile(&handle,
			windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE|windows.WRITE_DAC,
			&attributes, &status, nil, windows.FILE_ATTRIBUTE_NORMAL,
			share, windows.FILE_CREATE, options,
			0, 0)
		var native windows.NTStatus
		if errors.As(createErr, &native) {
			createErr = native.Errno()
		}
	})
	runtime.KeepAlive(sd)
	runtime.KeepAlive(leaf)
	if err = errors.Join(err, createErr); err != nil {
		if handle != 0 && handle != windows.InvalidHandle {
			err = errors.Join(err, windows.CloseHandle(handle))
		}
		return nil, err
	}
	if handle == 0 || handle == windows.InvalidHandle {
		return nil, ErrPrivacy
	}
	f := os.NewFile(uintptr(handle), displayName)
	if f == nil {
		return nil, errors.Join(ErrPrivacy, windows.CloseHandle(handle))
	}
	return f, nil
}
