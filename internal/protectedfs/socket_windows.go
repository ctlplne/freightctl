//go:build windows

package protectedfs

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// AF_UNIX is a specific native socket reparse tag,not permission to follow an
// arbitrary reparse point. The pinned Go platform also uses this exact tag to
// distinguish sockets from links and other filesystem extensions.
const unixSocketReparseTag = 0x80000023

func nativeSocketPrivacyFailure(stage string, err error) error {
	// Fixed internal stages only;never expose a SID,path or descriptor contents.
	return fmt.Errorf("native private socket %s: %w", stage, errors.Join(ErrPrivacy, err))
}

func platformSocket(path string, observed os.FileInfo) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	// Attribute-only handles do not participate in native share-access checks.
	// Read-data access pins this exact reparse object against delete/rename;the
	// object remains metadata-only here and is never read as a byte stream.
	h, err := windows.CreateFile(name, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES|windows.FILE_READ_DATA,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(h), path)
	if f == nil {
		return nil, errors.Join(ErrPrivacy, windows.CloseHandle(h))
	}
	current, err := f.Stat()
	if err != nil || !os.SameFile(observed, current) {
		return nil, errors.Join(nativeSocketPrivacyFailure("physical-identity", err), f.Close())
	}
	if err = platformSocketPrivacy(f, current); err != nil {
		return nil, errors.Join(err, f.Close())
	}
	return f, nil
}

func platformSocketPrivacy(f *os.File, observed os.FileInfo) error {
	if f == nil {
		return ErrPrivacy
	}
	current, err := f.Stat()
	if err != nil || !os.SameFile(current, observed) || current.Mode()&os.ModeSocket == 0 {
		return nativeSocketPrivacyFailure("held-object-identity", err)
	}
	connection, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var operationErr error
	err = connection.Control(func(fd uintptr) {
		h := windows.Handle(fd)
		kind, e := windows.GetFileType(h)
		if e != nil || kind != windows.FILE_TYPE_DISK {
			operationErr = nativeSocketPrivacyFailure("file-type", e)
			return
		}
		var tag struct{ Attributes, ReparseTag uint32 }
		e = windows.GetFileInformationByHandleEx(h, windows.FileAttributeTagInfo, (*byte)(unsafe.Pointer(&tag)), uint32(unsafe.Sizeof(tag)))
		if e != nil || tag.Attributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 || tag.Attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0 || tag.ReparseTag != unixSocketReparseTag {
			operationErr = nativeSocketPrivacyFailure("af-unix-tag", e)
			return
		}
		sd, e := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if e != nil {
			operationErr = e
			return
		}
		if e = inspectDescriptor(sd, privateDescriptor); e != nil {
			operationErr = nativeSocketPrivacyFailure("security-descriptor", e)
		}
		runtime.KeepAlive(sd)
	})
	return errors.Join(err, operationErr)
}
