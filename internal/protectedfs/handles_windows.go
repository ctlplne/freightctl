//go:build windows

package protectedfs

import (
	"errors"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

func runtimeSID() (*windows.SID, error) {
	token, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return token.User.Sid.Copy()
}

func ownerDescriptor() (*windows.SECURITY_DESCRIPTOR, error) {
	sid, err := runtimeSID()
	if err != nil {
		return nil, err
	}
	text := sid.String()
	return windows.SecurityDescriptorFromString("O:" + text + "D:P(A;;FA;;;" + text + ")")
}

func platformCreate(path string) (*os.File, error) {
	sd, err := ownerDescriptor()
	if err != nil {
		return nil, err
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL, windows.FILE_SHARE_READ, &sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	runtime.KeepAlive(sd)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(h), path)
	if f == nil {
		windows.CloseHandle(h)
		return nil, ErrPrivacy
	}
	return f, nil
}

func platformPrivacy(f *os.File, _ os.FileInfo, directory bool) error {
	return platformAccess(f, directory, false)
}

func platformPublic(f *os.File, _ os.FileInfo) error {
	return platformAccess(f, false, true)
}

func platformAccess(f *os.File, directory, public bool) error {
	connection, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var result error
	err = connection.Control(func(fd uintptr) { result = accessHandle(windows.Handle(fd), directory, public) })
	return errors.Join(err, result)
}

func privateHandle(h windows.Handle, directory bool) error {
	return accessHandle(h, directory, false)
}

func accessHandle(h windows.Handle, directory, public bool) error {
	kind, err := windows.GetFileType(h)
	if err != nil {
		return err
	}
	if kind != windows.FILE_TYPE_DISK {
		return ErrPrivacy
	}
	var info windows.ByHandleFileInformation
	if err = windows.GetFileInformationByHandle(h, &info); err != nil {
		return err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || (info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory {
		return ErrPrivacy
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	if sd == nil || !sd.IsValid() {
		return ErrPrivacy
	}
	defer runtime.KeepAlive(sd)
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !owner.IsValid() {
		return ErrPrivacy
	}
	control, _, err := sd.Control()
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil || acl.AceCount == 0 || acl.AceCount > 256 {
		return ErrPrivacy
	}
	user, err := runtimeSID()
	if err != nil {
		return err
	}
	entries := make([]accessEntry, 0, acl.AceCount)
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err = windows.GetAce(acl, i, &ace); err != nil {
			return err
		}
		if ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 || ace.Header.AceSize < 16 {
			return ErrPrivacy
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() || sid.Len() > int(ace.Header.AceSize)-int(unsafe.Offsetof(ace.SidStart)) {
			return ErrPrivacy
		}
		entries = append(entries, accessEntry{principal: sid.String(), allow: true, mask: uint32(ace.Mask)})
	}
	present, protected := control&windows.SE_DACL_PRESENT != 0, control&windows.SE_DACL_PROTECTED != 0
	accepted := privateDescriptor(owner.String(), user.String(), present, protected, entries)
	if public {
		readMask := uint32(windows.GENERIC_READ | windows.GENERIC_EXECUTE | windows.FILE_GENERIC_READ | windows.FILE_GENERIC_EXECUTE)
		accepted = publicDescriptor(owner.String(), user.String(), present, protected, entries, readMask)
	}
	if !accepted {
		return ErrPrivacy
	}
	return nil
}
