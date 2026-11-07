//go:build windows

package protectedfs

import (
	"errors"
	"os"
	"runtime"
	"strconv"

	"golang.org/x/sys/windows"
)

// Go Root.Link opens the original with FILE_WRITE_ATTRIBUTES. This metadata
// right grants no data/append,ACL/owner,delete or execution permission.
const sealedAccess = uint32(windows.FILE_GENERIC_READ | windows.FILE_WRITE_ATTRIBUTES)

func platformProtection(f *os.File, _ os.FileInfo) (ProtectionState, error) {
	connection, err := f.SyscallConn()
	if err != nil {
		return 0, err
	}
	var state ProtectionState
	var inspectErr error
	err = connection.Control(func(fd uintptr) {
		inspectErr = inspectHandle(windows.Handle(fd), false, func(owner, user string, present, protected bool, entries []accessEntry) bool {
			readable := uint32(windows.FILE_READ_DATA | windows.GENERIC_READ | windows.GENERIC_ALL)
			allowed := sealedAccess | windows.GENERIC_READ
			if sealedDescriptor(owner, user, present, protected, entries, allowed, readable) {
				state = PrivateSealed
				return true
			}
			writable := uint32(windows.FILE_WRITE_DATA | windows.GENERIC_WRITE | windows.GENERIC_ALL)
			if writableDescriptor(owner, user, present, protected, entries, readable, writable) {
				state = PrivateWritable
				return true
			}
			return false
		})
	})
	if err = errors.Join(err, inspectErr); err != nil {
		return 0, err
	}
	return state, nil
}

func platformSeal(f *os.File) error {
	user, err := runtimeSID()
	if err != nil {
		return err
	}
	sid := user.String()
	sd, err := windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;;0x" + strconv.FormatUint(uint64(sealedAccess), 16) + ";;;" + sid + ")")
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return ErrPrivacy
	}
	connection, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var sealErr error
	err = connection.Control(func(fd uintptr) {
		h := windows.Handle(fd)
		if sealErr = privateHandle(h, false); sealErr != nil {
			return
		}
		sealErr = windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
			nil, nil, acl, nil)
	})
	runtime.KeepAlive(sd)
	return errors.Join(err, sealErr)
}
