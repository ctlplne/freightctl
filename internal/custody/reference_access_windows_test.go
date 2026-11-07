//go:build windows

package custody

import (
	"runtime"
	"testing"

	"golang.org/x/sys/windows"
)

func setCustodyAccessForTest(t testing.TB, path string, writable bool) {
	t.Helper()
	rights := "0x120189" // FILE_GENERIC_READ|FILE_WRITE_ATTRIBUTES;no byte writes.
	if writable {
		rights = "FA"
	}
	setCustodyDescriptorForTest(t, path, rights, false)
}

func makeBroadRootForTest(t testing.TB, path string) {
	t.Helper()
	setCustodyDescriptorForTest(t, path, "FA", true)
}

func setCustodyDescriptorForTest(t testing.TB, path, rights string, broad bool) {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.User.Sid.String()
	sddl := "D:P(A;;" + rights + ";;;" + sid + ")"
	if broad {
		sddl += "(A;;FR;;;WD)"
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		t.Fatal("fixture DACL absent", err)
	}
	h := custodySecurityHandleForTest(t, path, windows.WRITE_DAC|windows.READ_CONTROL)
	defer windows.CloseHandle(h)
	if err = windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	runtime.KeepAlive(sd)
}

func custodySecurityHandleForTest(t testing.TB, path string, rights uint32) windows.Handle {
	t.Helper()
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(name, rights, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func rootProtectionSnapshotForTest(t testing.TB, path string) string {
	t.Helper()
	h := custodySecurityHandleForTest(t, path, windows.READ_CONTROL)
	defer windows.CloseHandle(h)
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || sd == nil {
		t.Fatal("fixture descriptor absent", err)
	}
	return sd.String()
}
