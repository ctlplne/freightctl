//go:build windows

package scanner

import (
	"runtime"
	"testing"

	"golang.org/x/sys/windows"
)

func setScannerFixtureSocketPrivacy(t *testing.T, path string, broad bool) {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	text := "D:P(A;;FA;;;" + user.User.Sid.String() + ")"
	if broad {
		text += "(A;;FR;;;WD)"
	}
	sd, err := windows.SecurityDescriptorFromString(text)
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(name, windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	err = windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, user.User.Sid, nil, acl, nil)
	runtime.KeepAlive(sd)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal("scanner fixture socket owner readback failed", err)
	}
	owner, _, err := actual.Owner()
	if err != nil || owner == nil || !owner.Equals(user.User.Sid) {
		t.Fatal("scanner fixture socket did not install current runtime owner", err)
	}
	runtime.KeepAlive(actual)
}
