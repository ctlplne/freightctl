//go:build windows

package protectedfs

import (
	"errors"
	"os"
	"runtime"
	"testing"

	"golang.org/x/sys/windows"
)

func setSocketFixturePrivacy(t *testing.T, path string, broad bool) {
	t.Helper()
	sid, err := runtimeSID()
	if err != nil {
		t.Fatal(err)
	}
	text := "D:P(A;;FA;;;" + sid.String() + ")"
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
	h, err := windows.CreateFile(name, windows.READ_CONTROL|windows.WRITE_DAC, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	err = windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
	runtime.KeepAlive(sd)
	if err != nil {
		t.Fatal(err)
	}
}

func TestWindowsPrivateSocketPinsTheExactNativeName(t *testing.T) {
	path := socketFixture(t)
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := OpenPrivateSocket(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ref.Close()
	if err = os.Rename(path, path+"-replacement"); !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		t.Fatal("held native socket name was not pinned", err)
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) || ref.Validate() != nil {
		t.Fatal("refused replacement changed the pinned socket", err)
	}
}
