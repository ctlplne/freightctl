//go:build windows

package crypto

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"golang.org/x/sys/windows"
)

// chmod does not add a Windows read ACE. Change the actual task-owned DACL;
// the same assertion must refuse an actual grant to Everyone on Windows.
func broadenPrivateFileForTest(t *testing.T, path string) {
	setReferenceAccessForTest(t, path, 0644)
}

func setReferenceAccessForTest(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	grant := ""
	switch mode {
	case 0600:
	case 0644:
		grant = "(A;;FR;;;WD)"
	case 0666:
		grant = "(A;;FRFW;;;WD)"
	default:
		t.Fatal("unsupported reference permission fixture")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.User.Sid.String()
	sd, err := windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;;FA;;;" + sid + ")" + grant)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(pointer, windows.WRITE_DAC|windows.READ_CONTROL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatal(err)
	}
	err = windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
	runtime.KeepAlive(sd)
	closeErr := windows.CloseHandle(h)
	if err != nil {
		t.Fatal(err)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
}

func TestWindowsSecretReferenceUsesActualProtectedDACLAndRefusesNewReadGrant(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owner-only.token")
	if err := WriteToken(path); err != nil {
		t.Fatal(err)
	}
	s, err := ReadSecret(path, 64)
	if err != nil {
		t.Fatal("new protected token unreadable", err)
	}
	if len(s.Bytes) != 64 {
		t.Fatal("token length changed")
	}
	s.Close()
	broadenPrivateFileForTest(t, path)
	if s, err = ReadSecret(path, 64); err == nil {
		s.Close()
		t.Fatal("Everyone read ACE accepted for a secret")
	}
}
