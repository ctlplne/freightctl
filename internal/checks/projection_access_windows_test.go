//go:build windows

package checks

import (
	"os"
	"runtime"
	"testing"

	"github.com/ctlplne/freightctl/internal/protectedfs"
	"golang.org/x/sys/windows"
)

// The host owner can change its own ACL just as a Unix owner can chmod. Exercise
// corruption of the same physical sealed object;do not replace it or relax the
// product's byte-write refusal for ordinary opened handles.
func rewriteSealedProjectionForTest(t testing.TB, path string, body []byte) {
	t.Helper()
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(name, windows.WRITE_DAC|windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(h), path)
	if f == nil {
		windows.CloseHandle(h)
		t.Fatal("cannot hold exact tamper fixture")
	}
	defer f.Close()
	state, err := protectedfs.Protection(f)
	if err != nil || state != protectedfs.PrivateSealed {
		t.Fatal("tamper fixture was not originally private sealed bytes", err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		t.Fatal("tamper fixture DACL absent", err)
	}
	if err = windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	runtime.KeepAlive(sd)
	if err = os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	if err = protectedfs.SealReadOnly(f); err != nil {
		t.Fatal(err)
	}
}
