//go:build windows

package protectedfs

import (
	"path/filepath"
	"runtime"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsHeldFilePrivacyRefusesBroadNullInheritedAndUnprotectedDACL(t *testing.T) {
	user, err := runtimeSID()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.String()
	for _, c := range []struct {
		name, sddl string
		protected  bool
	}{
		{"everyone", "D:P(A;;FA;;;" + sid + ")(A;;FR;;;WD)", true},
		{"null", "D:NO_ACCESS_CONTROL", true},
		{"empty", "D:P", true},
		{"inherited-ace", "D:P(A;ID;FA;;;" + sid + ")", true},
		{"unprotected", "D:(A;;FA;;;" + sid + ")", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "private")
			f, err := CreateExclusive(path)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			sd, err := windows.SecurityDescriptorFromString(c.sddl)
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
			original, err := ownerDescriptor()
			if err != nil {
				windows.CloseHandle(h)
				t.Fatal(err)
			}
			defer func() {
				originalACL, _, restoreErr := original.DACL()
				if restoreErr == nil {
					restoreErr = windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, originalACL, nil)
				}
				runtime.KeepAlive(original)
				closeErr := windows.CloseHandle(h)
				if restoreErr != nil {
					t.Error("task-owned test ACL restoration failed", restoreErr)
				}
				if closeErr != nil {
					t.Error(closeErr)
				}
			}()
			flags := windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION
			if !c.protected {
				flags = windows.DACL_SECURITY_INFORMATION | windows.UNPROTECTED_DACL_SECURITY_INFORMATION
			}
			err = windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.SECURITY_INFORMATION(flags), nil, nil, dacl, nil)
			runtime.KeepAlive(sd)
			if err != nil {
				t.Fatal(err)
			}
			if c.name == "inherited-ace" {
				// A successful setter call does not establish that Windows kept
				// the supplied inheritance flag. Read the held object's actual
				// DACL before drawing any conclusion about the refusal check.
				applied, readErr := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
				if readErr != nil || applied == nil {
					t.Fatal("cannot read actual inherited-ACE precondition", readErr)
				}
				appliedACL, _, readErr := applied.DACL()
				if readErr != nil || appliedACL == nil || appliedACL.AceCount != 1 {
					t.Fatal("actual inherited-ACE fixture has no exact one-entry DACL", readErr)
				}
				var appliedACE *windows.ACCESS_ALLOWED_ACE
				if readErr = windows.GetAce(appliedACL, 0, &appliedACE); readErr != nil || appliedACE == nil {
					t.Fatal("cannot read actual inherited ACE", readErr)
				}
				flags := appliedACE.Header.AceFlags
				runtime.KeepAlive(applied)
				if flags&windows.INHERITED_ACE == 0 {
					t.Fatalf("inherited-ACE precondition absent on actual held object: ACE flags=0x%02x;refusal remains unqualified", flags)
				}
			}
			if ValidateFile(f) == nil {
				t.Fatal("changed actual DACL accepted on original held handle")
			}
		})
	}
}
