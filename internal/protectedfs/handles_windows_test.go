//go:build windows

package protectedfs

import (
	"errors"
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
		{"inherited-ace", "D:(A;;FA;;;" + sid + ")", false},
		{"unprotected", "D:(A;;FA;;;" + sid + ")", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			directory := t.TempDir()
			if c.name == "inherited-ace" {
				installInheritableOwnerParentForTest(t, directory, sid)
			}
			path := filepath.Join(directory, "private")
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
				if readErr != nil || appliedACL == nil || appliedACL.AceCount < 1 || appliedACL.AceCount > 8 {
					t.Fatal("actual inherited-ACE fixture has no bounded DACL", readErr)
				}
				inherited := false
				for i := uint32(0); i < uint32(appliedACL.AceCount); i++ {
					var appliedACE *windows.ACCESS_ALLOWED_ACE
					if readErr = windows.GetAce(appliedACL, i, &appliedACE); readErr != nil || appliedACE == nil {
						t.Fatal("cannot read actual inherited ACE", readErr)
					}
					inherited = inherited || appliedACE.Header.AceFlags&windows.INHERITED_ACE != 0
				}
				runtime.KeepAlive(applied)
				if !inherited {
					t.Fatal("inherited-ACE precondition absent on actual held object;refusal remains unqualified")
				}
			}
			if ValidateFile(f) == nil {
				t.Fatal("changed actual DACL accepted on original held handle")
			}
		})
	}
}

// The observed setter normalized the supplied inherited flag. Establish actual
// inheritance from a task-owned parent instead of forging the child's bit.
func installInheritableOwnerParentForTest(t testing.TB, path, sid string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + sid + ")(A;OICIIO;FA;;;" + sid + ")")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		t.Fatal("inheritable parent fixture DACL absent", err)
	}
	// Open only this task-owned parent for the fixture mutation;children still
	// receive their own protected descriptor at creation.
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(name, windows.WRITE_DAC|windows.READ_CONTROL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatal(err)
	}
	original, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil || original == nil {
		windows.CloseHandle(h)
		t.Fatal("cannot preserve task-owned parent DACL", err)
	}
	control, _, err := original.Control()
	if err != nil {
		windows.CloseHandle(h)
		t.Fatal(err)
	}
	t.Cleanup(func() {
		originalACL, _, restoreErr := original.DACL()
		flags := windows.DACL_SECURITY_INFORMATION | windows.UNPROTECTED_DACL_SECURITY_INFORMATION
		if control&windows.SE_DACL_PROTECTED != 0 {
			flags = windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION
		}
		if restoreErr == nil {
			restoreErr = windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.SECURITY_INFORMATION(flags), nil, nil, originalACL, nil)
		}
		runtime.KeepAlive(original)
		if err := errors.Join(restoreErr, windows.CloseHandle(h)); err != nil {
			t.Error("task-owned parent DACL restoration failed", err)
		}
	})
	if err = windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	runtime.KeepAlive(sd)
}

func TestWindowsDescriptorRefusesInheritedACEEvenInProtectedOwnerOnlyDACL(t *testing.T) {
	user, err := runtimeSID()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.String()
	for _, inherited := range []bool{false, true} {
		flags := ""
		if inherited {
			flags = "ID"
		}
		sd, err := windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;" + flags + ";FA;;;" + sid + ")")
		if err != nil {
			t.Fatal(err)
		}
		acl, _, err := sd.DACL()
		if err != nil || acl == nil || acl.AceCount != 1 {
			t.Fatal("parser fixture DACL absent", err)
		}
		var ace *windows.ACCESS_ALLOWED_ACE
		if err = windows.GetAce(acl, 0, &ace); err != nil || ace == nil || (ace.Header.AceFlags&windows.INHERITED_ACE != 0) != inherited {
			t.Fatal("parser fixture inheritance absent", err)
		}
		// Check the real parser used after GetSecurityInfo,including a protected
		// owner-only descriptor so no other privacy failure masks ACE refusal.
		err = inspectDescriptor(sd, privateDescriptor)
		runtime.KeepAlive(sd)
		if inherited && !errors.Is(err, ErrPrivacy) || !inherited && err != nil {
			t.Fatal("actual descriptor parser confused explicit and inherited access", err)
		}
	}
}
