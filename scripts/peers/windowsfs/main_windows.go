//go:build windows

// Native Windows API observations only. No production permission or durability
// guard is changed, and no successful flush is treated as power-loss evidence.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const unknown = ^uint32(0)
const share = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE

type operation struct {
	Attempted bool   `json:"attempted"`
	Code      uint32 `json:"code"`
}
type aclObservation struct {
	Queried            bool   `json:"queried"`
	Code               uint32 `json:"code"`
	Null               bool   `json:"null"`
	Protected          bool   `json:"protected"`
	OwnerCurrent       bool   `json:"owner_current"`
	ExpectedDescriptor bool   `json:"expected_descriptor"`
	ACECount           uint16 `json:"ace_count"`
}
type observation struct {
	Case        string         `json:"case"`
	Open        operation      `json:"open"`
	Write       operation      `json:"write"`
	Flush       operation      `json:"flush"`
	Close       operation      `json:"close"`
	ParentClose operation      `json:"parent_close"`
	Readback    bool           `json:"readback"`
	Mode        uint32         `json:"mode_bits"`
	ACL         aclObservation `json:"acl"`
}
type report struct {
	Schema        int            `json:"schema_version"`
	Kind          string         `json:"kind"`
	State         string         `json:"state"`
	Source        string         `json:"source_commit"`
	System        string         `json:"system"`
	Architecture  string         `json:"architecture"`
	GoVersion     string         `json:"go_version"`
	Phase         string         `json:"phase"`
	Error         operation      `json:"error"`
	Elevated      bool           `json:"elevated"`
	Filesystem    string         `json:"filesystem"`
	DirectoryACL  aclObservation `json:"directory_acl"`
	Cases         []observation  `json:"cases"`
	Cleanup       operation      `json:"cleanup"`
	CleanupAbsent bool           `json:"cleanup_absent"`
	Qualified     bool           `json:"qualification_claim"`
}

func code(err error) uint32 {
	if err == nil {
		return 0
	}
	var value syscall.Errno
	if errors.As(err, &value) {
		return uint32(value)
	}
	return unknown
}
func op(err error) operation { return operation{true, code(err)} }
func inspect(handle windows.Handle, expected *windows.SECURITY_DESCRIPTOR, owner *windows.SID) aclObservation {
	r := aclObservation{Queried: true}
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		r.Code = code(err)
		return r
	}
	control, _, err := sd.Control()
	if err != nil {
		r.Code = code(err)
		return r
	}
	r.Protected = control&windows.SE_DACL_PROTECTED != 0
	actualOwner, _, err := sd.Owner()
	if err != nil {
		r.Code = code(err)
		return r
	}
	r.OwnerCurrent = actualOwner != nil && windows.EqualSid(actualOwner, owner)
	acl, _, err := sd.DACL()
	if err != nil {
		r.Code = code(err)
		return r
	}
	if acl == nil {
		r.Null = true
		return r
	}
	r.ACECount = acl.AceCount
	want, got := expected.String(), sd.String()
	r.ExpectedDescriptor = want != "" && got != "" && want == got
	return r
}
func fileCase(name, filename string, explicit bool, sd *windows.SECURITY_DESCRIPTOR, owner *windows.SID) (r observation) {
	r.Case = name
	var f *os.File
	var err error
	if explicit {
		pointer, e := windows.UTF16PtrFromString(filename)
		if e != nil {
			r.Open = op(e)
			return
		}
		sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
		handle, e := windows.CreateFile(pointer, windows.GENERIC_READ|windows.GENERIC_WRITE, share, &sa,
			windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_WRITE_THROUGH, 0)
		err = e
		if err == nil {
			f = os.NewFile(uintptr(handle), "owned-windows-probe")
		}
	} else {
		f, err = os.OpenFile(filename, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	}
	r.Open = op(err)
	if err != nil {
		return
	}
	defer func() { r.Close = op(f.Close()) }()
	r.ACL = inspect(windows.Handle(f.Fd()), sd, owner)
	if info, e := f.Stat(); e == nil {
		r.Mode = uint32(info.Mode().Perm())
	}
	payload := bytes.Repeat([]byte{'p'}, 512) // Public synthetic bytes, never a key or customer file.
	n, err := f.Write(payload)
	if err == nil && n != len(payload) {
		err = windows.ERROR_WRITE_FAULT
	}
	r.Write = op(err)
	if err == nil {
		r.Flush = op(f.Sync())
	}
	body, e := os.ReadFile(filename)
	r.Readback = e == nil && bytes.Equal(body, payload)
	return
}
func directoryCase(name, directory string, access, flags uint32, useGo, reopen bool, sd *windows.SECURITY_DESCRIPTOR, owner *windows.SID) (r observation) {
	r.Case = name
	if useGo {
		f, err := os.Open(directory)
		r.Open = op(err)
		if err != nil {
			return
		}
		defer func() { r.Close = op(f.Close()) }()
		r.ACL = inspect(windows.Handle(f.Fd()), sd, owner)
		if info, e := f.Stat(); e == nil {
			r.Mode = uint32(info.Mode().Perm())
		}
		r.Flush = op(f.Sync())
		return
	}
	pointer, err := windows.UTF16PtrFromString(directory)
	if err != nil {
		r.Open = op(err)
		return
	}
	handle, err := windows.CreateFile(pointer, access, share, nil, windows.OPEN_EXISTING, flags|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	r.Open = op(err)
	if err != nil {
		return
	}
	if reopen {
		original := handle
		defer func() { r.ParentClose = op(windows.CloseHandle(original)) }()
		procedure := windows.NewLazySystemDLL("kernel32.dll").NewProc("ReOpenFile")
		if e := procedure.Find(); e != nil {
			r.Open = op(e)
			return
		}
		value, _, e := procedure.Call(uintptr(original), uintptr(windows.GENERIC_READ|windows.GENERIC_WRITE), uintptr(share), uintptr(windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_WRITE_THROUGH))
		if value == uintptr(windows.InvalidHandle) {
			r.Open = op(e)
			if r.Open.Code == 0 {
				r.Open.Code = unknown
			}
			return
		}
		handle = windows.Handle(value)
	}
	defer func() { r.Close = op(windows.CloseHandle(handle)) }()
	r.ACL = inspect(handle, sd, owner)
	r.Flush = op(windows.FlushFileBuffers(handle))
	return
}
func run(r *report) {
	r.Phase = "preflight"
	source := os.Getenv("GITHUB_SHA")
	if os.Getenv("GITHUB_ACTIONS") != "true" || runtime.GOOS != "windows" || runtime.GOARCH != "amd64" || runtime.Version() != "go1.26.10" || !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(source) {
		r.Error = operation{true, unknown}
		return
	}
	r.Source, r.System, r.Architecture, r.GoVersion = source, "Windows", "amd64", runtime.Version()
	r.Phase = "create-temp"
	root, err := os.MkdirTemp("", "freightctl-windows-fs-")
	if err != nil {
		r.Error = op(err)
		return
	}
	defer func() {
		r.Cleanup = op(os.RemoveAll(root))
		_, e := os.Lstat(root)
		r.CleanupAbsent = os.IsNotExist(e)
		if r.Cleanup.Code != 0 || !r.CleanupAbsent {
			r.State, r.Phase = "failed", "cleanup"
			r.Error = r.Cleanup
		}
	}()
	r.Phase = "token"
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		r.Error = op(err)
		return
	}
	r.Elevated = token.IsElevated()
	r.Phase = "descriptor"
	sid := user.User.Sid
	dirSD, err := windows.SecurityDescriptorFromString("O:" + sid.String() + "D:P(A;OICI;FA;;;" + sid.String() + ")(A;OICI;FA;;;SY)")
	if err != nil {
		r.Error = op(err)
		return
	}
	fileSD, err := windows.SecurityDescriptorFromString("O:" + sid.String() + "D:P(A;;FA;;;" + sid.String() + ")(A;;FA;;;SY)")
	if err != nil {
		r.Error = op(err)
		return
	}
	directory := filepath.Join(root, "controlled")
	pointer, err := windows.UTF16PtrFromString(directory)
	if err != nil {
		r.Error = op(err)
		return
	}
	r.Phase = "create-controlled"
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: dirSD}
	if err = windows.CreateDirectory(pointer, &sa); err != nil {
		r.Error = op(err)
		return
	}
	r.Phase = "directory-handle"
	handle, err := windows.CreateFile(pointer, windows.GENERIC_READ, share, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		r.Error = op(err)
		return
	}
	r.DirectoryACL = inspect(handle, dirSD, sid)
	var filesystem [32]uint16
	var serial, maximum, flags uint32
	if err = windows.GetVolumeInformationByHandle(handle, nil, 0, &serial, &maximum, &flags, &filesystem[0], uint32(len(filesystem))); err == nil {
		name := windows.UTF16ToString(filesystem[:])
		switch name {
		case "NTFS", "ReFS", "FAT", "FAT32", "exFAT":
			r.Filesystem = name
		default:
			r.Filesystem = "other"
		}
	}
	if err = windows.CloseHandle(handle); err != nil {
		r.Error = op(err)
		return
	}
	r.Phase = "cases"
	r.Cases = append(r.Cases, fileCase("go-file", filepath.Join(directory, "go.txt"), false, fileSD, sid))
	r.Cases = append(r.Cases, directoryCase("go-directory", directory, 0, 0, true, false, dirSD, sid))
	r.Cases = append(r.Cases, directoryCase("win-directory-read", directory, windows.GENERIC_READ, windows.FILE_FLAG_BACKUP_SEMANTICS, false, false, dirSD, sid))
	r.Cases = append(r.Cases, directoryCase("win-directory-read-write", directory, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_FLAG_BACKUP_SEMANTICS, false, false, dirSD, sid))
	r.Cases = append(r.Cases, directoryCase("win-directory-write-through", directory, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_WRITE_THROUGH, false, false, dirSD, sid))
	r.Cases = append(r.Cases, directoryCase("reopened-directory-read-write", directory, windows.GENERIC_READ, windows.FILE_FLAG_BACKUP_SEMANTICS, false, true, dirSD, sid))
	r.Cases = append(r.Cases, fileCase("win-file-write-through", filepath.Join(directory, "native.txt"), true, fileSD, sid))
	r.State, r.Phase = "recorded", "complete"
}
func main() {
	runtime.GOMAXPROCS(1)
	r := report{Schema: 1, Kind: "freightctl-windows-fs-api-observation-v1", State: "failed", Filesystem: "unobserved", Cases: []observation{}}
	func() {
		defer func() {
			if recover() != nil {
				r.State, r.Phase = "failed", "panic"
				r.Error = operation{true, unknown}
			}
		}()
		run(&r)
	}()
	if json.NewEncoder(os.Stdout).Encode(r) != nil || r.State != "recorded" {
		os.Exit(2)
	}
}
