// Package protectedfs checks operating-system file privacy on held handles.
// A metadata check does not establish directory durability or storage isolation.
package protectedfs

import "errors"

var ErrPrivacy = errors.New("file reference is not private to the runtime identity")

// Windows descriptors are accepted only when their explicit protected DACL
// grants access to the owning runtime user. Unknown ACE kinds fail closed.
// This profile does not infer Unix permission bits from Windows attributes.
type accessEntry struct {
	principal string
	allow     bool
	mask      uint32
}

func privateDescriptor(owner, runtimeUser string, present, protected bool, entries []accessEntry) bool {
	if owner == "" || runtimeUser == "" || owner != runtimeUser || !present || !protected || len(entries) == 0 || len(entries) > 256 {
		return false
	}
	granted := false
	for _, e := range entries {
		if e.principal == "" || e.principal != runtimeUser || !e.allow || e.mask == 0 {
			return false
		}
		granted = true
	}
	return granted
}

func publicDescriptor(owner, runtimeUser string, present, protected bool, entries []accessEntry, readMask uint32) bool {
	if owner == "" || owner != runtimeUser || !present || !protected || len(entries) == 0 || len(entries) > 256 || readMask == 0 {
		return false
	}
	ownerGrant := false
	for _, e := range entries {
		if e.principal == "" || !e.allow || e.mask == 0 {
			return false
		}
		if e.principal == runtimeUser {
			ownerGrant = true
		} else if e.mask & ^readMask != 0 {
			return false
		}
	}
	return ownerGrant
}

func sealedDescriptor(owner, runtimeUser string, present, protected bool, entries []accessEntry, allowed, readable uint32) bool {
	if !privateDescriptor(owner, runtimeUser, present, protected, entries) {
		return false
	}
	read := false
	for _, e := range entries {
		if e.mask & ^allowed != 0 {
			return false
		}
		read = read || e.mask&readable != 0
	}
	return read
}

func writableDescriptor(owner, runtimeUser string, present, protected bool, entries []accessEntry, readable, writable uint32) bool {
	if !privateDescriptor(owner, runtimeUser, present, protected, entries) {
		return false
	}
	var granted uint32
	for _, e := range entries {
		granted |= e.mask
	}
	return granted&readable != 0 && granted&writable != 0
}
