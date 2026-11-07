package protectedfs

import "testing"

func TestPrivateDescriptorRequiresTheRuntimeOwnerAndNoOtherAuthority(t *testing.T) {
	const user = "S-1-5-21-1-2-3-1001"
	entries := []accessEntry{{principal: user, allow: true, mask: 0x1f01ff}}
	if !privateDescriptor(user, user, true, true, entries) {
		t.Fatal("explicit owner-only descriptor refused")
	}
	for _, r := range []struct {
		owner, runtime     string
		present, protected bool
		entries            []accessEntry
	}{
		{"", user, true, true, entries},
		{user, "other-runtime", true, true, entries},
		{user, user, false, true, entries},
		{user, user, true, false, entries},
		{user, user, true, true, nil},
		{user, user, true, true, []accessEntry{{principal: "S-1-1-0", allow: true, mask: 1}}},
		{user, user, true, true, []accessEntry{{principal: user, allow: false, mask: 1}}},
		{user, user, true, true, []accessEntry{{principal: user, allow: true, mask: 0}}},
		{user, user, true, true, append(append([]accessEntry{}, entries...), accessEntry{principal: "S-1-5-32-545", allow: true, mask: 1})},
	} {
		if privateDescriptor(r.owner, r.runtime, r.present, r.protected, r.entries) {
			t.Fatal("broad,null,inherited,unknown or wrong-owner descriptor accepted")
		}
	}
}

func TestPublicTrustDescriptorAllowsReadsButRefusesOtherMutationAuthority(t *testing.T) {
	const user, everyone = "S-1-5-21-1-2-3-1001", "S-1-1-0"
	// FILE_GENERIC_READ|FILE_GENERIC_EXECUTE and their generic equivalents.
	const readMask uint32 = 0x1200a9 | 0x80000000 | 0x20000000
	owner := accessEntry{principal: user, allow: true, mask: 0x1f01ff}
	read := accessEntry{principal: everyone, allow: true, mask: 0x120089}
	entries := []accessEntry{owner, read}
	if !publicDescriptor(user, user, true, true, entries, readMask) || privateDescriptor(user, user, true, true, entries) {
		t.Fatal("public read profile was confused with secret privacy")
	}
	for _, mutation := range []uint32{2, 4, 16, 256, 0x10000, 0x40000, 0x80000, 0x40000000, 0x10000000} {
		changed := read
		changed.mask |= mutation
		if publicDescriptor(user, user, true, true, []accessEntry{owner, changed}, readMask) {
			t.Fatal("another principal gained file or ACL mutation authority")
		}
	}
	if publicDescriptor(user, user, true, false, entries, readMask) || publicDescriptor(user, user, false, true, entries, readMask) || publicDescriptor(user, everyone, true, true, entries, readMask) || publicDescriptor(user, user, true, true, []accessEntry{read}, readMask) {
		t.Fatal("inherited,null,wrong-owner or missing-owner grant accepted")
	}
}
