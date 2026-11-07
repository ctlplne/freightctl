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
