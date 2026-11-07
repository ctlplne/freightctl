package protectedfs

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateSealKeepsExactBytesAndAllowsAtomicIdentityLink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "freightctl-sealed")
	directory, err := CreateDirectoryExclusive(path)
	if err != nil {
		t.Fatal(err)
	}
	directory.Close()
	root, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	f, err := CreateAt(root, "private-object")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if state, err := Protection(f); err != nil || state != PrivateWritable {
		t.Fatal("new staging file does not have exact writable privacy", err)
	}
	want := []byte("exact sealed task-owned bytes")
	if _, err = f.Write(want); err != nil {
		t.Fatal(err)
	}
	if err = SealReadOnly(f); err != nil {
		t.Fatal(err)
	}
	if state, err := Protection(f); err != nil || state != PrivateSealed {
		t.Fatal("file sealing did not remove data-write grants", err)
	}
	if err = SealReadOnly(f); err != nil {
		t.Fatal("already-sealed file was not idempotent", err)
	}
	if err = f.Sync(); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	if err = root.Link("private-object", "published-identity"); err != nil {
		t.Fatal("sealed identity cannot be linked without overwriting", err)
	}
	opened, err := root.Open("published-identity")
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	if state, err := Protection(opened); err != nil || state != PrivateSealed {
		t.Fatal("linked identity lost sealed privacy", err)
	}
	original, err := root.Stat("private-object")
	linked, linkedErr := opened.Stat()
	if err != nil || linkedErr != nil || !os.SameFile(original, linked) {
		t.Fatal("publication did not preserve the same sealed filesystem object")
	}
	got, err := root.ReadFile("published-identity")
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("sealing/linking changed exact bytes", err)
	}
}

func TestSealedDescriptorRequiresPrivateReadabilityAndNoByteMutation(t *testing.T) {
	const user = "S-1-5-21-1-2-3-1001"
	const read, writable, all, genericRead uint32 = 1, 2, 0x10000000, 0x80000000
	const allowed uint32 = 0x120189 | genericRead
	owner := accessEntry{principal: user, allow: true, mask: 0x120189}
	if !sealedDescriptor(user, user, true, true, []accessEntry{owner}, allowed, read|genericRead|all) || writableDescriptor(user, user, true, true, []accessEntry{owner}, read|genericRead|all, writable|0x40000000|all) {
		t.Fatal("sealed bytes confused with writable staging")
	}
	for _, mutation := range []uint32{2, 4, 16, 32, 0x10000, 0x40000, 0x80000, 0x40000000, all} {
		changed := owner
		changed.mask |= mutation
		if sealedDescriptor(user, user, true, true, []accessEntry{changed}, allowed, read|genericRead|all) {
			t.Fatal("sealed descriptor retained byte,ACL,owner,delete or execution authority")
		}
	}
	if sealedDescriptor(user, user, true, true, []accessEntry{owner, {principal: "S-1-1-0", allow: true, mask: read}}, allowed, read) || sealedDescriptor(user, user, true, true, []accessEntry{{principal: user, allow: true, mask: 0x100}}, allowed, read) {
		t.Fatal("public or unreadable descriptor qualified as sealed")
	}
}
