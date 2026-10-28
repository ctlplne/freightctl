package vpath

import (
	"strings"
	"testing"
)

func TestMountAndVirtualPathCombinedLengthBound(t *testing.T) {
	root := strings.Repeat("/"+strings.Repeat("a", 255), 4)
	if _, err := Canonical(root); err != nil {
		t.Fatal(err)
	}
	if actual, err := Resolve(root, "/x"); err == nil {
		t.Fatalf("combined path exceeded the 1024-byte storage contract: %d", len(actual))
	}
}

func TestPathsRemainVirtualAndCanonical(t *testing.T) {
	for _, value := range []string{"", "relative", "/../secret", "/a/./b", "/a//b", "/a/", "/a\\b", "/C:/x", "/a\x00b", "/a\nb", "/CON.txt", "/lpt1", "/name. ", "/name.", "/name "} {
		if _, err := Canonical(value); err == nil {
			t.Errorf("unsafe path accepted: %q", value)
		}
	}
	p, err := Canonical("/cafe\u0301/payroll.csv")
	if err != nil || p != "/café/payroll.csv" {
		t.Fatal("NFC normalization", p, err)
	}
	resolved, err := Resolve("/partners/a", "/inbox/file.csv")
	if err != nil || resolved != "/partners/a/inbox/file.csv" {
		t.Fatal(resolved, err)
	}
	if Within("/partners/a", "/partners/ab/secret") {
		t.Fatal("prefix collision escaped mount")
	}
	if p, err := Relative("/partners/a", resolved); err != nil || p != "/inbox/file.csv" {
		t.Fatal(p, err)
	}
}

func FuzzCanonicalPath(f *testing.F) {
	for _, value := range []string{"/", "/inbox/payroll.csv", "/a/../b", "/cafe\u0301", "/NUL", "/a\\b"} {
		f.Add(value)
	}
	f.Fuzz(func(t *testing.T, value string) {
		p, err := Canonical(value)
		if err != nil {
			return
		}
		again, err := Canonical(p)
		if err != nil || again != p {
			t.Fatal("unstable canonicalization")
		}
		resolved, err := Resolve("/mount", p)
		if err != nil {
			return
		}
		canonical, err := Canonical(resolved)
		if err != nil || canonical != resolved || !Within("/mount", resolved) {
			t.Fatal("escaped virtual mount")
		}
	})
}
