package sftpd

import (
	"encoding/binary"
	"testing"
)

func TestPacketPathsAndAttributeBounds(t *testing.T) {
	for _, raw := range []string{"/../outside", "../../outside", "/a/../../outside", "/C:/file", "/a\\b", "/NUL"} {
		if _, err := virtualPath(raw); err == nil {
			t.Fatalf("unsafe path accepted %q", raw)
		}
	}
	if p, err := virtualPath("/inbox/../archive/./file"); err != nil || p != "/archive/file" {
		t.Fatal(p, err)
	}
	for _, flags := range []uint32{2, 16, 0x80000000} {
		if _, err := parseAttributes(flags, nil); err == nil {
			t.Fatal("unsupported attributes accepted")
		}
	}
	for _, flags := range []uint32{1, 4, 8} {
		if _, err := parseAttributes(flags, nil); err == nil {
			t.Fatal("truncated attributes accepted")
		}
	}
	size := make([]byte, 8)
	binary.BigEndian.PutUint64(size, 1<<30+1)
	if _, err := parseAttributes(1, size); err == nil {
		t.Fatal("unbounded size attribute accepted")
	}
}
func FuzzInspectPacket(f *testing.F) {
	f.Add([]byte{1, 0, 0, 0, 3})
	f.Add([]byte{3, 0, 0, 0, 1})
	f.Add([]byte{200, 0, 0, 0, 1})
	f.Add([]byte{10, 0, 0, 0, 1})
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > 256<<10 {
			return
		}
		attrs, err := inspectPacket(body)
		if err != nil {
			return
		}
		if attrs.mode != nil && *attrs.mode > 0777 {
			t.Fatal("unbounded mode")
		}
		if attrs.size != nil && (*attrs.size < 0 || *attrs.size > 1<<30) {
			t.Fatal("unbounded size")
		}
	})
}
