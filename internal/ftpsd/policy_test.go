package ftpsd

import (
	"errors"
	"net"
	"os"
	"strings"
	"testing"
)

func TestFTPReservedUploadPathsDoNotBecomeOrdinaryFiles(t *testing.T) {
	id := "11111111-1111-4111-8111-111111111111"
	name := "/.freightctl/uploads/" + id
	if got, control := uploadTicket(name); !control || got != id {
		t.Fatal("exact ticket grammar rejected")
	}
	for _, value := range []string{"/.freightctl", "/.freightctl/uploads", "/.freightctl/uploads/bad", name + "/suffix", "/other/.freightctl/uploads/" + id} {
		if got, control := uploadTicket(value); !control || got != "" {
			t.Fatal("reserved namespace escaped its narrow control grammar")
		}
	}
	for _, value := range []string{"/ordinary.csv", "/uploads/" + id, "/.freightctl/uploads/../" + id, "/.freightctl/uploads/" + id + "\n"} {
		if _, control := uploadTicket(value); control {
			t.Fatal("ordinary or malformed path became a ticket")
		}
	}
	// An engine without the accepted-type capability must fail closed even
	// before any database or host filesystem is consulted.
	for _, flags := range []int{os.O_RDONLY, os.O_WRONLY | os.O_CREATE} {
		if _, err := (&filesystem{}).GetHandle(name, flags, 0); !errors.Is(err, os.ErrPermission) {
			t.Fatal("ticket opened without engine/type authority", err)
		}
	}
}

func TestActiveDestinationCannotBounceToOtherPeersOrPrivilegedServices(t *testing.T) {
	peer := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 40000}
	for _, c := range []struct {
		command, parameter string
		allowed            bool
	}{
		{"PORT", "127,0,0,1,8,0", true},
		{"EPRT", "|1|127.0.0.1|2048|", true},
		{"PORT", "127,0,0,2,8,0", false},
		{"EPRT", "|1|127.0.0.2|2048|", false},
		{"PORT", "127,0,0,1,0,22", false},
		{"EPRT", "|1|127.0.0.1|22|", false},
		{"EPRT", "|1|localhost|2048|", false},
		{"PORT", "127,000,0,1,8,0", false},
		{"PORT", "127,0,0,1,256,0", false},
		{"PORT", "127,0,0,1,-1,0", false},
		{"EPRT", "|1|127.0.0.1|65536|", false},
		{"EPRT", "|1|127.0.0.1|+2048|", false},
		{"EPRT", "|2|127.0.0.1|2048|", false},
		{"EPRT", "|1|::1|2048|", false},
		{"EPRT", "|1|127.0.0.1|2048|extra", false},
		{"PORT", strings.Repeat("1", 4096), false},
	} {
		if got := safeActiveDestination(c.command, c.parameter, peer); got != c.allowed {
			t.Fatalf("%s %q: allowed=%v", c.command, c.parameter, got)
		}
	}
	if !safeActiveDestination("EPRT", "|2|::1|2048|", &net.TCPAddr{IP: net.ParseIP("::1")}) {
		t.Fatal("numeric IPv6 peer refused")
	}
	if safeActiveDestination("EPRT", "|1|127.0.0.1|2048|", nil) {
		t.Fatal("missing control peer granted a destination")
	}
}

func TestFTPVirtualNamesCannotReachHostOrControlPaths(t *testing.T) {
	for _, name := range []string{"", "relative", "/../private", "/a/../b", "/a//b", "/.freightctl/upload", "/a/.freightctl", "/name\r\nSTOR bad", "/C:\\private", "/trailing.", "/trailing "} {
		if virtual(name) == nil {
			t.Fatalf("unsafe name accepted: %q", name)
		}
	}
	for _, name := range []string{"/", "/safe", "/directory/file.csv"} {
		if err := virtual(name); err != nil {
			t.Fatalf("safe name %q: %v", name, err)
		}
	}
}

func FuzzActiveDestination(f *testing.F) {
	for _, s := range []string{"127,0,0,1,8,0", "|1|127.0.0.1|2048|", "|2|::1|2048|", "|1|example.com|22|", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		peer := &net.TCPAddr{IP: net.ParseIP("127.0.0.1")}
		_ = safeActiveDestination("PORT", s, peer)
		_ = safeActiveDestination("EPRT", s, peer)
	})
}
