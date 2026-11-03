package ftpserver

import (
	"net"
	"testing"
)

func TestFreightctlActiveParserAcceptsRFC2428Delimiter(t *testing.T) {
	for _, parameter := range []string{"|1|127.0.0.1|2048|", "#1#127.0.0.1#2048#"} {
		addr, err := parseEPRTAddr(parameter)
		if err != nil || addr == nil || !addr.IP.Equal(net.ParseIP("127.0.0.1")) || addr.Port != 2048 {
			t.Fatalf("valid EPRT endpoint %q differs: %v", parameter, err)
		}
	}
}

func TestFreightctlActiveParserRejectsDNSOverflowAndFamilyMismatch(t *testing.T) {
	for _, parameter := range []string{"|1|localhost|2048|", "|2|127.0.0.1|2048|", "|1|::1|2048|", "|1|127.0.0.1|65536|", "|1|127.0.0.1|+2048|", "|1|127.0.0.1|2048|extra"} {
		if _, err := parseEPRTAddr(parameter); err == nil {
			t.Fatalf("invalid EPRT endpoint accepted: %q", parameter)
		}
	}
	for _, parameter := range []string{"127,0,0,1,256,0", "999,0,0,1,8,0", "127,0,0,1,0,0", "localhost,0,0,1,8,0"} {
		if _, err := parsePORTAddr(parameter); err == nil {
			t.Fatalf("invalid PORT endpoint accepted: %q", parameter)
		}
	}
}
