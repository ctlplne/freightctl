package ftpserver

import (
	"io"
	"log/slog"
	"net"
	"testing"
	"time"
)

func TestFreightctlPassiveListenAddressAndDeadline(t *testing.T) {
	for _, ranged := range []bool{false, true} {
		t.Run(map[bool]string{false: "ephemeral", true: "range"}[ranged], func(t *testing.T) {
			settings := &Settings{PassiveTransferListenIP: "127.0.0.1"}
			if ranged {
				probe, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				port := probe.Addr().(*net.TCPAddr).Port
				_ = probe.Close()
				settings.PassiveTransferPortRange = &PortRange{Start: port, End: port}
			}
			h := &clientHandler{server: &FtpServer{settings: settings}, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
			_, listener, deadline, err := h.getPassiveListener()
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			addr := listener.Addr().(*net.TCPAddr)
			if !addr.IP.Equal(net.ParseIP("127.0.0.1")) {
				t.Fatalf("passive socket is not bound to the approved loopback address: %v", addr)
			}
			if err := deadline.SetDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			_, err = listener.Accept()
			if e, ok := err.(net.Error); !ok || !e.Timeout() {
				t.Fatalf("the original listener deadline is not enforced: %v", err)
			}
		})
	}
}

func TestFreightctlPassiveListenAddressRefusals(t *testing.T) {
	for _, ip := range []string{"localhost", "0.0.0.0", "::", "127.0.0.1:2000", "untrusted.invalid"} {
		t.Run(ip, func(t *testing.T) {
			s := NewFtpServer(&TestServerDriver{Settings: &Settings{PassiveTransferListenIP: ip}})
			if err := s.loadSettings(); err == nil {
				t.Fatal("unsafe passive bind accepted")
			}
		})
	}
	s := NewFtpServer(&TestServerDriver{Settings: &Settings{PassiveTransferListenIP: "127.0.0.1", PassiveTransferPortMultiplexing: true}})
	if err := s.loadSettings(); err == nil {
		t.Fatal("multiplexing bypassed the explicit passive binding")
	}
}
