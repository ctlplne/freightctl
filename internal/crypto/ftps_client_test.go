package crypto

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFTPSClientReferencesAndSessionCacheAreBounded(t *testing.T) {
	dir := t.TempDir()
	cert, key, pw := filepath.Join(dir, "cert"), filepath.Join(dir, "key"), filepath.Join(dir, "pw")
	if err := DevCertificate(cert, key); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(cert)
	if err := os.WriteFile(pw, []byte("fixture-password"), 0600); err != nil {
		t.Fatal(err)
	}
	d := FTPSDestination{Address: "127.0.0.1:21000", ServerName: "localhost", Mode: "explicit", User: "fixture", CAFile: cert, CASHA256: Digest(data), PasswordFile: pw, PasswordSHA256: Digest([]byte("fixture-password"))}
	if _, err := ftpsTrust(d); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*FTPSDestination){func(v *FTPSDestination) { v.Address = "198.51.100.1:21000" }, func(v *FTPSDestination) { v.Address = "localhost:21000" }, func(v *FTPSDestination) { v.Address = "127.0.0.1:+21000" }, func(v *FTPSDestination) { v.User = "injected\r\nPASS" }, func(v *FTPSDestination) { v.Mode = "plain" }, func(v *FTPSDestination) { v.CASHA256 = strings.Repeat("0", 64) }, func(v *FTPSDestination) { v.PasswordFile = "relative" }} {
		v := d
		change(&v)
		if _, err := ftpsTrust(v); err == nil {
			t.Fatal("unsafe destination reference accepted")
		}
	}
	s, err := ReadFTPSPassword(d)
	if err != nil {
		t.Fatal(err)
	}
	alias := s.Bytes
	s.Close()
	for _, v := range alias {
		if v != 0 {
			t.Fatal("owned secret was not cleared")
		}
	}
	if err = os.WriteFile(pw, []byte("new-password"), 0600); err != nil {
		t.Fatal(err)
	}
	if s, err = ReadFTPSPassword(d); err == nil {
		s.Close()
		t.Fatal("changed password accepted")
	}
	control := &controlTicket{}
	readonly := dataTicket{control}
	other := &controlTicket{}
	if _, ok := readonly.Get("peer"); ok {
		t.Fatal("invented cached ticket")
	}
	first, replacement := &tls.ClientSessionState{}, &tls.ClientSessionState{}
	control.Put("peer", first)
	readonly.Put("peer", replacement)
	if got, ok := readonly.Get("peer"); !ok || got != first {
		t.Fatal("data ticket replaced the control session")
	}
	if _, ok := readonly.Get("other-peer"); ok {
		t.Fatal("ticket escaped its approved peer")
	}
	if control.state != first || other.state != nil {
		t.Fatal("data channel replaced or shared a control cache")
	}
}
