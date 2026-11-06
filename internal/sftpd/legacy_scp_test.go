package sftpd

import (
	"bufio"
	"strings"
	"testing"
)

func TestLegacySCPCommandParsesOnlyLiteralRegularFileRoles(t *testing.T) {
	for _, tc := range []struct {
		raw, path          string
		receive, directory bool
	}{
		{"scp -t /exact.dat", "/exact.dat", true, false},
		{"scp -vf relative.dat", "/relative.dat", false, false},
		{"scp -d -t .", "/", true, true},
		{"scp -t '/literal space.dat'", "/literal space.dat", true, false},
		{`scp -f /literal\ space.dat`, "/literal space.dat", false, false},
		{`scp -f '/literal;$(inert).dat'`, "/literal;$(inert).dat", false, false},
		{"scp -t -- -literal.dat", "/-literal.dat", true, false},
	} {
		command, err := parseSCPCommand(tc.raw)
		if err != nil || command.Path != tc.path || command.Receive != tc.receive || command.Directory != tc.directory {
			t.Fatal("literal file command changed meaning", tc.raw, command, err)
		}
	}
	for _, raw := range []string{"", "sh -c true", "scp -t /one /two", "scp -tf /file", "scp -t -t /file", "scp -f -d /folder", "scp -p -t /file", "scp -r -t /folder", "scp -f /", "scp -t ../escape", "scp -t /.freightctl/ticket", "scp -t /a/../b", "scp -t /glob*", "scp -t ~/file", "scp -t /a;touch /b", "scp -t /$(command)", "scp -t \"$HOME/file\"", "scp -t `command`", "scp -t /file\nsecond", "scp -t /file\x00", "scp -t '/unterminated", "scp -t /trailing\\", "scp -t -literal.dat", "scp -t /one -- /two", "scp -t -- -- /two", "scp -t " + strings.Repeat("x", 2050)} {
		if _, err := parseSCPCommand(raw); err == nil {
			t.Fatal("unsupported or evaluated command accepted", raw)
		}
	}
}

func TestLegacySCPRecordsRejectTraversalSpecialModesOversizeAndUnsupportedFrames(t *testing.T) {
	mode, size, name, err := scpHeader([]byte("C0640 65536 file name.dat"), 65536)
	if err != nil || mode != 0640 || size != 65536 || name != "file name.dat" {
		t.Fatal("ordinary regular-file record refused")
	}
	if _, size, _, err = scpHeader([]byte("C0600 0 empty.dat"), 1); err != nil || size != 0 {
		t.Fatal("empty file record refused")
	}
	for _, line := range []string{"C0640 65537 large.dat", "C0640 -1 negative.dat", "C0640 +1 signed.dat", "C0640 9223372036854775808 overflow.dat", "C4640 1 special.dat", "C0888 1 bad.dat", "C0640 1 ../escape", "C0640 1 /escape", "C0640 1 .", "C0640 1 .freightctl", "C0640 1 folder/file", "C0640 1 bad\nname", "D0750 0 folder", "E", "T0 0 0 0", "C0640 1 "} {
		if _, _, _, err := scpHeader([]byte(line), 65536); err == nil {
			t.Fatal("unsafe or unimplemented record accepted", line)
		}
	}
	for _, raw := range []string{"C0600 1 x", strings.Repeat("x", 2048) + "\n", "\n"} {
		if _, err := scpLine(bufio.NewReaderSize(strings.NewReader(raw), 4096)); err == nil {
			t.Fatal("unbounded or incomplete record accepted")
		}
	}
	if err := scpAck(bufio.NewReader(strings.NewReader("\x00"))); err != nil {
		t.Fatal("normal peer response refused")
	}
	for _, raw := range []string{"", "\x01private untrusted text\n", "\x02fatal\n", "x", "\x01" + strings.Repeat("x", 4096)} {
		if err := scpAck(bufio.NewReaderSize(strings.NewReader(raw), 4096)); err == nil || strings.Contains(err.Error(), "private untrusted") {
			t.Fatal("bad peer response accepted or disclosed")
		}
	}
}
