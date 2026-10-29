package checks

import (
	"context"
	"strings"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

func testPolicy(t *testing.T) Policy {
	t.Helper()
	p, err := Normalize(Policy{Schema: 1, Kind: "csv", Columns: []Column{{Name: "account", Type: "text", Required: true}, {Name: "amount", Type: "decimal", Required: true, Precision: 12, Scale: 2}, {Name: "day", Type: "date", Required: true}}})
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func validateText(t *testing.T, p Policy, text string) Report {
	t.Helper()
	f := store.File{ID: secure.NewID(), Size: int64(len(text)), SHA256: secure.Digest([]byte(text))}
	r, err := Validate(context.Background(), p, f, strings.Repeat("a", 64), strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func TestCSVPreservesBusinessTextAndRejectsInvalidContracts(t *testing.T) {
	p := testPolicy(t)
	for _, text := range []string{"account,amount,day\n00001,0.01,2024-02-29\n", "account,amount,day\r\n\"account,with,commas\",-001.20,2026-10-28\r\n", "account,amount,day\n\"quoted\nline\",100,2026-01-01"} {
		if r := validateText(t, p, text); r.Code != "valid_csv" || r.Rows != 1 {
			t.Fatal(r)
		}
	}
	for _, text := range []string{"account,amount,wrong\n00001,0.01,2026-01-01\n", "account,amount,day\nx,1.234,2026-01-01\n", "account,amount,day\nx,NaN,2026-01-01\n", "account,amount,day\nx,1e3,2026-01-01\n", "account,amount,day\nx,1,2025-02-29\n", "account,amount,day\nx,1,2026-01-01,extra\n", "account,amount,day\n\"bad,1,2026-01-01\n", "account,amount,day\n\xff,1,2026-01-01\n", "account,amount,day\n,1,2026-01-01\n"} {
		if r := validateText(t, p, text); r.Code == "valid_csv" {
			t.Fatal("accepted malformed or invalid CSV")
		}
	}
	p.MaxRows = 1
	if r := validateText(t, p, "account,amount,day\na,1,2026-01-01\nb,2,2026-01-01\n"); r.Code != "row_limit" {
		t.Fatal(r)
	}
}
func TestCSVRecordMemoryAndExactSourceBound(t *testing.T) {
	p := testPolicy(t)
	p.MaxRecordBytes = 128
	for i := range p.Columns {
		p.Columns[i].MaxBytes = 128
	}
	// Both a newline-free field and quoted multiline input hit the reader budget;
	// the parser cannot buffer the complete 2 MiB attack string.
	for _, prefix := range []string{"", "\""} {
		r := validateText(t, p, "account,amount,day\n"+prefix+strings.Repeat("a", 2<<20))
		if r.Code != "record_byte_limit" || r.Bytes > int64(128+4096+4096) {
			t.Fatal(r)
		}
	}
	f := store.File{ID: secure.NewID(), Size: 3, SHA256: secure.Digest([]byte("abc"))}
	text := "account,amount,day\na,1,2026-01-01\n"
	r, err := Validate(context.Background(), testPolicy(t), f, strings.Repeat("a", 64), strings.NewReader(text))
	if err != nil || r.Code != "source_integrity_changed" {
		t.Fatal(r, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = Validate(ctx, p, f, strings.Repeat("a", 64), strings.NewReader(text)); err == nil {
		t.Fatal("cancelled parsing succeeded")
	}
}
func FuzzCSVContract(f *testing.F) {
	f.Add([]byte("account,amount,day\n0001,1.00,2026-01-01\n"))
	f.Add([]byte("\"\"\"\n"))
	f.Add([]byte("\xff\x00"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			return
		}
		p := testPolicy(t)
		p.MaxBytes = 1 << 20
		p.MaxRecordBytes = 4096
		file := store.File{ID: "00000000-0000-0000-0000-000000000001", Size: int64(len(b)), SHA256: secure.Digest(b)}
		r, err := Validate(context.Background(), p, file, strings.Repeat("a", 64), strings.NewReader(string(b)))
		if err != nil {
			t.Fatal(err)
		}
		if r.Bytes > file.Size || r.Rows > p.MaxRows+1 {
			t.Fatal(r)
		}
	})
}
