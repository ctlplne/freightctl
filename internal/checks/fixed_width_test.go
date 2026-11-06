package checks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

func fixedWidthPolicy(t testing.TB) Policy {
	t.Helper()
	var policy Policy
	if err := json.Unmarshal([]byte(`{"schema_version":3,"kind":"fixed_width","columns":[{"name":"account","type":"text","required":true,"max_bytes":8,"width_bytes":8,"padding":"none"},{"name":"amount","type":"decimal","required":true,"max_bytes":12,"precision":12,"scale":2,"width_bytes":12,"padding":"space_left"},{"name":"day","type":"date","required":true,"max_bytes":10,"width_bytes":10,"padding":"none"}],"max_bytes":1024,"max_rows":2,"max_record_bytes":64,"timeout_seconds":2}`), &policy); err != nil {
		t.Fatal(err)
	}
	return policy
}

func TestFixedWidthRefusesMalformedRecordsCoercionAndChangedSource(t *testing.T) {
	base := "00000001      100.012026-11-06"
	for _, c := range []struct{ body, code string }{
		{base + "x\n", "invalid_record_width"},
		{base[:len(base)-1], "invalid_record_width"},
		{"\n", "invalid_record_width"},
		{base + "\r", "invalid_line_ending"},
		{base[:4] + "\r" + base[5:], "invalid_line_ending"},
		{base[:4] + "\x00" + base[5:], "invalid_cell"},
		{base[:4] + "\xff" + base[5:], "invalid_cell"},
		{"00000001       1e+022026-11-06", "invalid_cell"},
		{"00000001      100.012026-02-30", "invalid_cell"},
		{base + "\n" + base + "\r\n" + base, "row_limit"},
	} {
		file := store.File{Size: int64(len(c.body)), SHA256: secure.Digest([]byte(c.body))}
		r, err := Validate(context.Background(), fixedWidthPolicy(t), file, strings.Repeat("a", 64), strings.NewReader(c.body))
		if err != nil || r.Code != c.code {
			t.Fatalf("malformed input: want %s,got %s,%v", c.code, r.Code, err)
		}
		wire, _ := json.Marshal(r)
		if bytes.Contains(wire, []byte("00000001")) || bytes.Contains(wire, []byte("2026-02-30")) {
			t.Fatal("record values leaked into evidence")
		}
	}
	for _, change := range []func(*store.File){func(f *store.File) { f.Size++ }, func(f *store.File) { f.SHA256 = strings.Repeat("f", 64) }} {
		file := store.File{Size: int64(len(base)), SHA256: secure.Digest([]byte(base))}
		change(&file)
		r, err := Validate(context.Background(), fixedWidthPolicy(t), file, "", strings.NewReader(base))
		if err != nil || r.Code != "source_integrity_changed" {
			t.Fatal("changed immutable source passed", err, r.Code)
		}
	}
}

type fixedCountingReader struct {
	input io.Reader
	bytes int
}

func (r *fixedCountingReader) Read(p []byte) (int, error) {
	n, e := r.input.Read(p)
	r.bytes += n
	return n, e
}

func TestFixedWidthBoundsPaddingUnicodeAndPolicyMeaning(t *testing.T) {
	p := fixedWidthPolicy(t)
	p.MaxBytes = 1 << 20
	input := &fixedCountingReader{input: strings.NewReader(strings.Repeat("x", 100000))}
	r, err := Validate(context.Background(), p, store.File{Size: 100000}, "", input)
	if err != nil || r.Code != "record_byte_limit" || input.bytes > p.MaxRecordBytes+4096 {
		t.Fatal("newline-free input escaped the record read budget", err, r.Code, input.bytes)
	}
	p = Policy{Schema: 3, Kind: "fixed_width", MaxRecordBytes: 64, Columns: []Column{{Name: "private-field", Type: "text", Width: 4, Padding: "space_right", MaxBytes: 4}}}
	validate := func(body string) Report {
		t.Helper()
		f := store.File{Size: int64(len(body)), SHA256: secure.Digest([]byte(body))}
		r, e := Validate(context.Background(), p, f, "", strings.NewReader(body))
		if e != nil {
			t.Fatal(e)
		}
		return r
	}
	for _, body := range []string{"é  ", "    ", ""} {
		if r := validate(body); r.Code != "valid_fixed_width" {
			t.Fatal("valid optional byte field refused", r.Code)
		}
	}
	p.Columns[0].Required = true
	if r := validate("    "); r.Code != "invalid_cell" {
		t.Fatal("required padded blank accepted")
	}
	// Whole text is valid UTF-8,but the declared field boundary splits é.
	p.Columns = []Column{{Name: "a", Type: "text", Width: 1, MaxBytes: 1}, {Name: "b", Type: "text", Width: 3, MaxBytes: 3}}
	if r := validate("é  "); r.Code != "invalid_cell" {
		t.Fatal("split UTF-8 field accepted")
	}
	p = fixedWidthPolicy(t)
	p.Columns[1].Padding = "none"
	if r := validate("00000001      100.012026-11-06"); r.Code != "invalid_cell" {
		t.Fatal("numeric padding was silently inferred")
	}
	for _, change := range []func(*Policy){
		func(p *Policy) { p.Columns[0].Width = 0 }, func(p *Policy) { p.Columns[0].Width = 65 },
		func(p *Policy) { p.Columns[0].MaxBytes = 9 }, func(p *Policy) { p.Columns[0].Padding = "trim" },
		func(p *Policy) { p.Columns[0].Width = 63; p.Columns[0].MaxBytes = 8 },
		func(p *Policy) { p.Schema, p.Kind = 1, "csv" }, func(p *Policy) { p.Schema, p.Kind = 2, "json_records" },
	} {
		bad := fixedWidthPolicy(t)
		change(&bad)
		if _, e := Normalize(bad); !errors.Is(e, ErrInput) {
			t.Fatal("ambiguous width/padding policy admitted", e)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := Validate(ctx, fixedWidthPolicy(t), store.File{}, "", strings.NewReader("")); !errors.Is(e, context.Canceled) {
		t.Fatal("cancellation lost", e)
	}
}

func TestFixedWidthValidatesExplicitByteFieldsWithoutChangingData(t *testing.T) {
	p := fixedWidthPolicy(t)
	for _, ending := range []string{"", "\n", "\r\n"} {
		body := "00000001      100.012026-11-06" + ending
		file := store.File{ID: "11111111-1111-4111-8111-111111111111", Size: int64(len(body)), SHA256: secure.Digest([]byte(body))}
		r, err := Validate(context.Background(), p, file, strings.Repeat("a", 64), strings.NewReader(body))
		if err != nil || r.Code != "valid_fixed_width" || r.Engine != "freightctl-fixed-width-v1" || r.Rows != 1 || r.Bytes != file.Size || r.SHA256 != file.SHA256 {
			t.Fatal("explicit fixed-width policy is not enforced on the complete exact source", err, r.Code)
		}
	}
}

func FuzzFixedWidthContract(f *testing.F) {
	f.Add([]byte("00000001      100.012026-11-06\n"))
	f.Add([]byte("\xff\x00\n"))
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > 2048 {
			return
		}
		p := fixedWidthPolicy(t)
		file := store.File{Size: int64(len(body)), SHA256: secure.Digest(body)}
		r, err := Validate(t.Context(), p, file, "", bytes.NewReader(body))
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) && r.Code != "valid_fixed_width" {
				return
			}
			t.Fatal(err)
		}
		if r.Code == "valid_fixed_width" {
			if r.Engine != "freightctl-fixed-width-v1" || r.Bytes != file.Size || r.Rows > p.MaxRows {
				t.Fatal("invalid success evidence")
			}
			file.SHA256 = strings.Repeat("f", 64)
			changed, e := Validate(t.Context(), p, file, "", bytes.NewReader(body))
			if e == nil && changed.Code == "valid_fixed_width" {
				t.Fatal("source hash ignored")
			}
		}
	})
}
