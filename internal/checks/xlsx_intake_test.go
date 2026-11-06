package checks

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

func xlsxIntakePolicy(t testing.TB) Policy {
	t.Helper()
	var p Policy
	wire := `{"schema_version":5,"kind":"xlsx_records","columns":[{"name":"account","type":"text","required":true,"max_bytes":32},{"name":"amount","type":"decimal","required":true,"max_bytes":32,"precision":12,"scale":2},{"name":"day","type":"date","required":true,"max_bytes":10}],"max_bytes":262144,"max_rows":4,"max_record_bytes":2048,"timeout_seconds":2,"xlsx":{"sheet":"Records","date_mode":"iso_text","max_parts":32,"max_directory_bytes":32768,"max_part_bytes":65536,"max_expanded_bytes":131072,"max_expansion_ratio":100,"max_shared_strings":32,"max_shared_bytes":2048}}`
	if err := json.Unmarshal([]byte(wire), &p); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestXLSXIntakeBindsOrdinaryReportToWholeImmutableFile(t *testing.T) {
	body := workbookFixture(t, workbookCells, nil)
	f := store.File{ID: "11111111-1111-4111-8111-111111111111", Size: int64(len(body)), SHA256: secure.Digest(body)}
	r, err := Validate(t.Context(), xlsxIntakePolicy(t), f, strings.Repeat("a", 64), bytes.NewReader(body))
	if err != nil || r.Code != "valid_xlsx_records" || r.Engine != "freightctl-xlsx-records-v1" || r.Rows != 1 || r.Bytes != f.Size || r.FileID != f.ID || r.SHA256 != f.SHA256 || r.PolicyHash != strings.Repeat("a", 64) {
		t.Fatal("governed XLSX intake is missing or unbound", r.Code, err)
	}
}

type xlsxSequentialOnly struct{ io.Reader }

type xlsxFaultSource struct {
	*bytes.Reader
	starts int
	late   bool
}

func (r *xlsxFaultSource) ReadAt(p []byte, off int64) (int, error) {
	if off == 0 {
		r.starts++
		if !r.late || r.starts > 1 {
			return 0, io.ErrClosedPipe
		}
	}
	return r.Reader.ReadAt(p, off)
}

func TestXLSXIntakeSourceIOFailureRemainsRetryable(t *testing.T) {
	body := workbookFixture(t, workbookCells, nil)
	file := store.File{Size: int64(len(body)), SHA256: secure.Digest(body)}
	for _, late := range []bool{false, true} {
		r, e := Validate(t.Context(), xlsxIntakePolicy(t), file, "", &xlsxFaultSource{Reader: bytes.NewReader(body), late: late})
		if e == nil {
			t.Fatal("source I/O failure became a permanent business rejection", r.Code)
		}
	}
}

func TestXLSXIntakeRejectsChangedSourcesAndAmbiguousPolicies(t *testing.T) {
	body := workbookFixture(t, workbookCells, nil)
	file := store.File{Size: int64(len(body)), SHA256: secure.Digest(body)}
	for _, mutate := range []func(*store.File){func(f *store.File) { f.Size++ }, func(f *store.File) { f.Size-- }, func(f *store.File) { f.SHA256 = strings.Repeat("a", 64) }} {
		bad := file
		mutate(&bad)
		r, e := Validate(t.Context(), xlsxIntakePolicy(t), bad, "", bytes.NewReader(body))
		if e != nil || r.Code != "source_integrity_changed" {
			t.Fatal("changed source accepted", r.Code, e)
		}
	}
	if _, e := Validate(t.Context(), xlsxIntakePolicy(t), file, "", xlsxSequentialOnly{bytes.NewReader(body)}); !errors.Is(e, ErrInput) {
		t.Fatal("sequential input was silently buffered/spooled", e)
	}
	for _, mutate := range []func(*Policy){
		func(p *Policy) {
			p.Schema = 4
			p.Kind = "xml_records"
			p.XML = &XMLRecordPolicy{Root: "r", Record: "r"}
		},
		func(p *Policy) { p.XLSX = nil }, func(p *Policy) { p.XLSX.Sheet = "bad/name" }, func(p *Policy) { p.XLSX.DateMode = "guess" },
		func(p *Policy) { p.XLSX.MaxParts = 4097 }, func(p *Policy) { p.XLSX.MaxDirectoryBytes = 17 << 20 }, func(p *Policy) { p.XLSX.MaxPartBytes = p.XLSX.MaxExpandedBytes + 1 }, func(p *Policy) { p.XLSX.MaxSharedBytes = p.XLSX.MaxExpandedBytes + 1 }, func(p *Policy) { p.Columns[0].Width = 1 },
	} {
		p := xlsxIntakePolicy(t)
		mutate(&p)
		if _, e := Normalize(p); !errors.Is(e, ErrInput) {
			t.Fatal("ambiguous or unbounded workbook policy accepted", e)
		}
	}
	p := xlsxIntakePolicy(t)
	normalized, e := Normalize(p)
	if e != nil {
		t.Fatal(e)
	}
	p.XLSX.Sheet = "Other"
	if normalized.XLSX.Sheet != "Records" {
		t.Fatal("policy normalization retained mutable workbook settings")
	}
}
