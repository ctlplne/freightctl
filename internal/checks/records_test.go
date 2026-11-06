package checks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

func recordSource(body []byte) store.File {
	return store.File{ID: "11111111-1111-4111-8111-111111111111", Size: int64(len(body)), SHA256: secure.Digest(body)}
}

func FuzzRecordStream(f *testing.F) {
	f.Add([]byte(`[{"id":"0001","amount":1.23},{"amount":null}]`))
	f.Add([]byte(`[]`))
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > 65536 {
			return
		}
		p := Policy{Schema: 2, Kind: "json_records", MaxBytes: 65536, MaxRows: 4, MaxRecordBytes: 1024, TimeoutSeconds: 1, Columns: []Column{{Name: "id", Type: "text", MaxBytes: 64}, {Name: "amount", Type: "decimal", MaxBytes: 64, Precision: 38, Scale: 2}}}
		seen := int64(0)
		r, e := StreamRecords(context.Background(), p, recordSource(body), "", bytes.NewReader(body), func(row Record) error {
			seen++
			if row.Number != seen || len(row.Cells) != 2 || seen > 4 {
				t.Fatal("stream row/count/shape escaped contract")
			}
			for _, c := range row.Cells {
				if c.Presence != CellValue && c.Presence != CellNull && c.Presence != CellMissing || c.Presence != CellValue && c.Value != "" {
					t.Fatal("invalid cell state emitted")
				}
			}
			return nil
		})
		if e == nil && r.Code == "valid_json_records" && r.Rows != seen {
			t.Fatal("qualified count differs from typed stream")
		}
	})
}

func TestRecordStreamPreservesJSONPresencePrecisionOrderAndDuplicates(t *testing.T) {
	p := Policy{Schema: 2, Kind: "json_records", Columns: []Column{{Name: "id", Type: "text", Required: true}, {Name: "amount", Type: "decimal", Required: true, Precision: 38, Scale: 2}, {Name: "empty", Type: "text"}, {Name: "absent", Type: "text"}, {Name: "null", Type: "text"}}}
	body := []byte(`[{"id":"0001","amount":12345678901234567890.12,"empty":"","null":null},{"id":"0001","amount":12345678901234567890.12,"empty":"","null":null}]`)
	var rows []Record
	r, e := StreamRecords(t.Context(), p, recordSource(body), strings.Repeat("a", 64), bytes.NewReader(body), func(row Record) error { rows = append(rows, row); return nil })
	if e != nil || r.Code != "valid_json_records" || r.Rows != 2 || len(rows) != 2 {
		t.Fatal("typed JSON record stream is absent or incomplete", r.Code, e)
	}
	want := []RecordCell{{Presence: CellValue, Value: "0001"}, {Presence: CellValue, Value: "12345678901234567890.12"}, {Presence: CellValue, Value: ""}, {Presence: CellMissing}, {Presence: CellNull}}
	for i, row := range rows {
		if row.Number != int64(i+1) || !reflect.DeepEqual(row.Cells, want) {
			t.Fatal("presence,precision or record order changed")
		}
	}
	rows[0].Cells[0].Value = "changed"
	if rows[1].Cells[0].Value != "0001" {
		t.Fatal("rows share mutable cell storage")
	}
	wire, _ := json.Marshal(rows)
	if bytes.Contains(wire, []byte("12345678901234567890")) || bytes.Contains(wire, []byte("0001")) {
		t.Fatal("transient record values became metadata")
	}
}

func TestRecordStreamUsesTheSameValidatorsForEveryFormat(t *testing.T) {
	base := Policy{Schema: 1, Kind: "csv", Columns: []Column{{Name: "account", Type: "text", Required: true, MaxBytes: 4}, {Name: "amount", Type: "decimal", Required: true, MaxBytes: 6, Precision: 12, Scale: 2}, {Name: "day", Type: "date", Required: true, MaxBytes: 10}}}
	for _, kind := range []string{"csv", "json_records", "fixed_width", "xml_records", "xlsx_records"} {
		t.Run(kind, func(t *testing.T) {
			p := base
			p.Columns = append([]Column(nil), base.Columns...)
			body := []byte("account,amount,day\n0001,100.01,2026-10-28\n")
			switch kind {
			case "json_records":
				p.Schema, p.Kind = 2, kind
				body = []byte(`[{"account":"0001","amount":100.01,"day":"2026-10-28"}]`)
			case "fixed_width":
				p.Schema, p.Kind = 3, kind
				for i, w := range []int{4, 6, 10} {
					p.Columns[i].Width = w
				}
				body = []byte("0001100.012026-10-28\n")
			case "xml_records":
				p.Schema, p.Kind = 4, kind
				p.XML = &XMLRecordPolicy{Root: "records", Record: "record"}
				body = []byte("<records>" + xmlGoodRecord + "</records>")
			case "xlsx_records":
				p.Schema, p.Kind = 5, kind
				p.XLSX = &XLSXPolicy{Sheet: "Records", DateMode: "iso_text"}
				body = workbookFixture(t, workbookCells, nil)
			}
			file := recordSource(body)
			ordinary, e := Validate(t.Context(), p, file, "", bytes.NewReader(body))
			if e != nil {
				t.Fatal(e)
			}
			var rows []Record
			r, e := StreamRecords(t.Context(), p, file, "", bytes.NewReader(body), func(row Record) error { rows = append(rows, row); return nil })
			if e != nil || !reflect.DeepEqual(r, ordinary) || len(rows) != 1 || r.Rows != 1 {
				t.Fatal("stream and ordinary validator disagree", r.Code, e)
			}
			for i, want := range []string{"0001", "100.01", "2026-10-28"} {
				if rows[0].Cells[i].Presence != CellValue || rows[0].Cells[i].Value != want {
					t.Fatal("typed scalar changed")
				}
			}
			marker := errors.New("private consumer contents")
			r, e = StreamRecords(t.Context(), p, file, "", bytes.NewReader(body), func(Record) error { return marker })
			if !errors.Is(e, marker) || r.Code != "record_consumer_failed" || strings.Contains(e.Error(), "private consumer contents") {
				t.Fatal("consumer failure was swallowed,leaked or passed", r.Code, e)
			}
		})
	}
}

func TestRecordStreamPreservesBlankSpreadsheetAndMissingXMLCells(t *testing.T) {
	p := xlsxIntakePolicy(t)
	for i := range p.Columns {
		p.Columns[i].Required = false
	}
	cells := strings.Replace(workbookCells, `<row r="2"><c r="A2" t="inlineStr"><is><t>0001</t></is></c><c r="B2"><v>100.01</v></c><c r="C2" t="inlineStr"><is><t>2026-10-28</t></is></c></row>`, `<row r="2"><c r="A2" t="inlineStr"><is><t/></is></c><c r="B2"/></row>`, 1)
	body := workbookFixture(t, cells, nil)
	var row Record
	r, e := StreamRecords(t.Context(), p, recordSource(body), "", bytes.NewReader(body), func(v Record) error { row = v; return nil })
	if e != nil || r.Code != "valid_xlsx_records" || !reflect.DeepEqual(row.Cells, []RecordCell{{Presence: CellValue, Value: ""}, {Presence: CellNull}, {Presence: CellMissing}}) {
		t.Fatal("spreadsheet blank,empty and missing states collapsed", r.Code, e)
	}
	p = Policy{Schema: 4, Kind: "xml_records", XML: &XMLRecordPolicy{Root: "records", Record: "record"}, Columns: []Column{{Name: "empty", Type: "text"}, {Name: "missing", Type: "text"}}}
	body = []byte(`<records><record><empty/></record></records>`)
	r, e = StreamRecords(t.Context(), p, recordSource(body), "", bytes.NewReader(body), func(v Record) error { row = v; return nil })
	if e != nil || r.Code != "valid_xml_records" || !reflect.DeepEqual(row.Cells, []RecordCell{{Presence: CellValue}, {Presence: CellMissing}}) {
		t.Fatal("XML missing and empty states collapsed", r.Code, e)
	}
}

func TestRecordStreamCannotTurnAPartialPrefixOrChangedSourceIntoAPass(t *testing.T) {
	p := Policy{Schema: 2, Kind: "json_records", Columns: []Column{{Name: "id", Type: "text", Required: true}}}
	for _, body := range [][]byte{[]byte(`[{"id":"first"},{"id":"second"`), []byte(`[{"id":"first"},{"id":"second","id":"duplicate"}]`)} {
		seen := 0
		r, e := StreamRecords(t.Context(), p, recordSource(body), "", bytes.NewReader(body), func(Record) error { seen++; return nil })
		if e != nil || r.Code == "valid_json_records" || seen != 1 {
			t.Fatal("invalid suffix established a qualified stream", r.Code, e, seen)
		}
	}
	body := []byte(`[{"id":"first"}]`)
	file := recordSource(body)
	file.SHA256 = strings.Repeat("f", 64)
	r, e := StreamRecords(t.Context(), p, file, "", bytes.NewReader(body), func(Record) error { return nil })
	if e != nil || r.Code != "source_integrity_changed" {
		t.Fatal("a record bypassed complete source identity", r.Code, e)
	}
	if _, e = StreamRecords(t.Context(), p, recordSource(body), "", bytes.NewReader(body), nil); !errors.Is(e, ErrInput) {
		t.Fatal("nil consumer accepted", e)
	}
}
