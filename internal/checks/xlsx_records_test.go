package checks

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/ctlplne/freightctl/internal/zipcontainer"
)

func workbookContract() XLSXContract {
	return XLSXContract{Sheet: "Records", DateMode: "iso_text", MaxRows: 4, MaxRecordBytes: 2048, MaxSharedStrings: 32, MaxSharedBytes: 2048,
		Columns:   []Column{{Name: "account", Type: "text", Required: true, MaxBytes: 32}, {Name: "amount", Type: "decimal", Required: true, MaxBytes: 32, Precision: 12, Scale: 2}, {Name: "day", Type: "date", Required: true, MaxBytes: 10}},
		Container: zipcontainer.Limits{MaxBytes: 1 << 20, MaxEntries: 32, MaxDirectoryBytes: 32 << 10, MaxEntryBytes: 64 << 10, MaxExpandedBytes: 128 << 10, MaxRatio: 100, MaxNameBytes: 256, MaxDepth: 8}}
}

const workbookCells = `<row r="1"><c r="A1" t="inlineStr"><is><t>account</t></is></c><c r="B1" t="inlineStr"><is><t>amount</t></is></c><c r="C1" t="inlineStr"><is><t>day</t></is></c></row><row r="2"><c r="A2" t="inlineStr"><is><t>0001</t></is></c><c r="B2"><v>100.01</v></c><c r="C2" t="inlineStr"><is><t>2026-10-28</t></is></c></row>`

func workbookFixture(t testing.TB, cells string, edit func(map[string]string)) []byte {
	t.Helper()
	parts := map[string]string{
		"[Content_Types].xml":        `<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>`,
		"_rels/.rels":                `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="r1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>`,
		"xl/workbook.xml":            `<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Records" sheetId="1" r:id="r1"/></sheets></workbook>`,
		"xl/_rels/workbook.xml.rels": `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="r1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>`,
		"xl/worksheets/sheet1.xml":   `<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>` + cells + `</sheetData></worksheet>`,
	}
	if edit != nil {
		edit(parts)
	}
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for name, body := range parts {
		r, e := w.Create(name)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = io.WriteString(r, body); e != nil {
			t.Fatal(e)
		}
	}
	if e := w.Close(); e != nil {
		t.Fatal(e)
	}
	return b.Bytes()
}

func TestXLSXRecordsExactScalarsHeadersAndAllMembers(t *testing.T) {
	for _, cells := range []string{workbookCells, strings.Replace(workbookCells, "100.01", "1.0001e2", 1), strings.Replace(workbookCells, "<t>0001</t>", "<r><t>00</t></r><r><t>01</t></r>", 1)} {
		b := workbookFixture(t, cells, nil)
		r, e := ValidateXLSX(t.Context(), workbookContract(), bytes.NewReader(b), int64(len(b)))
		if e != nil || r.Code != "valid_xlsx_records" || r.Rows != 1 {
			t.Fatal("valid spreadsheet refused", r, e)
		}
	}
	for _, cells := range []string{
		strings.Replace(workbookCells, "<v>100.01</v>", "<f>1+1</f><v>100.01</v>", 1),
		strings.Replace(workbookCells, `r="A2" t="inlineStr"><is><t>0001</t></is>`, `r="A2"><v>1</v>`, 1),
		strings.Replace(workbookCells, "100.01", "100.001", 1),
		strings.Replace(workbookCells, "100.01", "1e999999", 1),
		strings.Replace(workbookCells, "2026-10-28", "2026-02-30", 1),
		strings.Replace(workbookCells, "<t>account</t>", "<t>ACCOUNT</t>", 1),
		strings.Replace(workbookCells, `r="B2"`, `r="A2"`, 1),
		strings.Replace(workbookCells, `r="C2"`, `r="C3"`, 1),
		strings.Replace(workbookCells, `r="2"`, `r="3"`, 1),
		strings.Replace(workbookCells, "</sheetData>", "", 1) + `<f>HYPERLINK("https://never-contact.invalid/")</f>`,
	} {
		b := workbookFixture(t, cells, nil)
		r, e := ValidateXLSX(t.Context(), workbookContract(), bytes.NewReader(b), int64(len(b)))
		if e != nil || r.Code == "valid_xlsx_records" {
			t.Fatal("coerced,ambiguous or executable spreadsheet accepted", r, e)
		}
	}
}

func TestXLSXRecordsRejectPackageRelationshipsEntitiesAndMissingContract(t *testing.T) {
	for _, edit := range []func(map[string]string){
		func(m map[string]string) {
			m["_rels/.rels"] = strings.Replace(m["_rels/.rels"], `Target="xl/workbook.xml"`, `Target="https://never-contact.invalid/book.xlsx" TargetMode="External"`, 1)
		},
		func(m map[string]string) {
			m["xl/_rels/workbook.xml.rels"] = strings.Replace(m["xl/_rels/workbook.xml.rels"], `worksheets/sheet1.xml`, `../../escape.xml`, 1)
		},
		func(m map[string]string) {
			m["xl/workbook.xml"] = strings.Replace(m["xl/workbook.xml"], `name="Records"`, `name="Other"`, 1)
		},
		func(m map[string]string) {
			m["xl/workbook.xml"] = strings.Replace(m["xl/workbook.xml"], `r:id="r1"`, `r:id="r1" r:id="r1"`, 1)
		},
		func(m map[string]string) {
			m["xl/workbook.xml"] = `<!DOCTYPE workbook SYSTEM "file:///never-open">` + m["xl/workbook.xml"]
		},
		func(m map[string]string) {
			m["xl/worksheets/sheet1.xml"] = strings.Replace(m["xl/worksheets/sheet1.xml"], `spreadsheetml/2006/main`, `unknown/namespace`, 1)
		},
		func(m map[string]string) { m["xl/vbaProject.bin"] = "inert;never execute" },
		func(m map[string]string) {
			m["xl/workbook.xml"] = strings.Replace(m["xl/workbook.xml"], `</workbook>`, `<definedNames><definedName name="Auto_Open">command</definedName></definedNames></workbook>`, 1)
		},
	} {
		b := workbookFixture(t, workbookCells, edit)
		r, e := ValidateXLSX(t.Context(), workbookContract(), bytes.NewReader(b), int64(len(b)))
		if e != nil || r.Code == "valid_xlsx_records" {
			t.Fatal("untrusted package semantics accepted", r, e)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	b := workbookFixture(t, workbookCells, nil)
	if _, e := ValidateXLSX(ctx, workbookContract(), bytes.NewReader(b), int64(len(b))); !errors.Is(e, context.Canceled) {
		t.Fatal("canceled spreadsheet parser ran", e)
	}
}

func TestXLSXRecordsPreserveOOXMLTextEscapesAndRefuseMixedStringViews(t *testing.T) {
	b := workbookFixture(t, strings.Replace(workbookCells, "<t>account</t>", "<t>_x0061_ccount</t>", 1), nil)
	r, e := ValidateXLSX(t.Context(), workbookContract(), bytes.NewReader(b), int64(len(b)))
	if e != nil || r.Code != "valid_xlsx_records" {
		t.Fatal("OOXML escaped header was not interpreted as the original text", r, e)
	}
	b = workbookFixture(t, strings.Replace(workbookCells, "<t>0001</t>", "<r><t>00</t></r><t>01</t>", 1), nil)
	r, e = ValidateXLSX(t.Context(), workbookContract(), bytes.NewReader(b), int64(len(b)))
	if e != nil || r.Code == "valid_xlsx_records" {
		t.Fatal("mixed rich/plain strings produce an ambiguous cell view", r, e)
	}
}

func workbookShared(m map[string]string, body string) {
	m["[Content_Types].xml"] = strings.Replace(m["[Content_Types].xml"], "</Types>", `<Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/></Types>`, 1)
	m["xl/_rels/workbook.xml.rels"] = strings.Replace(m["xl/_rels/workbook.xml.rels"], "</Relationships>", `<Relationship Id="shared" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" Target="sharedStrings.xml"/></Relationships>`, 1)
	m["xl/sharedStrings.xml"] = `<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="1" uniqueCount="1">` + body + `</sst>`
	m["xl/worksheets/sheet1.xml"] = strings.Replace(m["xl/worksheets/sheet1.xml"], `r="A2" t="inlineStr"><is><t>0001</t></is>`, `r="A2" t="s"><v>0</v>`, 1)
}

func TestXLSXRecordsSharedStringsRequireExactIndicesCountsAndBudgets(t *testing.T) {
	for _, item := range []string{`<si><t>0001</t></si>`, `<si><r><t>00</t></r><r><t>01</t></r></si>`, `<si><t>_x005F_x0041_</t></si>`} {
		b := workbookFixture(t, workbookCells, func(m map[string]string) { workbookShared(m, item) })
		r, e := ValidateXLSX(t.Context(), workbookContract(), bytes.NewReader(b), int64(len(b)))
		if e != nil || r.Code != "valid_xlsx_records" {
			t.Fatal("valid shared strings refused", r, e)
		}
	}
	for _, edit := range []func(map[string]string){
		func(m map[string]string) {
			m["xl/sharedStrings.xml"] = strings.Replace(m["xl/sharedStrings.xml"], `count="1"`, `count="2"`, 1)
		},
		func(m map[string]string) {
			m["xl/sharedStrings.xml"] = strings.Replace(m["xl/sharedStrings.xml"], `uniqueCount="1"`, `uniqueCount="2"`, 1)
		},
		func(m map[string]string) {
			m["xl/worksheets/sheet1.xml"] = strings.Replace(m["xl/worksheets/sheet1.xml"], `t="s"><v>0</v>`, `t="s"><v>1</v>`, 1)
		},
		func(m map[string]string) {
			m["xl/sharedStrings.xml"] = strings.Replace(m["xl/sharedStrings.xml"], `<t>0001</t>`, `<t>00</t><t>01</t>`, 1)
		},
		func(m map[string]string) {
			m["xl/sharedStrings.xml"] = strings.Replace(m["xl/sharedStrings.xml"], `<t>0001</t>`, `<r><t>00</t></r><t>01</t>`, 1)
		},
	} {
		b := workbookFixture(t, workbookCells, func(m map[string]string) { workbookShared(m, `<si><t>0001</t></si>`); edit(m) })
		r, e := ValidateXLSX(t.Context(), workbookContract(), bytes.NewReader(b), int64(len(b)))
		if e != nil || r.Code == "valid_xlsx_records" {
			t.Fatal("ambiguous shared table accepted", r, e)
		}
	}
	for _, mutate := range []func(*XLSXContract){func(c *XLSXContract) { c.MaxSharedBytes = 3 }, func(c *XLSXContract) { c.MaxRecordBytes = 64 }, func(c *XLSXContract) { c.Container.MaxEntryBytes = 100 }, func(c *XLSXContract) { c.MaxRows = 1; c.Columns[0].MaxBytes = 3 }} {
		c := workbookContract()
		mutate(&c)
		b := workbookFixture(t, workbookCells, func(m map[string]string) { workbookShared(m, `<si><t>0001</t></si>`) })
		r, e := ValidateXLSX(t.Context(), c, bytes.NewReader(b), int64(len(b)))
		if e != nil || r.Code == "valid_xlsx_records" {
			t.Fatal("workbook processing bound escaped", r, e)
		}
	}
}

func TestXLSXRecordsUnselectedSheetsStillRefuseActiveContent(t *testing.T) {
	for _, formula := range []bool{false, true} {
		b := workbookFixture(t, workbookCells, func(m map[string]string) {
			m["[Content_Types].xml"] = strings.Replace(m["[Content_Types].xml"], "</Types>", `<Override PartName="/xl/worksheets/sheet2.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>`, 1)
			m["xl/workbook.xml"] = strings.Replace(m["xl/workbook.xml"], "</sheets>", `<sheet name="Other" sheetId="2" r:id="r2"/></sheets>`, 1)
			m["xl/_rels/workbook.xml.rels"] = strings.Replace(m["xl/_rels/workbook.xml.rels"], "</Relationships>", `<Relationship Id="r2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet2.xml"/></Relationships>`, 1)
			m["xl/worksheets/sheet2.xml"] = `<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData/></worksheet>`
			if formula {
				m["xl/worksheets/sheet2.xml"] = strings.Replace(m["xl/worksheets/sheet2.xml"], "<sheetData/>", `<sheetData><row r="1"><c r="A1"><f>1+1</f><v>2</v></c></row></sheetData>`, 1)
			}
		})
		r, e := ValidateXLSX(t.Context(), workbookContract(), bytes.NewReader(b), int64(len(b)))
		if e != nil || formula && r.Code != "unsupported_xlsx_active_content" || !formula && r.Code != "valid_xlsx_records" {
			t.Fatal("other worksheet evaded workbook safety", r, e)
		}
	}
}

func TestXLSXRecordsExactNumberDateAndEscapeMeaning(t *testing.T) {
	for _, v := range []struct{ mode, serial, want string }{{"serial_1900", "1", "1900-01-01"}, {"serial_1900", "59", "1900-02-28"}, {"serial_1900", "61", "1900-03-01"}, {"serial_1904", "0", "1904-01-01"}, {"serial_1904", "1", "1904-01-02"}} {
		got, e := xlsxSerialDate(v.mode, v.serial)
		if e != nil || got != v.want {
			t.Fatal("serial date changed its calendar day", e)
		}
	}
	for _, v := range []struct{ in, out string }{{"_x0061_ccount", "account"}, {"_x005F_x0041_", "_x0041_"}, {"_xD834__xDD1E_", "𝄞"}, {"_x000D_", "\r"}, {"_xABCG_", "_xABCG_"}} {
		got, e := xlsxString(v.in)
		if e != nil || got != v.out {
			t.Fatal("text meaning changed", e)
		}
	}
	for _, v := range []string{"_xD800_", "_xDC00_", "_xD800__x0041_", "_x0000_", "_xFFFF_"} {
		if _, e := xlsxString(v); e == nil {
			t.Fatal("invalid scalar escape accepted")
		}
	}
	w := xlsxWorkbook{c: workbookContract()}
	date := Column{Type: "date", Required: true, MaxBytes: 10}
	for _, v := range []struct {
		mode, raw, category string
		valid               bool
	}{{"iso_text", "2026-10-28", "text", true}, {"iso_text", "46323", "number", false}, {"serial_1900", "1", "number", true}, {"serial_1900", "59", "number", true}, {"serial_1900", "60", "number", false}, {"serial_1900", "61", "number", true}, {"serial_1900", "0", "number", false}, {"serial_1904", "0", "number", true}, {"serial_1900", "1.5", "number", false}, {"serial_1900", "1", "text", false}} {
		w.c.DateMode = v.mode
		if w.typedCell(date, v.raw, v.category) != v.valid {
			t.Fatal("date system,leap-day or cell type silently coerced")
		}
	}
	for _, v := range []struct{ in, out string }{{"1e2", "100"}, {"1.0001e2", "100.01"}, {"1e-2", "0.01"}, {"-1e2", "-100"}, {"1.20", "1.20"}} {
		got, e := xlsxNumber(v.in, 32)
		if e != nil || got != v.out {
			t.Fatal("decimal meaning changed", e)
		}
	}
	for _, v := range []string{"1e9999", "NaN", "INF", "1,000", " 100", "1e-9999"} {
		if _, e := xlsxNumber(v, 32); e == nil {
			t.Fatal("unbounded or nondecimal numeric input accepted")
		}
	}
}

func FuzzXLSXRecords(f *testing.F) {
	f.Add(workbookFixture(f, workbookCells, nil))
	f.Add([]byte("PK\x03\x04"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65536 {
			return
		}
		r, e := ValidateXLSX(context.Background(), workbookContract(), bytes.NewReader(b), int64(len(b)))
		if e == nil && r.Code == "valid_xlsx_records" && r.Rows > workbookContract().MaxRows {
			t.Fatal("workbook row budget escaped")
		}
	})
}
