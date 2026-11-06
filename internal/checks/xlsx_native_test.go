//go:build xlsxnative

package checks

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestXLSXRecordsActualStockXlsxWriter(t *testing.T) {
	root := os.Getenv("FREIGHTCTL_TEST_XLSX_DIR")
	if root == "" {
		t.Fatal("actual native XlsxWriter fixture directory is required")
	}
	data, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil || len(data) > 32<<10 {
		t.Fatal("producer manifest unavailable", err)
	}
	var m struct {
		Schema   int                                    `json:"schema_version"`
		Producer struct{ Name, Version, Python string } `json:"producer"`
		Cases    []struct {
			Name, SHA256 string
			Bytes        int64
		} `json:"cases"`
	}
	if json.Unmarshal(data, &m) != nil || m.Schema != 1 || m.Producer.Name != "xlsxwriter" || m.Producer.Version != "3.3.1" || m.Producer.Python == "" || len(m.Cases) != 13 {
		t.Fatal("producer identity/coverage differs")
	}
	want := map[string]string{"shared.xlsx": "valid_xlsx_records", "inline.xlsx": "valid_xlsx_records", "rich.xlsx": "valid_xlsx_records", "literal_formula.xlsx": "valid_xlsx_records", "literal_escape.xlsx": "valid_xlsx_records", "serial_1900.xlsx": "valid_xlsx_records", "serial_1904.xlsx": "valid_xlsx_records", "numeric_identifier.xlsx": "invalid_cell", "formula.xlsx": "unsupported_xlsx_active_content", "formula_other_sheet.xlsx": "unsupported_xlsx_active_content", "external_link.xlsx": "unsupported_xlsx_relationship", "fake_leap_day.xlsx": "invalid_cell", "row_limit.xlsx": "row_limit"}
	for _, c := range m.Cases {
		code, found := want[c.Name]
		if !found || filepath.Base(c.Name) != c.Name || c.Bytes < 22 || c.Bytes > 1<<20 {
			t.Fatal("unexpected producer case")
		}
		delete(want, c.Name)
		body, e := os.ReadFile(filepath.Join(root, c.Name))
		if e != nil || int64(len(body)) != c.Bytes || secure.Digest(body) != c.SHA256 {
			t.Fatal("stock-produced source identity differs", e)
		}
		contract := workbookContract()
		if c.Name == "serial_1900.xlsx" || c.Name == "fake_leap_day.xlsx" {
			contract.DateMode = "serial_1900"
		}
		if c.Name == "serial_1904.xlsx" {
			contract.DateMode = "serial_1904"
		}
		f, e := os.Open(filepath.Join(root, c.Name))
		if e != nil {
			t.Fatal(e)
		}
		r, e := ValidateXLSX(t.Context(), contract, f, c.Bytes)
		f.Close()
		if e != nil || r.Code != code || code == "valid_xlsx_records" && r.Rows != 1 {
			t.Fatalf("stock %s:want %s,got %s/%d: %v", c.Name, code, r.Code, r.Rows, e)
		}
		if code == "valid_xlsx_records" {
			p := xlsxIntakePolicy(t)
			p.XLSX.DateMode = contract.DateMode
			var rows []Record
			stream, e := StreamRecords(t.Context(), p, store.File{Size: c.Bytes, SHA256: c.SHA256}, "", bytes.NewReader(body), func(row Record) error { rows = append(rows, row); return nil })
			id := "0001"
			if c.Name == "literal_formula.xlsx" {
				id = "=SUM(1,2)"
			}
			if c.Name == "literal_escape.xlsx" {
				id = "_x0041_"
			}
			if e != nil || stream.Code != code || len(rows) != 1 || rows[0].Number != 1 || len(rows[0].Cells) != 3 {
				t.Fatal("actual stock typed record stream differs", e)
			}
			for i, want := range []string{id, "100.01", "2026-10-28"} {
				if rows[0].Cells[i].Presence != CellValue || rows[0].Cells[i].Value != want {
					t.Fatal("actual stock scalar,rich text,escape or date meaning changed")
				}
			}
		}
	}
	if len(want) != 0 {
		t.Fatal("producer omitted required outcomes")
	}
	t.Logf("actual XlsxWriter%s/Python%s:13 exact workbooks,seven successful reads and six refusals;no runtime custody claim", m.Producer.Version, m.Producer.Python)
}
