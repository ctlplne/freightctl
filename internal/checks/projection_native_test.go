//go:build projectionnative

package checks

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRecordProjectionActualStockInputsAndIndependentReceiver(t *testing.T) {
	root := os.Getenv("FREIGHTCTL_TEST_PROJECTION_DIR")
	xlsx := os.Getenv("FREIGHTCTL_TEST_XLSX_DIR")
	if root == "" || xlsx == "" {
		t.Fatal("actual native projection and stock XLSX input directories are required")
	}
	data, e := os.ReadFile(filepath.Join(root, "inputs.json"))
	if e != nil {
		t.Fatal(e)
	}
	var manifest struct {
		Schema int    `json:"schema_version"`
		Python string `json:"python"`
		Inputs []struct {
			Name, SHA256 string
			Bytes        int64
		} `json:"inputs"`
	}
	if json.Unmarshal(data, &manifest) != nil || manifest.Schema != 1 || manifest.Python == "" || len(manifest.Inputs) != 4 {
		t.Fatal("independent source inventory differs")
	}
	inputs := map[string][]byte{}
	for _, item := range manifest.Inputs {
		if filepath.Base(item.Name) != item.Name {
			t.Fatal("unsafe synthetic source name")
		}
		body, e := os.ReadFile(filepath.Join(root, item.Name))
		if e != nil || int64(len(body)) != item.Bytes || recordSource(body).SHA256 != item.SHA256 {
			t.Fatal("independent source byte binding differs", e)
		}
		inputs[item.Name] = body
	}
	stock, e := os.ReadFile(filepath.Join(xlsx, "shared.xlsx"))
	if e != nil {
		t.Fatal(e)
	}
	directory := filepath.Join(root, "outputs")
	if e = os.Mkdir(directory, 0700); e != nil {
		t.Fatal(e)
	}
	type output struct {
		SourceKind string           `json:"source_kind"`
		OutputKind string           `json:"output_kind"`
		File       string           `json:"file"`
		Report     ProjectionReport `json:"report"`
	}
	var outputs []output
	for _, kind := range []string{"csv", "json_records", "xml_records", "fixed_width", "xlsx_records"} {
		p := Policy{Schema: 1, Kind: "csv", MaxBytes: 1 << 20, MaxRows: 4, MaxRecordBytes: 4096, TimeoutSeconds: 5, Columns: []Column{{Name: "account", Type: "text", Required: true, MaxBytes: 64}, {Name: "amount", Type: "decimal", Required: true, Precision: 38, Scale: 2, MaxBytes: 64}, {Name: "day", Type: "date", Required: true, MaxBytes: 10}}}
		body := inputs["source.csv"]
		switch kind {
		case "json_records":
			p.Schema, p.Kind = 2, kind
			body = inputs["source.json"]
		case "xml_records":
			p.Schema, p.Kind = 4, kind
			p.XML = &XMLRecordPolicy{Root: "records", Record: "record"}
			body = inputs["source.xml"]
		case "fixed_width":
			p.Schema, p.Kind = 3, kind
			for i, w := range []int{4, 24, 10} {
				p.Columns[i].Width, p.Columns[i].MaxBytes = w, w
			}
			p.Columns[1].Padding = "space_left"
			body = inputs["source.fixed"]
		case "xlsx_records":
			p.Schema, p.Kind = 5, kind
			p.XLSX = &XLSXPolicy{Sheet: "Records", DateMode: "iso_text"}
			body = stock
		}
		if len(body) == 0 {
			t.Fatal("required independent input missing")
		}
		source, e := Normalize(p)
		if e != nil {
			t.Fatal(e)
		}
		_, hash, _ := canonical(source)
		for _, outputKind := range []string{"json_records", "csv"} {
			plan := RecordProjection{Schema: 1, Kind: "record_projection", SourcePolicyHash: hash, OutputKind: outputKind, Columns: []ProjectionColumn{{Source: "amount", Target: "total"}, {Source: "account", Target: "account"}, {Source: "day", Target: "date"}}, MaxBytes: 1 << 20, MaxRecordBytes: 4096, MaxRows: 4, TimeoutSeconds: 5}
			name := kind + "-" + outputKind + ".data"
			path := filepath.Join(directory, name)
			f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if e != nil {
				t.Fatal(e)
			}
			r, e := ProjectRecords(t.Context(), source, plan, recordSource(body), bytes.NewReader(body), f)
			closeError := f.Close()
			if e != nil || closeError != nil || r.Code != "transformed" || r.Source.Code != policySuccess(source) {
				t.Fatal("actual native projection failed", kind, outputKind, r.Code, e, closeError)
			}
			outputs = append(outputs, output{kind, outputKind, name, r})
		}
	}
	wire, e := json.MarshalIndent(struct {
		Schema  int      `json:"schema_version"`
		Outputs []output `json:"outputs"`
	}{1, outputs}, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(directory, "manifest.json"), wire, 0600); e != nil {
		t.Fatal(e)
	}
	t.Logf("actual native projection prepared10 outputs from five independent source-format profiles;Python%s receiver must independently verify all bytes/values", manifest.Python)
}
