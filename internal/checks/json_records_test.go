package checks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestJSONRecordsRequireExactTypedScalarsAndWholeImmutableSource(t *testing.T) {
	policy := Policy{Schema: 2, Kind: "json_records", Columns: []Column{{Name: "account", Type: "text", Required: true}, {Name: "amount", Type: "decimal", Required: true, Precision: 12, Scale: 2}, {Name: "day", Type: "date", Required: true}}}
	data := []byte(`[{"account":"inert;never execute","amount":100.01,"day":"2026-11-06"}]`)
	file := store.File{ID: "11111111-1111-4111-8111-111111111111", Size: int64(len(data)), SHA256: secure.Digest(data)}
	report, err := Validate(context.Background(), policy, file, strings.Repeat("a", 64), bytes.NewReader(data))
	if err != nil || report.Code != "valid_json_records" || report.Engine != "freightctl-json-records-v1" || report.Rows != 1 || report.Bytes != file.Size || report.FileID != file.ID || report.SHA256 != file.SHA256 {
		t.Fatal("exact bounded JSON record contract is unsupported or unbound", report.Code, err)
	}
	for _, bad := range []string{
		`[{"account":"first","account":"second","amount":100.01,"day":"2026-11-06"}]`,
		`[{"account":"first","\u0061ccount":"second","amount":100.01,"day":"2026-11-06"}]`,
		`[{"account":"first","amount":"100.01","day":"2026-11-06"}]`,
		`[{"account":"first","amount":1e2,"day":"2026-11-06"}]`,
		`[{"account":"first","amount":100.01,"day":"2026-11-06","execute":"untrusted"}]`,
		`[{"account":"first","amount":100.01,"day":"2026-99-99"}]`,
		`[{"account":"first","amount":100.001,"day":"2026-11-06"}]`,
		`[{"account":null,"amount":100.01,"day":"2026-11-06"}]`,
		`[{"account":{"instruction":"execute"},"amount":100.01,"day":"2026-11-06"}]`,
		`{"account":"first","amount":100.01,"day":"2026-11-06"}`,
		`[{"account":"first","amount":100.01,"day":"2026-11-06"}][]`,
	} {
		f := file
		f.Size, f.SHA256 = int64(len(bad)), secure.Digest([]byte(bad))
		r, err := Validate(context.Background(), policy, f, strings.Repeat("a", 64), strings.NewReader(bad))
		if err != nil || r.Code == "valid_json_records" {
			t.Fatal("ambiguous,coerced,unknown or malformed JSON passed", r.Code, err)
		}
	}
	file.SHA256 = strings.Repeat("b", 64)
	report, err = Validate(context.Background(), policy, file, strings.Repeat("a", 64), bytes.NewReader(data))
	if err != nil || report.Code != "source_integrity_changed" {
		t.Fatal("valid records bypassed immutable whole-file identity", report.Code, err)
	}
}

func TestJSONRecordsBoundParsingAndPreserveUnicodeWithoutLeakingValues(t *testing.T) {
	policy := Policy{Schema: 2, Kind: "json_records", MaxRecordBytes: 128, MaxRows: 1, Columns: []Column{{Name: "secret-field", Type: "text", Required: true, MaxBytes: 128}}}
	validate := func(raw []byte) Report {
		t.Helper()
		file := store.File{ID: secure.NewID(), Size: int64(len(raw)), SHA256: secure.Digest(raw)}
		report, err := Validate(context.Background(), policy, file, strings.Repeat("a", 64), bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		encoded, _ := json.Marshal(report)
		if bytes.Contains(encoded, []byte("secret-field")) || bytes.Contains(encoded, []byte("untrusted-value")) {
			t.Fatal("report disclosed input names or values")
		}
		return report
	}
	for _, value := range []string{`"\uD834\uDD1E"`, `"\ufffd"`, `"\\ud800"`, `"ordinary text"`} {
		if report := validate([]byte(`[{"secret-field":` + value + `}]`)); report.Code != "valid_json_records" {
			t.Fatal("well-formed Unicode or escaped literal changed meaning", report.Code)
		}
	}
	for _, value := range []string{`"\ud800"`, `"\udc00"`, `"\ud800\u0061"`, "\"\xff\""} {
		if report := validate([]byte(`[{"secret-field":` + value + `}]`)); report.Code != "malformed_json" {
			t.Fatal("ill-formed Unicode was replaced or accepted", report.Code)
		}
	}
	if report := validate([]byte(`[{"secret-field":"untrusted-value"},{"secret-field":"second"}]`)); report.Code != "row_limit" {
		t.Fatal("row allowance ignored", report.Code)
	}
	if report := validate([]byte(`[{"secret-field":"` + strings.Repeat("x", 2<<20))); report.Code != "record_byte_limit" || report.Bytes > 128+4096+4096 {
		t.Fatal("decoder buffered an unbounded unfinished record", report.Code, report.Bytes)
	}
	if report := validate([]byte(`[{"secret-field":""}]`)); report.Code != "invalid_cell" {
		t.Fatal("empty required scalar accepted", report.Code)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Validate(ctx, policy, store.File{}, strings.Repeat("a", 64), strings.NewReader("[]")); err == nil {
		t.Fatal("cancelled JSON processing succeeded")
	}
	original := Policy{Schema: 2, Kind: "json_records", Columns: []Column{{Name: "a", Type: "text"}}}
	if _, err := Normalize(original); err != nil || original.Columns[0].MaxBytes != 0 {
		t.Fatal("normalization changed the caller's shared column definition", err)
	}
}

func FuzzJSONRecordsContract(f *testing.F) {
	for _, seed := range []string{`[]`, `[{"account":"inert"}]`, `[{"account":"one","account":"two"}]`, `[{"account":"\ud800"}]`, `[{"account":{"execute":"never"}}]`, `[{"account":"x"}][]`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		policy := Policy{Schema: 2, Kind: "json_records", MaxBytes: 2048, MaxRows: 8, MaxRecordBytes: 256, TimeoutSeconds: 1, Columns: []Column{{Name: "account", Type: "text", Required: true, MaxBytes: 128}}}
		file := store.File{ID: "11111111-1111-4111-8111-111111111111", Size: int64(len(raw)), SHA256: secure.Digest([]byte(raw))}
		report, err := Validate(context.Background(), policy, file, strings.Repeat("a", 64), strings.NewReader(raw))
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) && report.Code != "valid_json_records" {
				return
			}
			t.Fatal("bounded format returned an unexpected execution error")
		}
		if report.Code == "valid_json_records" {
			if report.Engine != "freightctl-json-records-v1" || report.Rows > policy.MaxRows || report.Bytes != file.Size {
				t.Fatal("format pass lost its source or resource contract")
			}
			file.SHA256 = strings.Repeat("b", 64)
			changed, err := Validate(context.Background(), policy, file, strings.Repeat("a", 64), strings.NewReader(raw))
			if err != nil || changed.Code != "source_integrity_changed" {
				t.Fatal("valid shape bypassed changed immutable identity")
			}
		}
	})
}
