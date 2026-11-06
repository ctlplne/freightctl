package checks

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ctlplne/freightctl/internal/custody"
)

func projectionContract(t testing.TB) (Policy, RecordProjection) {
	t.Helper()
	source, e := Normalize(Policy{Schema: 2, Kind: "json_records", Columns: []Column{{Name: "id", Type: "text", Required: true, MaxBytes: 32}, {Name: "amount", Type: "decimal", Required: true, Precision: 38, Scale: 2, MaxBytes: 64}, {Name: "empty", Type: "text", MaxBytes: 32}, {Name: "absent", Type: "text", MaxBytes: 32}, {Name: "null", Type: "text", MaxBytes: 32}}})
	if e != nil {
		t.Fatal(e)
	}
	_, hash, _ := canonical(source)
	return source, RecordProjection{Schema: 1, Kind: "record_projection", SourcePolicyHash: hash, OutputKind: "json_records", Columns: []ProjectionColumn{{Source: "amount", Target: "total"}, {Source: "id", Target: "account"}, {Source: "empty", Target: "empty"}, {Source: "absent", Target: "absent"}, {Source: "null", Target: "null"}}, MaxBytes: 8192, MaxRecordBytes: 1024, MaxRows: 4, TimeoutSeconds: 2}
}

func TestRecordProjectionPrivateStageSealsOnlyCompleteOutputs(t *testing.T) {
	source, plan := projectionContract(t)
	path := filepath.Join(t.TempDir(), "freightctl-projection")
	disk, e := custody.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer disk.Close()
	for _, valid := range []bool{false, true} {
		body := []byte(projectionInput)
		if !valid {
			body = []byte(`[{"id":"0001","amount":1.00},{"id":`)
		}
		file := recordSource(body)
		name := custody.Name(file.ID, file.ID, file.ID)
		if valid {
			name = custody.Name(file.ID, file.ID, "22222222-2222-4222-8222-222222222222")
		}
		var report ProjectionReport
		size, hash, e := disk.StageGenerated(t.Context(), name, plan.MaxBytes, func(w io.Writer) error {
			var err error
			report, err = ProjectRecords(t.Context(), source, plan, file, bytes.NewReader(body), w)
			return err
		})
		if !valid {
			if e == nil {
				t.Fatal("incomplete source sealed an artifact")
			}
			if _, e = os.Stat(filepath.Join(path, name)); !os.IsNotExist(e) {
				t.Fatal("private partial output survived failed generation", e)
			}
			continue
		}
		if e != nil || report.Code != "transformed" || size != report.OutputBytes || hash != report.OutputSHA256 {
			t.Fatal("sealed custody bytes differ from complete projection", e)
		}
		st, e := os.Stat(filepath.Join(path, name))
		if e != nil || st.Mode().Perm() != 0400 {
			t.Fatal("generated source is mutable", e)
		}
		reader, e := disk.VerifiedContext(t.Context(), name, size, hash)
		if e != nil {
			t.Fatal(e)
		}
		actual, e := io.ReadAll(reader)
		reader.Close()
		if e != nil || recordSource(actual).SHA256 != hash {
			t.Fatal("independent sealed byte readback differs", e)
		}
	}
}

func FuzzRecordProjection(f *testing.F) {
	f.Add([]byte(`[{"id":"0001","amount":1.23}]`), true)
	f.Add([]byte(`[{"id":"=cmd","amount":null}]`), false)
	f.Fuzz(func(t *testing.T, body []byte, jsonOutput bool) {
		if len(body) > 65536 {
			return
		}
		source, e := Normalize(Policy{Schema: 2, Kind: "json_records", MaxBytes: 65536, MaxRows: 4, MaxRecordBytes: 1024, TimeoutSeconds: 1, Columns: []Column{{Name: "id", Type: "text", MaxBytes: 64}, {Name: "amount", Type: "decimal", MaxBytes: 64, Precision: 38, Scale: 2}}})
		if e != nil {
			t.Fatal(e)
		}
		_, hash, _ := canonical(source)
		kind := "csv"
		if jsonOutput {
			kind = "json_records"
		}
		plan := RecordProjection{Schema: 1, Kind: "record_projection", SourcePolicyHash: hash, OutputKind: kind, Columns: []ProjectionColumn{{Source: "id", Target: "account", Missing: "empty", Null: "empty"}, {Source: "amount", Target: "total", Missing: "null", Empty: "null"}}, MaxBytes: 65536, MaxRows: 4, MaxRecordBytes: 2048, TimeoutSeconds: 1}
		var out bytes.Buffer
		r, e := ProjectRecords(context.Background(), source, plan, recordSource(body), bytes.NewReader(body), &out)
		if out.Len() > 65536 {
			t.Fatal("output byte bound escaped")
		}
		if e != nil {
			if r.OutputSHA256 != "" {
				t.Fatal("failed output was qualified")
			}
			return
		}
		if r.Code != "transformed" || r.Rows != r.Source.Rows || r.OutputBytes != int64(out.Len()) || r.OutputSHA256 != recordSource(out.Bytes()).SHA256 {
			t.Fatal("qualified output identity/count differs")
		}
		if jsonOutput {
			var rows []map[string]json.RawMessage
			if json.Unmarshal(out.Bytes(), &rows) != nil || int64(len(rows)) != r.Rows {
				t.Fatal("qualified JSON cannot be independently parsed")
			}
		} else {
			rows, e := csv.NewReader(bytes.NewReader(out.Bytes())).ReadAll()
			if e != nil || int64(len(rows)) != r.Rows+1 {
				t.Fatal("qualified CSV cannot be independently parsed")
			}
		}
	})
}

const projectionInput = `[{"id":"0001","amount":12345678901234567890.12,"empty":"","null":null},{"id":"0001","amount":12345678901234567890.12,"empty":"","null":null}]`

func TestRecordProjectionExactReviewedMappingPreservesTypedMeaning(t *testing.T) {
	source, plan := projectionContract(t)
	var output bytes.Buffer
	r, e := ProjectRecords(t.Context(), source, plan, recordSource([]byte(projectionInput)), strings.NewReader(projectionInput), &output)
	want := "[{\"total\":12345678901234567890.12,\"account\":\"0001\",\"empty\":\"\",\"null\":null},{\"total\":12345678901234567890.12,\"account\":\"0001\",\"empty\":\"\",\"null\":null}]\n"
	if e != nil || r.Code != "transformed" || r.Rows != 2 || r.Source.Rows != 2 || output.String() != want || r.OutputBytes != int64(len(want)) || r.OutputSHA256 != recordSource(output.Bytes()).SHA256 {
		t.Fatal("deterministic exact projection is absent or loses meaning", r.Code, e)
	}
	decoder := json.NewDecoder(bytes.NewReader(output.Bytes()))
	decoder.UseNumber()
	var rows []map[string]any
	if decoder.Decode(&rows) != nil || len(rows) != 2 || rows[0]["account"] != "0001" || rows[0]["total"] != json.Number("12345678901234567890.12") || rows[0]["null"] != nil {
		t.Fatal("independent JSON interpretation differs")
	}
	if _, found := rows[0]["absent"]; found {
		t.Fatal("missing value silently became null")
	}
	metadata, _ := json.Marshal(r)
	if bytes.Contains(metadata, []byte("12345678901234567890")) || bytes.Contains(metadata, []byte("0001")) {
		t.Fatal("transformation report leaked raw cells")
	}
	var again bytes.Buffer
	replay, e := ProjectRecords(t.Context(), source, plan, recordSource([]byte(projectionInput)), strings.NewReader(projectionInput), &again)
	if e != nil || !bytes.Equal(output.Bytes(), again.Bytes()) || !reflect.DeepEqual(r, replay) {
		t.Fatal("same input/definition changed the result", e)
	}
}

func TestRecordProjectionRefusesAmbiguityAndBindsEveryRule(t *testing.T) {
	source, p := projectionContract(t)
	normal, e := NormalizeRecordProjection(source, p)
	if e != nil {
		t.Fatal(e)
	}
	_, hash, _ := canonical(normal)
	for _, mutate := range []func(*RecordProjection){func(p *RecordProjection) { p.Columns[0].Target = "renamed" }, func(p *RecordProjection) { p.Columns[2].Empty = "null" }, func(p *RecordProjection) { p.Columns[3].Missing = "null" }, func(p *RecordProjection) { p.Columns[4].Null = "empty" }, func(p *RecordProjection) { p.Columns[0].Conversion = "text" }, func(p *RecordProjection) { p.MaxBytes++ }} {
		q := p
		q.Columns = append([]ProjectionColumn(nil), p.Columns...)
		mutate(&q)
		n, e := NormalizeRecordProjection(source, q)
		if e != nil {
			t.Fatal(e)
		}
		_, h, _ := canonical(n)
		if h == hash {
			t.Fatal("reviewed meaning changed without changing its hash")
		}
	}
	for _, mutate := range []func(*RecordProjection){func(p *RecordProjection) { p.SourcePolicyHash = strings.Repeat("a", 64) }, func(p *RecordProjection) { p.Columns[0].Source = "AMOUNT" }, func(p *RecordProjection) { p.Columns[0].Target = p.Columns[1].Target }, func(p *RecordProjection) { p.Columns[0].Conversion = "guess" }, func(p *RecordProjection) { p.Columns[0].Missing = "execute" }, func(p *RecordProjection) { p.OutputKind = "shell" }} {
		q := p
		q.Columns = append([]ProjectionColumn(nil), p.Columns...)
		mutate(&q)
		var out bytes.Buffer
		if _, e := ProjectRecords(t.Context(), source, q, recordSource([]byte(projectionInput)), strings.NewReader(projectionInput), &out); e == nil || out.Len() != 0 {
			t.Fatal("invalid projection wrote output or inferred meaning", e)
		}
	}
	p.Columns[0].Target = "outside"
	if normal.Columns[0].Target != "total" {
		t.Fatal("normalized review retained mutable mapping storage")
	}
}

func TestRecordProjectionCSVRequiresExplicitPresenceAndRefusesFormulaCells(t *testing.T) {
	source, plan := projectionContract(t)
	plan.OutputKind = "csv"
	var output bytes.Buffer
	r, e := ProjectRecords(t.Context(), source, plan, recordSource([]byte(projectionInput)), strings.NewReader(projectionInput), &output)
	if e == nil || r.Code != "output_presence_not_representable" || r.OutputSHA256 != "" {
		t.Fatal("CSV silently collapsed missing/null", r.Code, e)
	}
	plan.Columns[3].Missing = "empty"
	plan.Columns[4].Null = "empty"
	output.Reset()
	r, e = ProjectRecords(t.Context(), source, plan, recordSource([]byte(projectionInput)), strings.NewReader(projectionInput), &output)
	if e != nil || r.Code != "transformed" {
		t.Fatal(r.Code, e)
	}
	rows, e := csv.NewReader(bytes.NewReader(output.Bytes())).ReadAll()
	if e != nil || len(rows) != 3 || rows[1][0] != "12345678901234567890.12" || rows[1][1] != "0001" {
		t.Fatal("independent CSV interpretation differs", e)
	}
	for _, value := range []string{"=1+1", "+cmd", "-cmd", "@SUM(A1:A2)", "\tname", "\rname", "\nname", "  =cmd", "\ufeff=cmd", "＝cmd", "＋cmd", "－cmd", "＠cmd", "'=cmd"} {
		body, _ := json.Marshal([]map[string]any{{"id": value, "amount": json.Number("1.00")}})
		output.Reset()
		r, e = ProjectRecords(t.Context(), source, plan, recordSource(body), bytes.NewReader(body), &output)
		if e == nil || r.Code != "unsafe_csv_text" || r.OutputSHA256 != "" {
			t.Fatal("formula-like generated CSV text passed", r.Code, e)
		}
	}
}

type projectionBrokenWriter struct{}

func (projectionBrokenWriter) Write([]byte) (int, error) { return 0, errors.New("private output path") }

func TestRecordProjectionNeverQualifiesPartialOutputOrSwallowsFailure(t *testing.T) {
	source, plan := projectionContract(t)
	for _, body := range []string{`[{"id":"0001","amount":1.00},{"id":`, projectionInput} {
		f := recordSource([]byte(body))
		if body == projectionInput {
			f.SHA256 = strings.Repeat("f", 64)
		}
		var output bytes.Buffer
		r, e := ProjectRecords(t.Context(), source, plan, f, strings.NewReader(body), &output)
		if e == nil || r.Code != "source_rejected" || r.OutputSHA256 != "" {
			t.Fatal("partial/changed source qualified output", r.Code, e)
		}
	}
	for _, mutate := range []func(*RecordProjection){func(p *RecordProjection) { p.MaxBytes = 10 }, func(p *RecordProjection) { p.MaxRecordBytes = 64 }, func(p *RecordProjection) { p.MaxRows = 1 }} {
		p := plan
		mutate(&p)
		var output bytes.Buffer
		r, e := ProjectRecords(t.Context(), source, p, recordSource([]byte(projectionInput)), strings.NewReader(projectionInput), &output)
		if e == nil || r.OutputSHA256 != "" || r.Code == "transformed" {
			t.Fatal("output budget qualified a partial artifact", r.Code, e)
		}
	}
	r, e := ProjectRecords(t.Context(), source, plan, recordSource([]byte(projectionInput)), strings.NewReader(projectionInput), projectionBrokenWriter{})
	if e == nil || r.Code != "output_unavailable" || strings.Contains(e.Error(), "private output path") {
		t.Fatal("output error was swallowed or leaked", r.Code, e)
	}
	if _, e = ProjectRecords(t.Context(), source, plan, recordSource([]byte(projectionInput)), strings.NewReader(projectionInput), nil); e == nil {
		t.Fatal("nil sink accepted")
	}
}

func TestRecordProjectionNumbersNewlinesAndPresenceRulesAreExplicit(t *testing.T) {
	source, plan := projectionContract(t)
	plan.OutputKind = "csv"
	plan.Columns = plan.Columns[:2]
	body := []byte(`[{"id":"a\r\nb","amount":-1.00}]`)
	var output bytes.Buffer
	r, e := ProjectRecords(t.Context(), source, plan, recordSource(body), bytes.NewReader(body), &output)
	if e == nil || r.Code != "csv_newline_requires_mapping" {
		t.Fatal("CSV silently normalized CRLF data", r.Code, e)
	}
	plan.Columns[1].Conversion = "normalize_lf"
	output.Reset()
	r, e = ProjectRecords(t.Context(), source, plan, recordSource(body), bytes.NewReader(body), &output)
	if e != nil || r.Code != "transformed" {
		t.Fatal("explicit LF mapping refused", r.Code, e)
	}
	rows, e := csv.NewReader(bytes.NewReader(output.Bytes())).ReadAll()
	if e != nil || len(rows) != 2 || rows[1][1] != "a\nb" || rows[1][0] != "-1.00" {
		t.Fatal("approved newline or negative numeric meaning changed", e)
	}
	for _, v := range []struct{ in, want string }{{"+0001", "1"}, {"000.0100", "0.0100"}, {"-000.00", "-0.00"}, {"0", "0"}} {
		got, e := projectionJSONNumber(v.in)
		if e != nil || got != v.want {
			t.Fatal("JSON numeric canonicalization changed value or scale", e)
		}
	}
	for _, v := range []string{"", "NaN", "1e2", "1,00", "one"} {
		if _, e := projectionJSONNumber(v); e == nil {
			t.Fatal("invalid numeric representation emitted")
		}
	}
	source, plan = projectionContract(t)
	plan.Columns = plan.Columns[2:]
	plan.Columns[0].Empty = "null"
	plan.Columns[1].Missing = "empty"
	plan.Columns[2].Null = "missing"
	output.Reset()
	r, e = ProjectRecords(t.Context(), source, plan, recordSource([]byte(projectionInput)), strings.NewReader(projectionInput), &output)
	if e != nil || output.String() != "[{\"empty\":null,\"absent\":\"\"},{\"empty\":null,\"absent\":\"\"}]\n" {
		t.Fatal("explicit one-pass presence rules changed meaning", r.Code, e)
	}
}
