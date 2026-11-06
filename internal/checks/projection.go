package checks

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"slices"
	"strings"
	"time"
	"unicode"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

const ProjectionEngine = "freightctl-record-projection-v1"

type ProjectionColumn struct {
	Source     string `json:"source"`
	Target     string `json:"target"`
	Conversion string `json:"conversion"`
	Missing    string `json:"missing"`
	Null       string `json:"null"`
	Empty      string `json:"empty"`
}

// RecordProjection is declarative data mapping,never code or execution authority.
// Names are exact;order is explicit;presence conversions require a changed hash.
type RecordProjection struct {
	Schema           int                `json:"schema_version"`
	Kind             string             `json:"kind"`
	Engine           string             `json:"engine"`
	SourcePolicyHash string             `json:"source_policy_hash"`
	OutputKind       string             `json:"output_kind"`
	Columns          []ProjectionColumn `json:"columns"`
	MaxBytes         int64              `json:"max_bytes"`
	MaxRecordBytes   int                `json:"max_record_bytes"`
	MaxRows          int64              `json:"max_rows"`
	TimeoutSeconds   int                `json:"timeout_seconds"`
}

type ProjectionReport struct {
	Engine             string `json:"engine"`
	DefinitionHash     string `json:"definition_hash"`
	Source             Report `json:"source"`
	OutputKind         string `json:"output_kind"`
	OutputContractHash string `json:"output_contract_hash"`
	Code               string `json:"code"`
	Rows               int64  `json:"rows"`
	Row                int64  `json:"row,omitempty"`
	Column             int    `json:"column,omitempty"`
	OutputBytes        int64  `json:"output_bytes"`
	OutputSHA256       string `json:"output_sha256,omitempty"`
}

type projectionProblem struct {
	code   string
	row    int64
	column int
}

func (e *projectionProblem) Error() string { return e.code }
func projectionFailure(code string) error  { return &projectionProblem{code: code} }

func NormalizeRecordProjection(source Policy, p RecordProjection) (RecordProjection, error) {
	source, err := Normalize(source)
	if err != nil {
		return p, ErrInput
	}
	_, sourceHash, err := canonical(source)
	if p.Engine == "" {
		p.Engine = ProjectionEngine
	}
	if err != nil || p.Schema != 1 || p.Kind != "record_projection" || p.Engine != ProjectionEngine || p.SourcePolicyHash != sourceHash || p.OutputKind != "json_records" && p.OutputKind != "csv" || len(p.Columns) < 1 || len(p.Columns) > 128 {
		return p, ErrInput
	}
	if p.MaxBytes == 0 {
		p.MaxBytes = source.MaxBytes
	}
	if p.MaxRecordBytes == 0 {
		p.MaxRecordBytes = source.MaxRecordBytes
	}
	if p.MaxRows == 0 {
		p.MaxRows = source.MaxRows
	}
	if p.TimeoutSeconds == 0 {
		p.TimeoutSeconds = source.TimeoutSeconds
	}
	p.Columns = slices.Clone(p.Columns)
	indices := map[string]int{}
	for i, c := range source.Columns {
		indices[c.Name] = i
	}
	for i, m := range p.Columns {
		index, found := indices[m.Source]
		if !found {
			return p, ErrInput
		}
		if m.Conversion == "" {
			m.Conversion = "identity"
		}
		if m.Missing == "" {
			m.Missing = "preserve"
		}
		if m.Null == "" {
			m.Null = "preserve"
		}
		if m.Empty == "" {
			m.Empty = "preserve"
		}
		if !slices.Contains([]string{"identity", "text", "normalize_lf"}, m.Conversion) || m.Conversion == "normalize_lf" && source.Columns[index].Type != "text" || !slices.Contains([]string{"preserve", "empty", "null", "error"}, m.Missing) || !slices.Contains([]string{"preserve", "empty", "missing", "error"}, m.Null) || !slices.Contains([]string{"preserve", "missing", "null", "error"}, m.Empty) {
			return p, ErrInput
		}
		if p.OutputKind == "csv" && unsafeCSVText(m.Target) {
			return p, ErrInput
		}
		p.Columns[i] = m
	}
	if _, err = projectionOutputPolicy(source, p); err != nil {
		return p, ErrInput
	}
	b, err := json.Marshal(p)
	if err != nil || len(b) > 32<<10 {
		return p, ErrInput
	}
	return p, nil
}

func projectionOutputPolicy(source Policy, p RecordProjection) (Policy, error) {
	indices := map[string]Column{}
	for _, c := range source.Columns {
		indices[c.Name] = c
	}
	columns := make([]Column, len(p.Columns))
	for i, m := range p.Columns {
		c, found := indices[m.Source]
		if !found {
			return Policy{}, ErrInput
		}
		c.Name, c.Width, c.Padding = m.Target, 0, ""
		// A smaller output record budget narrows accepted output,never truncates
		// a scalar. Actual serialized rows still have to fit in full.
		c.MaxBytes = min(c.MaxBytes, p.MaxRecordBytes)
		if m.Conversion == "text" {
			c.Type, c.Precision, c.Scale = "text", 0, 0
		}
		columns[i] = c
	}
	schema := 2
	if p.OutputKind == "csv" {
		schema = 1
	}
	// This is a DATA contract,not an intake/release policy. The custody caller
	// must separately bind the current output policy and fresh protected checks.
	return Normalize(Policy{Schema: schema, Kind: p.OutputKind, Columns: columns, MaxBytes: p.MaxBytes, MaxRows: p.MaxRows, MaxRecordBytes: p.MaxRecordBytes, TimeoutSeconds: p.TimeoutSeconds})
}

type projectionWriter struct {
	ctx            context.Context
	out            io.Writer
	hash           hash.Hash
	maximum, count int64
}

func (w *projectionWriter) Write(b []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	if int64(len(b)) > w.maximum-w.count {
		return 0, projectionFailure("output_byte_limit")
	}
	n, err := w.out.Write(b)
	if n < 0 || n > len(b) {
		return 0, projectionFailure("output_unavailable")
	}
	if n > 0 {
		w.count += int64(n)
		_, _ = w.hash.Write(b[:n])
	}
	if err != nil || n != len(b) {
		return n, projectionFailure("output_unavailable")
	}
	return n, nil
}

type projectionRow struct {
	bytes.Buffer
	maximum int
}

func (w *projectionRow) Write(b []byte) (int, error) {
	if len(b) > w.maximum-w.Len() {
		return 0, projectionFailure("output_record_limit")
	}
	return w.Buffer.Write(b)
}
func (w *projectionRow) append(b []byte) error { _, err := w.Write(b); return err }

// ProjectRecords writes ONLY to caller-owned private staging. It always returns
// a non-nil error on incomplete/rejected output,so StageGenerated cannot seal a
// valid prefix by mistake. A completed report is still no custody acceptance,
// permission,signature/scanner verdict,publication or delivery receipt.
func ProjectRecords(ctx context.Context, source Policy, definition RecordProjection, file store.File, input io.Reader, output io.Writer) (ProjectionReport, error) {
	r := ProjectionReport{Engine: ProjectionEngine, OutputKind: definition.OutputKind}
	if output == nil || input == nil {
		return r, ErrInput
	}
	source, err := Normalize(source)
	if err != nil {
		return r, err
	}
	p, err := NormalizeRecordProjection(source, definition)
	if err != nil {
		return r, err
	}
	_, r.DefinitionHash, _ = canonical(p)
	shape, err := projectionOutputPolicy(source, p)
	if err != nil {
		return r, err
	}
	_, r.OutputContractHash, _ = canonical(shape)
	ctx, cancel := context.WithTimeout(ctx, time.Duration(p.TimeoutSeconds)*time.Second)
	defer cancel()
	w := &projectionWriter{ctx: ctx, out: output, hash: secure.NewDigest(), maximum: p.MaxBytes}
	finish := func(err error) (ProjectionReport, error) {
		r.OutputBytes = w.count
		if ctx.Err() != nil {
			r.Code = "projection_interrupted"
			return r, ctx.Err()
		}
		if err != nil {
			var problem *projectionProblem
			if errors.As(err, &problem) {
				r.Code, r.Row, r.Column = problem.code, problem.row, problem.column
				return r, problem
			}
			r.Code = "source_unavailable"
			return r, projectionFailure(r.Code)
		}
		if r.Source.Code != policySuccess(source) || r.Source.Rows != r.Rows {
			r.Code = "source_rejected"
			return r, projectionFailure(r.Code)
		}
		r.Code = "transformed"
		r.OutputSHA256 = hex.EncodeToString(w.hash.Sum(nil))
		return r, nil
	}
	indices := map[string]int{}
	for i, c := range source.Columns {
		indices[c.Name] = i
	}
	if p.OutputKind == "json_records" {
		_, err = w.Write([]byte("["))
	} else {
		header := make([]string, len(p.Columns))
		for i, c := range p.Columns {
			header[i] = c.Target
		}
		var row []byte
		row, err = projectionCSVRow(header, p.MaxRecordBytes)
		if err == nil {
			_, err = w.Write(row)
		}
	}
	if err != nil {
		return finish(err)
	}
	r.Source, err = StreamRecords(ctx, source, file, p.SourcePolicyHash, input, func(record Record) error {
		if record.Number != r.Rows+1 || len(record.Cells) != len(source.Columns) {
			return projectionFailure("invalid_record_stream")
		}
		if record.Number > p.MaxRows {
			return &projectionProblem{code: "output_row_limit", row: record.Number}
		}
		cells := make([]RecordCell, len(p.Columns))
		for i, m := range p.Columns {
			cell := record.Cells[indices[m.Source]]
			var e error
			cells[i], e = projectCell(cell, m)
			if e != nil {
				return &projectionProblem{code: "presence_mapping_refused", row: record.Number, column: i + 1}
			}
		}
		var row []byte
		var e error
		if p.OutputKind == "json_records" {
			row, e = projectionJSONRow(shape.Columns, cells, p.MaxRecordBytes)
		} else {
			values := make([]string, len(cells))
			for i, c := range cells {
				if c.Presence != CellValue {
					return &projectionProblem{code: "output_presence_not_representable", row: record.Number, column: i + 1}
				}
				if shape.Columns[i].Type == "text" && unsafeCSVText(c.Value) {
					return &projectionProblem{code: "unsafe_csv_text", row: record.Number, column: i + 1}
				}
				if strings.Contains(c.Value, "\r\n") {
					return &projectionProblem{code: "csv_newline_requires_mapping", row: record.Number, column: i + 1}
				}
				values[i] = c.Value
			}
			row, e = projectionCSVRow(values, p.MaxRecordBytes)
		}
		if e != nil {
			var problem *projectionProblem
			if errors.As(e, &problem) {
				problem.row = record.Number
			}
			return e
		}
		if p.OutputKind == "json_records" && r.Rows > 0 {
			if _, e = w.Write([]byte(",")); e != nil {
				return e
			}
		}
		if _, e = w.Write(row); e != nil {
			return e
		}
		r.Rows++
		return nil
	})
	if err != nil || r.Source.Code != policySuccess(source) {
		return finish(err)
	}
	if p.OutputKind == "json_records" {
		_, err = w.Write([]byte("]\n"))
	}
	return finish(err)
}

func projectCell(c RecordCell, m ProjectionColumn) (RecordCell, error) {
	if c.Presence != CellValue && c.Value != "" {
		return c, ErrInput
	}
	var rule string
	switch c.Presence {
	case CellMissing:
		rule = m.Missing
	case CellNull:
		rule = m.Null
	case CellValue:
		if c.Value == "" {
			rule = m.Empty
		} else {
			if m.Conversion == "normalize_lf" {
				c.Value = strings.ReplaceAll(strings.ReplaceAll(c.Value, "\r\n", "\n"), "\r", "\n")
			}
			return c, nil
		}
	default:
		return c, ErrInput
	}
	switch rule {
	case "preserve":
		return c, nil
	case "empty":
		return RecordCell{Presence: CellValue}, nil
	case "null":
		return RecordCell{Presence: CellNull}, nil
	case "missing":
		return RecordCell{Presence: CellMissing}, nil
	default:
		return c, ErrInput
	}
}

func projectionJSONRow(columns []Column, cells []RecordCell, maximum int) ([]byte, error) {
	b := &projectionRow{maximum: maximum}
	if err := b.append([]byte("{")); err != nil {
		return nil, err
	}
	fields := 0
	for i, c := range cells {
		if c.Presence == CellMissing {
			continue
		}
		if fields > 0 {
			if err := b.append([]byte(",")); err != nil {
				return nil, err
			}
		}
		name, _ := json.Marshal(columns[i].Name)
		if err := b.append(name); err != nil {
			return nil, err
		}
		if err := b.append([]byte(":")); err != nil {
			return nil, err
		}
		var value []byte
		if c.Presence == CellNull {
			value = []byte("null")
		} else if columns[i].Type == "integer" || columns[i].Type == "decimal" {
			number, e := projectionJSONNumber(c.Value)
			if e != nil {
				return nil, &projectionProblem{code: "empty_numeric_requires_rule", column: i + 1}
			}
			value = []byte(number)
		} else {
			value, _ = json.Marshal(c.Value)
		}
		if err := b.append(value); err != nil {
			return nil, err
		}
		fields++
	}
	if err := b.append([]byte("}")); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func projectionJSONNumber(value string) (string, error) {
	if !decimalPattern.MatchString(value) {
		return "", ErrInput
	}
	negative := strings.HasPrefix(value, "-")
	value = strings.TrimPrefix(strings.TrimPrefix(value, "+"), "-")
	parts := strings.SplitN(value, ".", 2)
	integer := strings.TrimLeft(parts[0], "0")
	if integer == "" {
		integer = "0"
	}
	if negative {
		integer = "-" + integer
	}
	if len(parts) == 2 {
		integer += "." + parts[1]
	}
	return integer, nil
}

func projectionCSVRow(values []string, maximum int) ([]byte, error) {
	b := &projectionRow{maximum: maximum}
	w := csv.NewWriter(b)
	// LF record separators preserve LF cells and bare CR data. CRLF scalar text
	// requires explicit newline mapping because ordinary CSV readers normalize it.
	if err := w.Write(values); err != nil {
		return nil, err
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func unsafeCSVText(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) {
			return true
		}
		if unicode.IsSpace(r) || unicode.Is(unicode.Cf, r) || r == '\'' || r == '\uff07' {
			continue
		}
		return strings.ContainsRune("=+-@＝＋－＠", r)
	}
	return false
}
