// Package checks validates held immutable revisions. It never interprets file
// contents as instructions. Pure CSV parsing has no model, shell or network
// capability; scanner I/O lives behind the separate bounded scanner adapter.
package checks

import (
	"context"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

var ErrInput = errors.New("invalid intake policy or decision")
var errRecordBudget = errors.New("record byte budget exceeded")
var keyPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
var hashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var integerPattern = regexp.MustCompile(`^[+-]?[0-9]+$`)
var decimalPattern = regexp.MustCompile(`^[+-]?[0-9]+(?:\.[0-9]+)?$`)

const Engine = "freightctl-csv-v1"

func policyEngine(p Policy) string {
	if p.Schema == 5 && p.Kind == "xlsx_records" {
		return "freightctl-xlsx-records-v1"
	}
	if p.Schema == 4 && p.Kind == "xml_records" {
		return "freightctl-xml-records-v1"
	}
	if p.Schema == 3 && p.Kind == "fixed_width" {
		return "freightctl-fixed-width-v1"
	}
	if p.Schema == 2 && p.Kind == "json_records" {
		return "freightctl-json-records-v1"
	}
	return Engine
}
func policySuccess(p Policy) string {
	if p.Schema == 5 && p.Kind == "xlsx_records" {
		return "valid_xlsx_records"
	}
	if p.Schema == 4 && p.Kind == "xml_records" {
		return "valid_xml_records"
	}
	if p.Schema == 3 && p.Kind == "fixed_width" {
		return "valid_fixed_width"
	}
	if p.Schema == 2 && p.Kind == "json_records" {
		return "valid_json_records"
	}
	return "valid_csv"
}

type Column struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	Required  bool   `json:"required"`
	MaxBytes  int    `json:"max_bytes"`
	Precision int    `json:"precision,omitempty"`
	Scale     int    `json:"scale,omitempty"`
	Width     int    `json:"width_bytes,omitempty"`
	Padding   string `json:"padding,omitempty"`
}
type Policy struct {
	Schema         int                     `json:"schema_version"`
	Kind           string                  `json:"kind"`
	Columns        []Column                `json:"columns"`
	MaxBytes       int64                   `json:"max_bytes"`
	MaxRows        int64                   `json:"max_rows"`
	MaxRecordBytes int                     `json:"max_record_bytes"`
	TimeoutSeconds int                     `json:"timeout_seconds"`
	Signature      *SignaturePolicy        `json:"signature,omitempty"`
	Scanner        *store.ScannerReference `json:"scanner,omitempty"`
	XML            *XMLRecordPolicy        `json:"xml,omitempty"`
	XLSX           *XLSXPolicy             `json:"xlsx,omitempty"`
}
type XMLRecordPolicy struct {
	Root      string `json:"root"`
	Record    string `json:"record"`
	Namespace string `json:"namespace"`
}
type SignaturePolicy struct {
	Key           store.PGPReference `json:"key"`
	MaxAgeSeconds uint32             `json:"max_age_seconds,omitempty"`
}
type SignatureProof struct {
	Key          store.PGPReference      `json:"key"`
	ObjectID     string                  `json:"object_id"`
	SHA256       string                  `json:"sha256"`
	Verification *secure.PGPVerification `json:"verification"`
}
type PolicyRequest struct {
	ExpectedVersion int    `json:"expected_version"`
	Definition      Policy `json:"definition"`
}
type Report struct {
	Engine     string          `json:"engine"`
	FileID     string          `json:"file_id"`
	SHA256     string          `json:"sha256"`
	PolicyHash string          `json:"policy_hash"`
	Code       string          `json:"code"`
	Rows       int64           `json:"rows"`
	Bytes      int64           `json:"bytes_read"`
	Row        int64           `json:"row,omitempty"`
	Column     int             `json:"column,omitempty"`
	Signature  *SignatureProof `json:"signature,omitempty"`
	Scanner    *ScanProof      `json:"scanner,omitempty"`
}

func Normalize(p Policy) (Policy, error) {
	if p.Scanner != nil && (!store.ValidID(p.Scanner.ID) || p.Scanner.Version < 1 || !hashPattern.MatchString(p.Scanner.Hash)) {
		return p, ErrInput
	}
	if p.Signature != nil && (!store.ValidID(p.Signature.Key.ID) || p.Signature.Key.Version < 1 || !hashPattern.MatchString(p.Signature.Key.Hash)) {
		return p, ErrInput
	}
	fixed := p.Schema == 3 && p.Kind == "fixed_width"
	xmlRecords := p.Schema == 4 && p.Kind == "xml_records"
	xlsxRecords := p.Schema == 5 && p.Kind == "xlsx_records"
	if !(p.Schema == 1 && p.Kind == "csv" || p.Schema == 2 && p.Kind == "json_records" || fixed || xmlRecords || xlsxRecords) || len(p.Columns) < 1 || len(p.Columns) > 128 {
		return p, ErrInput
	}
	if xmlRecords && !validXMLPolicy(p.XML) || !xmlRecords && p.XML != nil {
		return p, ErrInput
	}
	if xmlRecords {
		definition := *p.XML
		p.XML = &definition
	}
	if xlsxRecords {
		var err error
		p.XLSX, err = normalizeXLSXPolicy(p.XLSX)
		if err != nil {
			return p, err
		}
	} else if p.XLSX != nil {
		return p, ErrInput
	}
	if p.MaxBytes == 0 {
		p.MaxBytes = 16 << 20
	}
	if p.MaxRows == 0 {
		p.MaxRows = 100000
	}
	if p.MaxRecordBytes == 0 {
		p.MaxRecordBytes = 64 << 10
	}
	if p.TimeoutSeconds == 0 {
		p.TimeoutSeconds = 30
	}
	if p.MaxBytes < 1 || p.MaxBytes > 1<<30 || p.MaxRows < 1 || p.MaxRows > 1000000 || p.MaxRecordBytes < 64 || p.MaxRecordBytes > 1<<20 || p.TimeoutSeconds < 1 || p.TimeoutSeconds > 60 {
		return p, ErrInput
	}
	seen := map[string]bool{}
	width := 0
	p.Columns = slices.Clone(p.Columns)
	for i, c := range p.Columns {
		if !utf8.ValidString(c.Name) || len(c.Name) < 1 || len(c.Name) > 128 || strings.TrimSpace(c.Name) != c.Name || seen[c.Name] {
			return p, ErrInput
		}
		for _, r := range c.Name {
			if unicode.IsControl(r) {
				return p, ErrInput
			}
		}
		seen[c.Name] = true
		if xmlRecords && !xmlLocalName.MatchString(c.Name) {
			return p, ErrInput
		}
		if fixed {
			if c.Width < 1 || c.Width > p.MaxRecordBytes {
				return p, ErrInput
			}
			if c.Padding == "" {
				c.Padding = "none"
			}
			if c.Padding != "none" && c.Padding != "space_left" && c.Padding != "space_right" {
				return p, ErrInput
			}
			width += c.Width
			if width+2 > p.MaxRecordBytes || c.MaxBytes > c.Width {
				return p, ErrInput
			}
		} else if c.Width != 0 || c.Padding != "" {
			return p, ErrInput
		}
		if c.MaxBytes == 0 {
			c.MaxBytes = 4096
			if fixed {
				c.MaxBytes = min(c.MaxBytes, c.Width)
			}
		}
		if c.MaxBytes < 1 || c.MaxBytes > 64<<10 || c.MaxBytes > p.MaxRecordBytes {
			return p, ErrInput
		}
		switch c.Type {
		case "text", "integer", "date":
			if c.Precision != 0 || c.Scale != 0 {
				return p, ErrInput
			}
		case "decimal":
			if c.Precision < 1 || c.Precision > 38 || c.Scale < 0 || c.Scale > c.Precision {
				return p, ErrInput
			}
		default:
			return p, ErrInput
		}
		p.Columns[i] = c
	}
	encoded, err := json.Marshal(p)
	if err != nil || len(encoded) > 12<<10 {
		return p, ErrInput
	}
	return p, nil
}

// encoding/csv buffers ahead. Resetting a budget at each Read bounds even a
// newline-free or deeply quoted record before the parser can grow with the file.
// InputOffset then enforces the exact record limit, including buffered bytes.
type budgetReader struct {
	ctx       context.Context
	reader    io.Reader
	remaining int
	total     int64
	hash      io.Writer
}

func (r *budgetReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if r.remaining <= 0 {
		return 0, errRecordBudget
	}
	if len(p) > r.remaining {
		p = p[:r.remaining]
	}
	n, err := r.reader.Read(p)
	r.remaining -= n
	r.total += int64(n)
	if n > 0 {
		if _, e := r.hash.Write(p[:n]); e != nil {
			return n, e
		}
	}
	return n, err
}
func validCell(c Column, value string) bool {
	if !utf8.ValidString(value) || strings.ContainsRune(value, 0) || len(value) > c.MaxBytes {
		return false
	}
	if value == "" {
		return !c.Required
	}
	switch c.Type {
	case "text":
		return true
	case "integer":
		return integerPattern.MatchString(value)
	case "decimal":
		if !decimalPattern.MatchString(value) {
			return false
		}
		s := strings.TrimPrefix(strings.TrimPrefix(value, "+"), "-")
		parts := strings.Split(s, ".")
		scale := 0
		if len(parts) == 2 {
			scale = len(parts[1])
		}
		digits := len(strings.TrimLeft(parts[0], "0")) + scale
		return digits <= c.Precision && scale <= c.Scale
	case "date":
		_, err := time.Parse("2006-01-02", value)
		return err == nil && len(value) == 10
	}
	return false
}

// Validate returns only counters, positions and codes, never original cell data.
// A pass requires parsing every byte and matching the accepted length and hash.
func Validate(ctx context.Context, p Policy, f store.File, policyHash string, input io.Reader) (Report, error) {
	report := Report{Engine: Engine, FileID: f.ID, SHA256: f.SHA256, PolicyHash: policyHash}
	var err error
	p, err = Normalize(p)
	if err != nil {
		return report, err
	}
	report.Engine = policyEngine(p)
	ctx, cancel := context.WithTimeout(ctx, time.Duration(p.TimeoutSeconds)*time.Second)
	defer cancel()
	if err = ctx.Err(); err != nil {
		return report, err
	}
	if f.Size > p.MaxBytes {
		report.Code = "file_byte_limit"
		return report, nil
	}
	if p.Schema == 2 && p.Kind == "json_records" {
		return validateJSONRecords(ctx, p, f, policyHash, input)
	}
	if p.Schema == 3 && p.Kind == "fixed_width" {
		return validateFixedWidth(ctx, p, f, policyHash, input)
	}
	if p.Schema == 4 && p.Kind == "xml_records" {
		return validateXMLRecords(ctx, p, f, policyHash, input)
	}
	if p.Schema == 5 && p.Kind == "xlsx_records" {
		return validateXLSXIntake(ctx, p, f, policyHash, input)
	}
	h := secure.NewDigest()
	b := &budgetReader{ctx: ctx, reader: io.LimitReader(input, p.MaxBytes+1), hash: h}
	parser := csv.NewReader(b)
	parser.FieldsPerRecord = len(p.Columns)
	parser.ReuseRecord = true
	read := func() ([]string, error) {
		b.remaining = p.MaxRecordBytes + 4096
		before := parser.InputOffset()
		row, err := parser.Read()
		if parser.InputOffset()-before > int64(p.MaxRecordBytes) {
			return nil, errRecordBudget
		}
		return row, err
	}
	header, err := read()
	if err != nil {
		if ctx.Err() != nil {
			return report, ctx.Err()
		}
		report.Code = "invalid_header"
		report.Bytes = b.total
		return report, nil
	}
	for i, c := range p.Columns {
		if header[i] != c.Name {
			report.Code = "header_mismatch"
			report.Column = i + 1
			report.Bytes = b.total
			return report, nil
		}
	}
	for {
		cells, err := read()
		report.Bytes = b.total
		if errors.Is(err, io.EOF) {
			break
		}
		if ctx.Err() != nil {
			return report, ctx.Err()
		}
		if err != nil {
			report.Code = "malformed_csv"
			if errors.Is(err, errRecordBudget) {
				report.Code = "record_byte_limit"
			}
			report.Row = report.Rows + 2
			return report, nil
		}
		report.Rows++
		if report.Rows > p.MaxRows {
			report.Code = "row_limit"
			report.Row = report.Rows + 1
			return report, nil
		}
		for i, c := range p.Columns {
			if !validCell(c, cells[i]) {
				report.Code = "invalid_cell"
				report.Row = report.Rows + 1
				report.Column = i + 1
				return report, nil
			}
		}
	}
	if b.total != f.Size || hex.EncodeToString(h.Sum(nil)) != f.SHA256 {
		report.Code = "source_integrity_changed"
		return report, nil
	}
	report.Code = "valid_csv"
	return report, nil
}
