package checks

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"unicode/utf8"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

// RawMessage has already passed the JSON scanner. Check escaped UTF-16 pairs
// too:encoding/json otherwise replaces lone surrogates with replacement runes.
func validJSONRecordUnicode(raw []byte) bool {
	if !utf8.Valid(raw) {
		return false
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			return false
		}
		if raw[i] != 'u' {
			continue
		}
		if i+4 >= len(raw) {
			return false
		}
		n, err := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		if err != nil || n >= 0xdc00 && n <= 0xdfff {
			return false
		}
		i += 4
		if n >= 0xd800 && n <= 0xdbff {
			if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return false
			}
			low, err := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}

func checkJSONRecord(raw []byte, columns []Column, indices map[string]int, collect bool) (string, int, []RecordCell) {
	if !validJSONRecordUnicode(raw) {
		return "malformed_json", 0, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return "non_object_record", 0, nil
	}
	seen := make([]bool, len(columns))
	var cells []RecordCell
	if collect {
		cells = make([]RecordCell, len(columns))
		for i := range cells {
			cells[i].Presence = CellMissing
		}
	}
	for decoder.More() {
		key, err := decoder.Token()
		name, stringKey := key.(string)
		if err != nil || !stringKey {
			return "malformed_json", 0, nil
		}
		index, found := indices[name]
		if !found {
			return "unknown_field", 0, nil
		}
		if seen[index] {
			return "duplicate_field", index + 1, nil
		}
		seen[index] = true
		value, err := decoder.Token()
		if err != nil {
			return "malformed_json", index + 1, nil
		}
		column := columns[index]
		if value == nil {
			if collect {
				cells[index].Presence = CellNull
			}
			if column.Required {
				return "invalid_cell", index + 1, nil
			}
			continue
		}
		var cell string
		switch column.Type {
		case "text", "date":
			text, ok := value.(string)
			if !ok {
				return "invalid_cell", index + 1, nil
			}
			cell = text
		case "integer", "decimal":
			number, ok := value.(json.Number)
			if !ok {
				return "invalid_cell", index + 1, nil
			}
			cell = string(number)
		default:
			return "invalid_cell", index + 1, nil
		}
		if !validCell(column, cell) {
			return "invalid_cell", index + 1, nil
		}
		if collect {
			cells[index] = RecordCell{Presence: CellValue, Value: cell}
		}
	}
	if end, err := decoder.Token(); err != nil || end != json.Delim('}') {
		return "malformed_json", 0, nil
	}
	for i, column := range columns {
		if column.Required && !seen[i] {
			return "missing_field", i + 1, nil
		}
	}
	return "", 0, cells
}

func validateJSONRecords(ctx context.Context, p Policy, file store.File, policyHash string, input io.Reader, visit RecordVisitor) (Report, error) {
	report := Report{Engine: policyEngine(p), FileID: file.ID, SHA256: file.SHA256, PolicyHash: policyHash}
	hash := secure.NewDigest()
	bounded := &budgetReader{ctx: ctx, reader: io.LimitReader(input, p.MaxBytes+1), hash: hash, remaining: p.MaxRecordBytes + 4096}
	decoder := json.NewDecoder(bounded)
	fail := func(err error) (Report, error) {
		report.Bytes = bounded.total
		report.Row = report.Rows + 1
		if ctx.Err() != nil {
			return report, ctx.Err()
		}
		report.Code = "malformed_json"
		if errors.Is(err, errRecordBudget) {
			report.Code = "record_byte_limit"
		}
		return report, nil
	}
	start, err := decoder.Token()
	if err != nil || start != json.Delim('[') {
		return fail(err)
	}
	indices := make(map[string]int, len(p.Columns))
	for i, column := range p.Columns {
		indices[column.Name] = i
	}
	for {
		bounded.remaining = p.MaxRecordBytes + 4096
		before := decoder.InputOffset()
		if !decoder.More() {
			break
		}
		var raw json.RawMessage
		if err = decoder.Decode(&raw); err != nil {
			return fail(err)
		}
		report.Bytes = bounded.total
		if len(raw) > p.MaxRecordBytes || decoder.InputOffset()-before > int64(p.MaxRecordBytes) {
			report.Code, report.Row = "record_byte_limit", report.Rows+1
			return report, nil
		}
		report.Rows++
		if report.Rows > p.MaxRows {
			report.Code, report.Row = "row_limit", report.Rows
			return report, nil
		}
		code, column, cells := checkJSONRecord(raw, p.Columns, indices, visit != nil)
		if code != "" {
			report.Code, report.Row, report.Column = code, report.Rows, column
			return report, nil
		}
		if err = emitRecord(visit, report.Rows, cells); err != nil {
			report.Code = "record_consumer_failed"
			return report, err
		}
		if err = ctx.Err(); err != nil {
			return report, err
		}
	}
	if end, err := decoder.Token(); err != nil || end != json.Delim(']') {
		return fail(err)
	}
	bounded.remaining = p.MaxRecordBytes + 4096
	var trailing json.RawMessage
	if err = decoder.Decode(&trailing); err != io.EOF {
		return fail(err)
	}
	report.Bytes = bounded.total
	if bounded.total != file.Size || hex.EncodeToString(hash.Sum(nil)) != file.SHA256 {
		report.Code = "source_integrity_changed"
		return report, nil
	}
	report.Code = policySuccess(p)
	return report, nil
}
