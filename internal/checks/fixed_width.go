package checks

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"strings"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

func validateFixedWidth(ctx context.Context, p Policy, file store.File, policyHash string, input io.Reader, visit RecordVisitor) (Report, error) {
	report := Report{Engine: policyEngine(p), FileID: file.ID, SHA256: file.SHA256, PolicyHash: policyHash}
	hash := secure.NewDigest()
	bounded := &budgetReader{ctx: ctx, reader: io.LimitReader(input, p.MaxBytes+1), hash: hash}
	reader := bufio.NewReaderSize(bounded, 4096)
	width := 0
	for _, c := range p.Columns {
		width += c.Width
	}
	record := make([]byte, 0, min(width+2, 4096))
	for {
		bounded.remaining = p.MaxRecordBytes + 4096
		record = record[:0]
		var err error
		for {
			var part []byte
			part, err = reader.ReadSlice('\n')
			report.Bytes = bounded.total
			if len(record)+len(part) > p.MaxRecordBytes || errors.Is(err, errRecordBudget) {
				report.Code, report.Row = "record_byte_limit", report.Rows+1
				return report, nil
			}
			record = append(record, part...)
			if !errors.Is(err, bufio.ErrBufferFull) {
				break
			}
		}
		if ctx.Err() != nil {
			return report, ctx.Err()
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return report, err
		}
		if errors.Is(err, io.EOF) && len(record) == 0 {
			break
		}
		if bounded.total > p.MaxBytes {
			report.Code, report.Row = "file_byte_limit", report.Rows+1
			return report, nil
		}
		if record[len(record)-1] == '\n' {
			record = record[:len(record)-1]
			if len(record) > 0 && record[len(record)-1] == '\r' {
				record = record[:len(record)-1]
			}
		}
		if bytes.IndexByte(record, '\r') >= 0 {
			report.Code, report.Row = "invalid_line_ending", report.Rows+1
			return report, nil
		}
		if len(record) != width {
			report.Code, report.Row = "invalid_record_width", report.Rows+1
			return report, nil
		}
		report.Rows++
		if report.Rows > p.MaxRows {
			report.Code, report.Row = "row_limit", report.Rows
			return report, nil
		}
		offset := 0
		var values []RecordCell
		if visit != nil {
			values = make([]RecordCell, len(p.Columns))
		}
		for i, c := range p.Columns {
			value := string(record[offset : offset+c.Width])
			offset += c.Width
			switch c.Padding {
			case "space_left":
				value = strings.TrimLeft(value, " ")
			case "space_right":
				value = strings.TrimRight(value, " ")
			}
			if !validCell(c, value) {
				report.Code, report.Row, report.Column = "invalid_cell", report.Rows, i+1
				return report, nil
			}
			if visit != nil {
				values[i] = RecordCell{Presence: CellValue, Value: value}
			}
		}
		if err = emitRecord(visit, report.Rows, values); err != nil {
			report.Code = "record_consumer_failed"
			return report, err
		}
	}
	if bounded.total != file.Size || hex.EncodeToString(hash.Sum(nil)) != file.SHA256 {
		report.Code = "source_integrity_changed"
		return report, nil
	}
	report.Code = policySuccess(p)
	return report, nil
}
