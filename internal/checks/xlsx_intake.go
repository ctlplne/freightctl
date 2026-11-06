package checks

import (
	"context"
	"encoding/hex"
	"io"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/zipcontainer"
)

type XLSXPolicy struct {
	Sheet             string `json:"sheet"`
	DateMode          string `json:"date_mode"`
	MaxParts          int    `json:"max_parts"`
	MaxDirectoryBytes int64  `json:"max_directory_bytes"`
	MaxPartBytes      int64  `json:"max_part_bytes"`
	MaxExpandedBytes  int64  `json:"max_expanded_bytes"`
	MaxExpansionRatio uint32 `json:"max_expansion_ratio"`
	MaxSharedStrings  int    `json:"max_shared_strings"`
	MaxSharedBytes    int64  `json:"max_shared_bytes"`
}

func normalizeXLSXPolicy(p *XLSXPolicy) (*XLSXPolicy, error) {
	if p == nil {
		return nil, ErrInput
	}
	x := *p
	if !validSheetName(x.Sheet) || x.DateMode != "iso_text" && x.DateMode != "serial_1900" && x.DateMode != "serial_1904" {
		return nil, ErrInput
	}
	if x.MaxParts == 0 {
		x.MaxParts = 256
	}
	if x.MaxDirectoryBytes == 0 {
		x.MaxDirectoryBytes = 1 << 20
	}
	if x.MaxPartBytes == 0 {
		x.MaxPartBytes = 32 << 20
	}
	if x.MaxExpandedBytes == 0 {
		x.MaxExpandedBytes = 64 << 20
	}
	if x.MaxExpansionRatio == 0 {
		x.MaxExpansionRatio = 100
	}
	if x.MaxSharedStrings == 0 {
		x.MaxSharedStrings = 100000
	}
	if x.MaxSharedBytes == 0 {
		x.MaxSharedBytes = 8 << 20
	}
	if x.MaxParts < 1 || x.MaxParts > 4096 || x.MaxDirectoryBytes < 1 || x.MaxDirectoryBytes > 16<<20 || x.MaxPartBytes < 1 || x.MaxPartBytes > x.MaxExpandedBytes || x.MaxExpandedBytes < 1 || x.MaxExpandedBytes > 1<<30 || x.MaxExpansionRatio < 1 || x.MaxExpansionRatio > 10000 || x.MaxSharedStrings < 1 || x.MaxSharedStrings > 1000000 || x.MaxSharedBytes < 1 || x.MaxSharedBytes > x.MaxExpandedBytes || x.MaxSharedBytes > 64<<20 {
		return nil, ErrInput
	}
	return &x, nil
}

func xlsxContract(p Policy) XLSXContract {
	x := p.XLSX
	return XLSXContract{Sheet: x.Sheet, DateMode: x.DateMode, Columns: p.Columns, MaxRows: p.MaxRows, MaxRecordBytes: p.MaxRecordBytes, MaxSharedStrings: x.MaxSharedStrings, MaxSharedBytes: x.MaxSharedBytes, Container: zipcontainer.Limits{MaxBytes: p.MaxBytes, MaxEntries: x.MaxParts, MaxDirectoryBytes: x.MaxDirectoryBytes, MaxEntryBytes: x.MaxPartBytes, MaxExpandedBytes: x.MaxExpandedBytes, MaxRatio: x.MaxExpansionRatio, MaxNameBytes: 256, MaxDepth: 8}}
}

func validateXLSXIntake(ctx context.Context, p Policy, file store.File, policyHash string, input io.Reader) (Report, error) {
	report := Report{Engine: policyEngine(p), FileID: file.ID, SHA256: file.SHA256, PolicyHash: policyHash}
	source, ok := input.(io.ReaderAt)
	if !ok {
		return report, ErrInput
	}
	// Hash the complete supplied source without buffering or spooling it. The
	// ordinary custody service supplies an already verified immutable *os.File.
	h := secure.NewDigest()
	b := &budgetReader{ctx: ctx, reader: io.NewSectionReader(source, 0, p.MaxBytes+1), remaining: int(p.MaxBytes + 1), hash: h}
	n, err := io.CopyBuffer(io.Discard, b, make([]byte, 32<<10))
	report.Bytes = n
	if ctx.Err() != nil {
		return report, ctx.Err()
	}
	if n > p.MaxBytes {
		report.Code = "file_byte_limit"
		return report, nil
	}
	if err != nil {
		report.Code = "source_read_failed"
		return report, zipcontainer.ErrUnavailable
	}
	if n != file.Size || hex.EncodeToString(h.Sum(nil)) != file.SHA256 {
		report.Code = "source_integrity_changed"
		return report, nil
	}
	r, err := ValidateXLSX(ctx, xlsxContract(p), source, n)
	report.Code, report.Rows, report.Row, report.Column = r.Code, r.Rows, r.Row, r.Column
	return report, err
}
