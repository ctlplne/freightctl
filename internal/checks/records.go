package checks

import (
	"context"
	"io"
	"slices"

	"github.com/ctlplne/freightctl/internal/store"
)

type CellPresence string

const (
	CellMissing CellPresence = "missing"
	CellNull    CellPresence = "null"
	CellValue   CellPresence = "value"
)

// RecordCell preserves source presence separately from the scalar text. The
// approved column determines its type. Values are transient content,not metadata.
type RecordCell struct {
	Presence CellPresence `json:"-"`
	Value    string       `json:"-"`
}

type Record struct {
	Number int64        `json:"-"`
	Cells  []RecordCell `json:"-"`
}

type RecordVisitor func(Record) error

type recordConsumerError struct{ cause error }

func (e *recordConsumerError) Error() string { return "record consumer failed" }
func (e *recordConsumerError) Unwrap() error { return e.cause }

func emitRecord(visit RecordVisitor, number int64, cells []RecordCell) error {
	if visit == nil {
		return nil
	}
	// A callback may retain or change its own row without changing parser state
	// or another row. Strings retain the exact immutable scalar representation.
	if err := visit(Record{Number: number, Cells: slices.Clone(cells)}); err != nil {
		return &recordConsumerError{err}
	}
	return nil
}

// StreamRecords runs the SAME validator as Validate and supplies validated rows
// to a trusted in-process consumer. A row is not durable acceptance or proof of
// the whole source:an invalid suffix,changed source or later member failure can
// still reject the report. Consumers must write only private staging and discard
// it unless the complete report passes. Source authority,required crypto/scanner
// checks,custody acceptance and separate release remain the caller's obligations.
func StreamRecords(ctx context.Context, p Policy, file store.File, policyHash string, input io.Reader, visit RecordVisitor) (Report, error) {
	if visit == nil || input == nil {
		return Report{}, ErrInput
	}
	return validateRecords(ctx, p, file, policyHash, input, visit)
}
