package workflow

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ctlplne/freightctl/internal/recordplan"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/vpath"
	"golang.org/x/text/unicode/norm"
)

type ProcessingTask struct {
	ID           string                `json:"id"`
	Kind         string                `json:"kind"`
	Definition   recordplan.Projection `json:"definition"`
	OutputPolicy Reference             `json:"output_policy"`
	TargetPath   string                `json:"target_path"`
	Reason       string                `json:"reason"`
}
type ProcessingObservation struct {
	ID       string `json:"projection_id"`
	Hash     string `json:"definition_hash"`
	State    string `json:"state"`
	Revision int64  `json:"revision"`
	Attempts int    `json:"attempts"`
	FileID   string `json:"output_file_id,omitempty"`
	Current  bool   `json:"current"`
}
type ProcessingPort interface {
	ValidateProcessing(context.Context, *store.Transaction, ProcessingTask, string) (json.RawMessage, error)
	StageProcessing(context.Context, *store.Transaction, *store.WorkflowRun, ProcessingTask) (*store.RecordProjection, error)
	WorkProcessing(context.Context, store.Scope, store.WorkflowProcessing, int64, string) (*store.RecordProjection, error)
	ObserveProcessing(context.Context, *store.Transaction, *store.WorkflowRun, store.WorkflowProcessing) (*ProcessingObservation, error)
}

func normalizeProcessing(t ProcessingTask) (ProcessingTask, error) {
	p := t.Definition
	if !stepPattern.MatchString(t.ID) || t.Kind != "records.project" || !store.ValidID(t.OutputPolicy.ID) || t.OutputPolicy.Version < 1 || !hashPattern.MatchString(t.OutputPolicy.Hash) || p.Schema != 1 || p.Kind != "record_projection" || p.Engine != "freightctl-record-projection-v1" || !hashPattern.MatchString(p.SourcePolicyHash) || !slices.Contains([]string{"csv", "json_records"}, p.OutputKind) || len(p.Columns) < 1 || len(p.Columns) > 128 || p.MaxBytes < 1 || p.MaxBytes > 1<<30 || p.MaxRows < 1 || p.MaxRows > 1000000 || p.MaxRecordBytes < 64 || p.MaxRecordBytes > 1<<20 || p.TimeoutSeconds < 1 || p.TimeoutSeconds > 60 {
		return t, ErrInput
	}
	p.Columns = slices.Clone(p.Columns)
	seen := map[string]bool{}
	for i, c := range p.Columns {
		for _, name := range []string{c.Source, c.Target} {
			if !utf8.ValidString(name) || len(name) < 1 || len(name) > 128 || strings.TrimSpace(name) != name || strings.IndexFunc(name, unicode.IsControl) >= 0 {
				return t, ErrInput
			}
		}
		if seen[c.Target] {
			return t, ErrInput
		}
		seen[c.Target] = true
		if c.Conversion == "" {
			c.Conversion = "identity"
		}
		if c.Missing == "" {
			c.Missing = "preserve"
		}
		if c.Null == "" {
			c.Null = "preserve"
		}
		if c.Empty == "" {
			c.Empty = "preserve"
		}
		if !slices.Contains([]string{"identity", "text", "normalize_lf"}, c.Conversion) || !slices.Contains([]string{"preserve", "empty", "null", "error"}, c.Missing) || !slices.Contains([]string{"preserve", "empty", "missing", "error"}, c.Null) || !slices.Contains([]string{"preserve", "missing", "null", "error"}, c.Empty) {
			return t, ErrInput
		}
		p.Columns[i] = c
	}
	t.Definition = p
	t.Reason = norm.NFC.String(strings.TrimSpace(t.Reason))
	if !utf8.ValidString(t.Reason) || len(t.Reason) < 3 || len(t.Reason) > 1024 || utf8.RuneCountInString(t.Reason) > 240 || strings.IndexFunc(t.Reason, unicode.IsControl) >= 0 {
		return t, ErrInput
	}
	if t.TargetPath != "" {
		path, err := vpath.Canonical(t.TargetPath)
		if err != nil || path == "/" || vpath.ControlPath(path) {
			return t, ErrInput
		}
		t.TargetPath = path
	}
	return t, nil
}
