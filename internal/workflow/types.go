// Package workflow is the shared typed configuration and execution boundary.
// Definitions contain registered connection references, never executable code or
// model-granted authority. The first executor supports ordered SFTP deliveries.
package workflow

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ctlplne/freightctl/internal/store"
	"golang.org/x/text/unicode/norm"
)

var ErrInput = errors.New("invalid typed workflow request")
var keyPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
var stepPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
var filenamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
var hashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Reference struct {
	ID      string `json:"id"`
	Version int    `json:"version"`
	Hash    string `json:"hash"`
}
type Step struct {
	ID         string                  `json:"id"`
	Kind       string                  `json:"kind"`
	Connection Reference               `json:"connection"`
	Filename   string                  `json:"filename"`
	Encryption *store.EncryptionPolicy `json:"encryption,omitempty"`
}
type Definition struct {
	Schema int    `json:"schema_version"`
	Name   string `json:"name"`
	Steps  []Step `json:"steps"`
}
type DraftRequest struct {
	ID              string     `json:"workflow_id,omitempty"`
	ExpectedVersion int        `json:"expected_version"`
	Definition      Definition `json:"definition"`
}
type Decision struct {
	Hash     string `json:"definition_hash"`
	Revision int64  `json:"expected_revision"`
}
type RunRequest struct {
	Workflow Reference `json:"workflow"`
	FileID   string    `json:"file_id"`
}
type PreviewRequest struct {
	Definition Definition `json:"definition"`
	FileID     string     `json:"file_id,omitempty"`
}
type Result struct {
	Resource json.RawMessage `json:"resource"`
	Replayed bool            `json:"replayed"`
}
type RunStepView struct {
	ID          string                    `json:"id"`
	Ordinal     int                       `json:"ordinal"`
	DeliveryID  string                    `json:"delivery_id"`
	State       string                    `json:"state"`
	Attempts    int                       `json:"attempts"`
	Observation json.RawMessage           `json:"observation"`
	Ciphertext  *store.DeliveryCiphertext `json:"ciphertext,omitempty"`
}
type RunView struct {
	Run            *store.WorkflowRun `json:"run"`
	Steps          []RunStepView      `json:"steps"`
	ObservedState  string             `json:"observed_state"`
	ObservedReason string             `json:"observed_reason"`
}

// Decode rejects duplicate keys before typed decoding. Silently taking the last
// destination would give review and execution different meanings.
func Decode(data []byte, target any) error {
	if len(data) == 0 || len(data) > 32<<10 || !utf8.Valid(data) {
		return ErrInput
	}
	d := json.NewDecoder(bytes.NewReader(data))
	tokens := 0
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 16 || tokens > 4096 {
			return ErrInput
		}
		tokens++
		token, err := d.Token()
		if err != nil {
			return ErrInput
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		if delimiter == '{' {
			keys := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return ErrInput
				}
				name, ok := key.(string)
				if !ok || name != strings.ToLower(name) || keys[name] {
					return ErrInput
				}
				keys[name] = true
				if err = walk(depth + 1); err != nil {
					return err
				}
			}
			close, err := d.Token()
			if err != nil || close != json.Delim('}') {
				return ErrInput
			}
		} else if delimiter == '[' {
			for d.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			close, err := d.Token()
			if err != nil || close != json.Delim(']') {
				return ErrInput
			}
		} else {
			return ErrInput
		}
		return nil
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrInput
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return ErrInput
	}
	return nil
}
func Normalize(d Definition) (Definition, error) {
	if d.Schema != 1 || len(d.Steps) < 1 || len(d.Steps) > 16 || !utf8.ValidString(d.Name) {
		return d, ErrInput
	}
	d.Name = norm.NFC.String(d.Name)
	if len(d.Name) < 1 || len(d.Name) > 256 {
		return d, ErrInput
	}
	for _, r := range d.Name {
		if unicode.IsControl(r) {
			return d, ErrInput
		}
	}
	seen := map[string]bool{}
	for _, s := range d.Steps {
		if !stepPattern.MatchString(s.ID) || seen[s.ID] || s.Kind != "sftp.deliver" || !store.ValidID(s.Connection.ID) || s.Connection.Version < 1 || !hashPattern.MatchString(s.Connection.Hash) || !filenamePattern.MatchString(s.Filename) {
			return d, fmt.Errorf("%w: unsupported or incomplete step", ErrInput)
		}
		seen[s.ID] = true
		if s.Encryption != nil && (!store.ValidID(s.Encryption.Key.ID) || s.Encryption.Key.Version < 1 || !hashPattern.MatchString(s.Encryption.Key.Hash) || (s.Encryption.Profile != "seipd-v1-aes256" && s.Encryption.Profile != "seipd-v2-aes256-ocb")) {
			return d, fmt.Errorf("%w: incomplete recipient encryption policy", ErrInput)
		}
	}
	return d, nil
}
