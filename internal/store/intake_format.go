package store

import (
	"encoding/json"
	"strings"
)

const CSVIntakePrefix = "intake-csv-v1:"
const JSONRecordsIntakePrefix = "intake-json-records-v1:"
const FixedWidthIntakePrefix = "intake-fixed-width-v1:"
const XMLRecordsIntakePrefix = "intake-xml-records-v1:"
const XLSXRecordsIntakePrefix = "intake-xlsx-records-v1:"

// IntakePolicyHash recognizes only the exact controlled-custody profiles.
// A hash is metadata,not read,release,forwarding or execution authority.
func IntakePolicyHash(policy string) (string, bool) {
	for _, prefix := range []string{CSVIntakePrefix, JSONRecordsIntakePrefix, FixedWidthIntakePrefix, XMLRecordsIntakePrefix, XLSXRecordsIntakePrefix} {
		if hash, found := strings.CutPrefix(policy, prefix); found && browserSecretHash.MatchString(hash) {
			return hash, true
		}
	}
	return "", false
}

func ValidArtifactPolicy(policy string) bool {
	_, controlled := IntakePolicyHash(policy)
	return policy == "integrity-only-v1" || controlled
}

// IntakeFilePolicy selects the format identity of an already normalized stored
// policy. Full column,signature,scanner and processing validation stays in checks.
func IntakeFilePolicy(policy *Configuration) (string, error) {
	if policy == nil || !browserSecretHash.MatchString(policy.Hash) || len(policy.Definition) > 12<<10 {
		return "", ErrState
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(policy.Definition, &fields) != nil {
		return "", ErrState
	}
	var schema int
	var kind string
	if json.Unmarshal(fields["schema_version"], &schema) != nil || json.Unmarshal(fields["kind"], &kind) != nil {
		return "", ErrState
	}
	switch {
	case schema == 1 && kind == "csv":
		return CSVIntakePrefix + policy.Hash, nil
	case schema == 2 && kind == "json_records":
		return JSONRecordsIntakePrefix + policy.Hash, nil
	case schema == 3 && kind == "fixed_width":
		return FixedWidthIntakePrefix + policy.Hash, nil
	case schema == 4 && kind == "xml_records":
		return XMLRecordsIntakePrefix + policy.Hash, nil
	case schema == 5 && kind == "xlsx_records":
		return XLSXRecordsIntakePrefix + policy.Hash, nil
	default:
		return "", ErrState
	}
}
