package store

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestIntakeFormatsBindDistinctPrefixesToExactSchemaAndKind(t *testing.T) {
	hash := strings.Repeat("a", 64)
	for _, tc := range []struct{ definition, prefix string }{{`{"schema_version":1,"kind":"csv"}`, CSVIntakePrefix}, {`{"schema_version":2,"kind":"json_records"}`, JSONRecordsIntakePrefix}, {`{"schema_version":3,"kind":"fixed_width"}`, FixedWidthIntakePrefix}, {`{"schema_version":4,"kind":"xml_records"}`, XMLRecordsIntakePrefix}} {
		policy, err := IntakeFilePolicy(&Configuration{Hash: hash, Definition: json.RawMessage(tc.definition)})
		got, controlled := IntakePolicyHash(policy)
		if err != nil || policy != tc.prefix+hash || !controlled || got != hash || !ValidArtifactPolicy(policy) {
			t.Fatal("controlled identity differs", policy, err)
		}
	}
	for _, definition := range []string{`{"schema_version":1,"kind":"json_records"}`, `{"schema_version":2,"kind":"csv"}`, `{"schema_version":"2","kind":"json_records"}`, `{"SCHEMA_VERSION":2,"kind":"json_records"}`, `{"schema_version":2,"KIND":"json_records"}`, `{"schema_version":2,"kind":"json"}`, `{}`, `null`, `[]`} {
		if _, err := IntakeFilePolicy(&Configuration{Hash: hash, Definition: json.RawMessage(definition)}); err == nil {
			t.Fatal("unknown or mismatched format admitted", definition)
		}
	}
	for _, policy := range []string{"intake-json-records-v1:" + strings.Repeat("A", 64), JSONRecordsIntakePrefix + hash + "x", "intake-json-v1:" + hash, "intake-csv-v2:" + hash, JSONRecordsIntakePrefix, CSVIntakePrefix + hash[:63], "integrity-only-v1:extra"} {
		if _, ok := IntakePolicyHash(policy); ok || ValidArtifactPolicy(policy) {
			t.Fatal("unknown policy namespace or noncanonical hash admitted")
		}
	}
}
