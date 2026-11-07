// Package recordplan contains shared declarative record rules, never execution authority.
package recordplan

type Column struct {
	Source     string `json:"source"`
	Target     string `json:"target"`
	Conversion string `json:"conversion"`
	Missing    string `json:"missing"`
	Null       string `json:"null"`
	Empty      string `json:"empty"`
}

// Projection is declarative data mapping, never code or execution authority.
// Names are exact; order is explicit; presence conversions require a changed hash.
type Projection struct {
	Schema           int      `json:"schema_version"`
	Kind             string   `json:"kind"`
	Engine           string   `json:"engine"`
	SourcePolicyHash string   `json:"source_policy_hash"`
	OutputKind       string   `json:"output_kind"`
	Columns          []Column `json:"columns"`
	MaxBytes         int64    `json:"max_bytes"`
	MaxRecordBytes   int      `json:"max_record_bytes"`
	MaxRows          int64    `json:"max_rows"`
	TimeoutSeconds   int      `json:"timeout_seconds"`
}
