package workflow

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestStrictWorkflowInputRejectsAmbiguousAuthority(t *testing.T) {
	for _, data := range []string{
		`{"definition":{"name":"first","name":"other"}}`,
		`{"definition":{},"Definition":{}}`,
		`{"definition":{},"execute_shell":"whoami"}`,
		`{"definition":{}} {}`,
		`{"definition":{"steps":[{"kind":"sftp.deliver","key_file":"/unexpected"}]}}`,
		strings.Repeat("[", 18) + strings.Repeat("]", 18),
	} {
		var r PreviewRequest
		if Decode([]byte(data), &r) == nil {
			t.Fatal("ambiguous or unsupported input accepted", data)
		}
	}
	if Decode(bytes.Repeat([]byte(" "), (32<<10)+1), &PreviewRequest{}) == nil {
		t.Fatal("input byte budget ignored")
	}
}
func FuzzTypedWorkflow(f *testing.F) {
	f.Add([]byte(`{"schema_version":1,"name":"encrypted settlement","steps":[{"id":"send","kind":"sftp.deliver","connection":{"id":"00000000-0000-0000-0000-000000000001","version":1,"hash":"0000000000000000000000000000000000000000000000000000000000000000"},"filename":"settlement.pgp","encryption":{"key":{"id":"00000000-0000-0000-0000-000000000002","version":1,"hash":"0000000000000000000000000000000000000000000000000000000000000000"},"profile":"seipd-v1-aes256"}}]}`))
	f.Add([]byte(`{"schema_version":1,"name":"settlement","steps":[{"id":"send","kind":"sftp.deliver","connection":{"id":"00000000-0000-0000-0000-000000000001","version":1,"hash":"0000000000000000000000000000000000000000000000000000000000000000"},"filename":"settlement.csv"}]}`))
	f.Add([]byte(`{"schema_version":1,"name":"settlement","steps":[]}`))
	f.Add([]byte(`{"name":"a","name":"b"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var d Definition
		if Decode(data, &d) != nil {
			return
		}
		normalized, err := Normalize(d)
		if err != nil {
			return
		}
		encoded, err := json.Marshal(normalized)
		if err != nil {
			t.Fatal(err)
		}
		var again Definition
		if Decode(encoded, &again) != nil {
			t.Fatal("canonical workflow was rejected")
		}
		canonical, err := Normalize(again)
		if err != nil {
			t.Fatal(err)
		}
		other, _ := json.Marshal(canonical)
		if !bytes.Equal(encoded, other) {
			t.Fatal("normalization changed on repeated validation")
		}
	})
}
