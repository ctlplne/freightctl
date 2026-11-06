package api

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestTypedControlPreservesZeroOptionalValuesAndOriginalBodyLimits(t *testing.T) {
	raw := `{"path":"/empty.bin","expected_size":0,"expected_sha256":"` + strings.Repeat("a", 64) + `","expected_revision":0,"mode":0}`
	var upload custody.CreateUpload
	if err := boundedControlInput(httptest.NewRecorder(), httptest.NewRequest("POST", "https://freightctl.invalid", strings.NewReader(raw)), 16<<10, &upload); err != nil || upload.Size != 0 || upload.ExpectedRevision == nil || *upload.ExpectedRevision != 0 || upload.Mode == nil || *upload.Mode != 0 {
		t.Fatal("strict control changed meaningful zero values", err)
	}
	var command store.PathCommand
	valid := `{"operation":"mkdir","path":"/valid"}`
	if err := workflowInput(httptest.NewRecorder(), httptest.NewRequest("POST", "https://freightctl.invalid", strings.NewReader(valid)), &command); err != nil || command.Path != "/valid" {
		t.Fatal("shared workflow boundary changed valid control", err)
	}
	for _, raw := range []string{valid + `{}`, strings.Repeat(" ", 16<<10) + valid, `{"operation":"mkdir","approved":true}`, `{"operation":"mkdir","nested":` + strings.Repeat("[", 20) + `0` + strings.Repeat("]", 20) + `}`} {
		if err := boundedControlInput(httptest.NewRecorder(), httptest.NewRequest("POST", "https://freightctl.invalid", strings.NewReader(raw)), 16<<10, &command); err == nil {
			t.Fatal("unknown,trailing,oversized or deeply nested input accepted")
		}
	}
}

func TestNamespaceAndUploadControlsRejectRepeatedAliasedAndInvalidUTF8BeforeResources(t *testing.T) {
	sha := strings.Repeat("a", 64)
	cases := []struct {
		route, code string
		bodies      []string
	}{
		{"namespace/commands", "invalid_path_command", []string{`{"operation":"mkdir","path":"/first","path":"/second"}`, `{"operation":"mkdir","path":"/first","PATH":"/second"}`, `{"operation":"mkdir","path":"/first","\u0070ath":"/second"}`, "{\"operation\":\"mkdir\",\"path\":\"/a\xff\"}"}},
		{"uploads", "invalid_upload_session", []string{`{"path":"/first","path":"/second","expected_size":1,"expected_sha256":"` + sha + `"}`, `{"path":"/first","PATH":"/second","expected_size":1,"expected_sha256":"` + sha + `"}`, `{"path":"/first","expected_size":10000,"EXPECTED_SIZE":1,"expected_sha256":"` + sha + `"}`, "{\"path\":\"/a\xff\",\"expected_size\":1,\"expected_sha256\":\"" + sha + "\"}"}},
	}
	for _, c := range cases {
		for index, body := range c.bodies {
			t.Run(c.route+"/"+string(rune('a'+index)), func(t *testing.T) {
				defer func() {
					if recover() != nil {
						t.Fatal("ambiguous control reached an application resource")
					}
				}()
				r := httptest.NewRequest("POST", "https://freightctl.invalid/v1/tenants/11111111-1111-4111-8111-111111111111/partners/22222222-2222-4222-8222-222222222222/"+c.route, strings.NewReader(body))
				r.Header.Set("Authorization", "Bearer "+strings.Repeat("0", 64))
				r.Header.Set("Idempotency-Key", "original-key")
				w := httptest.NewRecorder()
				New(&custody.Service{MaxFile: 1024}, nil).ServeHTTP(w, r)
				if w.Code != 400 || !strings.Contains(w.Body.String(), `"error":"`+c.code+`"`) {
					t.Fatal("ambiguous control was not refused by the input boundary", w.Code)
				}
			})
		}
	}
}
