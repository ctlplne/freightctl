package main

import (
	"strings"
	"testing"

	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestCLIControlCannotChooseDuplicateAliasedOrLossyFields(t *testing.T) {
	for _, body := range []string{
		`{"operation":"mkdir","path":"/reviewed","path":"/other"}`,
		`{"operation":"mkdir","PATH":"/other"}`,
		`{"operation":"mkdir","path":"/reviewed","\u0070ath":"/other"}`,
		`{"operation":"properties","path":"/reviewed","property_changes":[{"operation":"remove","operation":"set","property_xml":"<x:p xmlns:x=\"urn:example\"/>"}]}`,
		"{\"operation\":\"mkdir\",\"path\":\"/a\xff\"}",
		`null`,
		`{"operation":"setstat","path":"/reviewed","expected_revision":0,"expected_revi\u017fion":1,"mode":0}`,
	} {
		var command store.PathCommand
		if err := decodeCLIControl(strings.NewReader(body), &command, 16<<10); err == nil {
			t.Error("actual CLI reader admitted ambiguous or lossy namespace control")
		}
	}
	for _, body := range []string{
		`{"path":"/reviewed","path":"/other","expected_size":0,"expected_sha256":"` + strings.Repeat("a", 64) + `"}`,
		`{"path":"/reviewed","EXPECTED_SIZE":0,"expected_sha256":"` + strings.Repeat("a", 64) + `"}`,
		"{\"path\":\"/a\xff\",\"expected_size\":0,\"expected_sha256\":\"" + strings.Repeat("a", 64) + "\"}",
	} {
		var request custody.CreateUpload
		if err := decodeCLIControl(strings.NewReader(body), &request, 16<<10); err == nil {
			t.Error("actual CLI reader admitted ambiguous or lossy upload control")
		}
	}
}

func TestCLIControlPreservesMeaningfulZeroValuesAndUnicodeContent(t *testing.T) {
	var command store.PathCommand
	if err := decodeCLIControl(strings.NewReader(`{"operation":"setstat","path":"/été","expected_revision":0,"mode":0}`), &command, 16<<10); err != nil || command.Path != "/été" || command.ExpectedRevision == nil || *command.ExpectedRevision != 0 || command.Mode == nil || *command.Mode != 0 {
		t.Fatal("strict control changed valid zero values or Unicode data", err)
	}
	var upload custody.CreateUpload
	if err := decodeCLIControl(strings.NewReader(`{"path":"/été","expected_size":0,"expected_sha256":"`+strings.Repeat("a", 64)+`","expected_revision":0,"mode":0}`), &upload, 16<<10); err != nil || upload.Path != "/été" || upload.Size != 0 || upload.ExpectedRevision == nil || *upload.ExpectedRevision != 0 || upload.Mode == nil || *upload.Mode != 0 {
		t.Fatal("strict upload control lost explicit zero values", err)
	}
}

func TestCLIControlCannotAcceptAPrefixAtItsReadLimit(t *testing.T) {
	valid := `{"operation":"mkdir","path":"/reviewed"}`
	input := valid + strings.Repeat(" ", (16<<10)-len(valid)) + `{"operation":"remove"}`
	var command store.PathCommand
	if err := decodeCLIControl(strings.NewReader(input), &command, 16<<10); err == nil {
		t.Fatal("bounded CLI reader fabricated EOF and accepted a prefix of oversized control")
	}
}
