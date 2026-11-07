package api

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ctlplne/freightctl/internal/store"
)

func TestTypedControlRejectsNullAndUnicodeASCIIFieldAliases(t *testing.T) {
	for _, body := range []string{`null`, `{"operation":"setstat","path":"/reviewed","expected_revision":0,"expected_revi\u017fion":1,"mode":0}`, `{"operation":"setstat","path":"/reviewed","expected_reviſion":1,"mode":0}`} {
		var command store.PathCommand
		if err := boundedControlInput(httptest.NewRecorder(), httptest.NewRequest("POST", "https://localhost", strings.NewReader(body)), 16<<10, &command); err == nil {
			t.Error("typed control admitted null or a Unicode alias that Go treats as an ASCII field")
		}
	}
}
