package workflow

import (
	"strings"
	"testing"
)

func TestControlObjectsKeepUnicodeDataAndRefuseASCIIFieldAliases(t *testing.T) {
	var data map[string]string
	if err := Decode([]byte(`{"étiquette":"été","σ":"réception","latin-key":"data"}`), &data); err != nil || data["étiquette"] != "été" || data["σ"] != "réception" {
		t.Fatal("unrelated Unicode dictionary data was restricted", err)
	}
	for _, body := range []string{`null`, `[]`, `"not an object"`, `{"schema":0,"ſchema":1}`, `{"schema":0,"\u017fchema":1}`, `{"schema":0,"SCHEMA":1}`, strings.Repeat(" ", 32<<10) + `{}`} {
		var request struct {
			Schema int `json:"schema"`
		}
		if err := Decode([]byte(body), &request); err == nil {
			t.Fatal("control admitted null,scalar,oversize or an ASCII field alias")
		}
	}
}
