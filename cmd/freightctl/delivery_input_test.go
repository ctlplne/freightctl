package main

import (
	"strings"
	"testing"
)

func TestDeliveryCLIRefusesAmbiguousDestinationAndCredentialControl(t *testing.T) {
	for _, input := range []string{
		`{"directory":"/approved","directory":"/other"}`,
		`{"dav":{"destination":{"address":"127.0.0.1:443","address":"192.0.2.1:443"}}}`,
		`{"dav":{"destination":{"token_reference":"/private/approved","TOKEN_REFERENCE":"/private/other"}}}`,
		`{"dav":{"receiver_contract":{"receipt":"exact-readback","receipt":"business-accepted"}}}`,
		`{"dav":null,"dav":{}}`,
		"{\"directory\":\"/a\xff\"}",
		`null`,
	} {
		if _, err := decodeDeliveryRequest(strings.NewReader(input)); err == nil {
			t.Error("delivery CLI admitted ambiguous or lossy authority-bearing control")
		}
	}
}
