package crypto

import (
	"bytes"
	"strings"
	"testing"
)

func TestBrowserTokensSeparatePurposeScopeAndReplay(t *testing.T) {
	credential := []byte(strings.Repeat("a", 64))
	first, err := BrowserSessionToken(credential, strings.Repeat("1", 36), strings.Repeat("2", 36), "same-operation")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	again, err := BrowserSessionToken(credential, strings.Repeat("1", 36), strings.Repeat("2", 36), "same-operation")
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if !EqualToken(first.Bytes, again.Bytes) || bytes.Equal(first.Bytes, credential) {
		t.Fatal("replay changed token or reused parent credential")
	}
	for _, input := range []struct{ tenant, partner, key string }{{strings.Repeat("3", 36), strings.Repeat("2", 36), "same-operation"}, {strings.Repeat("1", 36), strings.Repeat("3", 36), "same-operation"}, {strings.Repeat("1", 36), strings.Repeat("2", 36), "different-operation"}} {
		other, err := BrowserSessionToken(credential, input.tenant, input.partner, input.key)
		if err != nil {
			t.Fatal(err)
		}
		if EqualToken(first.Bytes, other.Bytes) {
			t.Error("scope or operation did not separate browser credential")
		}
		other.Close()
	}
	csrf, err := BrowserCSRFToken(first.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	defer csrf.Close()
	if EqualToken(first.Bytes, csrf.Bytes) || EqualToken(credential, csrf.Bytes) || EqualToken(first.Bytes[:63], first.Bytes) {
		t.Fatal("CSRF/session/parent purposes overlap or truncated comparison accepted")
	}
	if _, err := BrowserSessionToken([]byte("invalid"), strings.Repeat("1", 36), strings.Repeat("2", 36), "same-operation"); err == nil {
		t.Fatal("invalid parent credential accepted")
	}
}
