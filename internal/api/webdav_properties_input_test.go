package api

import (
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestDAVPropertyMutationRejectsUntrustedXMLBeforeServiceAccess(t *testing.T) {
	for _, body := range []string{
		`<!DOCTYPE propertyupdate [<!ENTITY x SYSTEM "file:///SYNTHETIC_NEVER_READ">]><propertyupdate xmlns="DAV:"><set><prop><x:p xmlns:x="urn:example">&x;</x:p></prop></set></propertyupdate>`,
		`<propertyupdate xmlns="DAV:"><execute><prop><x:p xmlns:x="urn:example">data</x:p></prop></execute></propertyupdate>`,
		`<propertyupdate xmlns="DAV:" approved="true"><set><prop><x:p xmlns:x="urn:example">data</x:p></prop></set></propertyupdate>`,
	} {
		r := httptest.NewRequest("PROPPATCH", "https://localhost/v1/tenants/t/partners/p/dav/file.dat", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 64))
		r.Header.Set("If-Match", `"freightctl-10000000-1111-4111-8111-111111111111-`+strings.Repeat("b", 64)+`"`)
		r.Header.Set("Idempotency-Key", "properties-original-command")
		r.Header.Set("Content-Type", "application/xml")
		w := httptest.NewRecorder()
		if prepareDAVRequest(w, r) || w.Code != 400 {
			t.Fatalf("untrusted property control reached service;status=%d", w.Code)
		}
	}
}

func TestDAVPropertyMutationRequiresOneExactNamespaceConditionAndInertXML(t *testing.T) {
	const body = `<propertyupdate xmlns="DAV:" xmlns:x="urn:example"><set><prop><x:p>inert</x:p></prop></set></propertyupdate>`
	const condition = "10000000-1111-4111-8111-111111111111:1"
	request := func() *httptest.ResponseRecorder { return httptest.NewRecorder() }
	for _, test := range []struct {
		name, header, value string
		status              int
	}{
		{"valid", "", "", 200},
		{"missing", "X-Freightctl-Namespace-Revision", "", 428},
		{"empty", "X-Freightctl-Namespace-Revision", "", 400},
		{"zero", "X-Freightctl-Namespace-Revision", strings.TrimSuffix(condition, ":1") + ":0", 400},
		{"negative", "X-Freightctl-Namespace-Revision", strings.TrimSuffix(condition, ":1") + ":-1", 400},
		{"padded", "X-Freightctl-Namespace-Revision", strings.TrimSuffix(condition, ":1") + ":01", 400},
		{"overflow", "X-Freightctl-Namespace-Revision", strings.TrimSuffix(condition, ":1") + ":9223372036854775808", 400},
		{"foreign tag", "If-Match", `"freightctl-byte-tag"`, 400},
		{"DAV conditions", "If", "(<untrusted-lock>)", 400},
		{"body MIME", "Content-Type", "text/plain", 415},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest("PROPPATCH", "https://localhost/v1/tenants/t/partners/p/dav/file", strings.NewReader(body))
			r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 64))
			r.Header.Set("Idempotency-Key", "properties-original")
			r.Header.Set("Content-Type", "application/xml")
			r.Header.Set("X-Freightctl-Namespace-Revision", condition)
			if test.header != "" {
				r.Header.Set(test.header, test.value)
			}
			if test.name == "missing" {
				r.Header.Del("X-Freightctl-Namespace-Revision")
			}
			w := request()
			valid := prepareDAVRequest(w, r)
			if valid != (test.status == 200) || w.Code != test.status {
				t.Fatal("property request escaped its declared contract", valid, w.Code)
			}
			if valid {
				input, ok := r.Context().Value(davPropertyContext{}).(davPropertyInput)
				if !ok || input.Revision != 1 || len(input.Changes) != 1 || input.Entry != strings.TrimSuffix(condition, ":"+strconv.Itoa(1)) {
					t.Fatal("parsed meaning not retained")
				}
			}
		})
	}
	r := httptest.NewRequest("PROPPATCH", "https://localhost/v1/tenants/t/partners/p/dav/file", strings.NewReader(strings.Replace(body, "urn:example", "DAV:", 1)))
	r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 64))
	r.Header.Set("Content-Type", "application/xml")
	w := request()
	if prepareDAVRequest(w, r) || w.Code != 403 {
		t.Fatal("live property mutation reached service", w.Code)
	}
}
