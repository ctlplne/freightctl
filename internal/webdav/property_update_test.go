package webdav

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ctlplne/freightctl/internal/namespaceprops"
)

func TestDeadPropertyReadbackPreservesMixedXMLAndNameOnlyOmitsValues(t *testing.T) {
	changes, err := namespaceprops.ParseUpdate(strings.NewReader(`<propertyupdate xmlns="DAV:" xmlns:x="urn:example" xmlns:q="urn:types" xml:lang="fr"><set><prop><x:p>avant <q:label q:type="q:Label">été &amp; tail</q:label> après q:Label</x:p></prop></set></propertyupdate>`))
	if err != nil {
		t.Fatal(err)
	}
	properties, err := namespaceprops.Apply(nil, changes)
	if err != nil {
		t.Fatal(err)
	}
	r := Resource{Path: "/data", EntryID: "00000001-1111-4111-8111-111111111111", Revision: 2, Properties: properties}
	for _, selection := range []Selection{{All: true}, {Names: []xml.Name{{Space: "urn:example", Local: "p"}}}} {
		body, err := Multistatus("/dav/", []Resource{r}, selection)
		if err != nil || !bytes.Contains(body, []byte(changes[0].Property)) {
			t.Fatal("dead XML value/context changed", err)
		}
		var parsed struct {
			Responses []struct {
				Groups []struct {
					Prop struct {
						P struct {
							Text  string `xml:",chardata"`
							Label string `xml:"urn:types label"`
						} `xml:"urn:example p"`
					} `xml:"DAV: prop"`
				} `xml:"DAV: propstat"`
			} `xml:"DAV: response"`
		}
		if xml.Unmarshal(body, &parsed) != nil || len(parsed.Responses) != 1 || parsed.Responses[0].Groups[0].Prop.P.Label != "été & tail" || parsed.Responses[0].Groups[0].Prop.P.Text != "avant  après q:Label" {
			t.Fatal("encoded dead property no longer has the reviewed mixed content")
		}
	}
	body, err := Multistatus("/dav/", []Resource{r}, Selection{NamesOnly: true})
	if err != nil || bytes.Contains(body, []byte("avant")) || !bytes.Contains(body, []byte("urn:example")) {
		t.Fatal("propname disclosed values or lost names", err)
	}
	body, err = PropertyUpdateResponse("/dav/", r, changes)
	if err != nil || !bytes.Contains(body, []byte("HTTP/1.1 200 OK")) || bytes.Contains(body, []byte("avant")) {
		t.Fatal("atomic mutation response disclosed values or wrong status", err)
	}
}

func TestDeadPropertyResponseIsBoundedBeforeHeadersAndRejectsPersistedMarkup(t *testing.T) {
	value := `<p xmlns="urn:example">` + strings.Repeat("x", 16000) + `</p>`
	resources := make([]Resource, 600)
	for i := range resources {
		resources[i] = Resource{Path: fmt.Sprintf("/%d", i), Properties: map[string]string{"{urn:example}p": value}}
	}
	if body, err := Multistatus("/dav/", resources, Selection{All: true}); !errors.Is(err, ErrResponseLimit) || body != nil {
		t.Fatal("oversized complete answer returned a partial success", err)
	}
	for _, value := range []string{`<!DOCTYPE p><p xmlns="urn:example"/>`, `</prop><execute/>`, `<?xml version="1.0"?><p xmlns="urn:example"/>`} {
		resources[0].Properties["{urn:example}p"] = value
		if body, err := Multistatus("/dav/", resources[:1], Selection{All: true}); err == nil || body != nil {
			t.Fatal("persisted markup bypassed XML validation")
		}
	}
}
