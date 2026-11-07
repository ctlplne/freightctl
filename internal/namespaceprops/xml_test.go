package namespaceprops

import (
	"encoding/xml"
	"io"
	"strings"
	"testing"
)

func TestPropertyUpdateRetainsMixedXMLNamespaceAndInheritedContext(t *testing.T) {
	body := `<?xml version="1.0"?><d:propertyupdate xmlns:d="DAV:" xmlns:x="urn:example" xmlns:q="urn:types" xml:lang="fr" xml:base="https://example.invalid/a/"><d:set><d:prop><x:color xml:base="../b/" q:type="q:Label">été &amp; q:Label <q:label>rouge</q:label> tail</x:color></d:prop></d:set><d:remove><d:prop><x:old/></d:prop></d:remove></d:propertyupdate>`
	changes, err := ParseUpdate(strings.NewReader(body))
	if err != nil || len(changes) != 2 || changes[0].Operation != "set" || changes[1].Operation != "remove" {
		t.Fatal("ordered property transaction was not retained", err)
	}
	if !strings.Contains(changes[0].Property, `xmlns:q="urn:types"`) || !strings.Contains(changes[0].Property, `xml:lang="fr"`) || !strings.Contains(changes[0].Property, `xml:base="https://example.invalid/b/"`) {
		t.Fatal("property lost inherited namespace,language or effective base")
	}
	name, err := Inspect(changes[0].Property, false)
	if err != nil || name != (xml.Name{Space: "urn:example", Local: "color"}) {
		t.Fatal("property name changed", err)
	}
	d := xml.NewDecoder(strings.NewReader(changes[0].Property))
	nested, text := false, ""
	for {
		token, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		switch v := token.(type) {
		case xml.StartElement:
			if v.Name == (xml.Name{Space: "urn:types", Local: "label"}) {
				nested = true
			}
		case xml.CharData:
			text += string(v)
		}
	}
	if !nested || text != "été & q:Label rouge tail" {
		t.Fatal("mixed content or expanded QName changed")
	}
	if name, err = Inspect(changes[1].Property, true); err != nil || name.Local != "old" {
		t.Fatal("empty removal name changed", err)
	}
}

func TestPropertyUpdatePreservesSequentialRepeatedNamesAndInertValueData(t *testing.T) {
	body := `<propertyupdate xmlns="DAV:" xmlns:x="urn:example"><set><prop><x:p><x:execute approved="true">untrusted data</x:execute></x:p></prop></set><remove><prop><x:p/></prop></remove></propertyupdate>`
	changes, err := ParseUpdate(strings.NewReader(body))
	if err != nil || len(changes) != 2 || changes[0].Operation != "set" || changes[1].Operation != "remove" {
		t.Fatal("document order was collapsed or data interpreted as a control", err)
	}
}

func TestPropertyUpdateRefusesMalformedAmbiguousAndUnboundedXMLAtomically(t *testing.T) {
	valid := `<propertyupdate xmlns="DAV:" xmlns:x="urn:example"><set><prop><x:p>data</x:p></prop></set></propertyupdate>`
	for name, body := range map[string]string{
		"empty":                        "",
		"wrong root":                   `<propfind xmlns="DAV:"><allprop/></propfind>`,
		"extra control":                strings.Replace(valid, "<set>", `<set approved="true">`, 1),
		"unknown action":               strings.ReplaceAll(valid, "set>", "execute>"),
		"DTD":                          `<!DOCTYPE propertyupdate [<!ENTITY x SYSTEM "file:///SYNTHETIC_NEVER_READ">]>` + valid,
		"entity":                       strings.Replace(valid, "data", "&unknown;", 1),
		"unbound prefix":               strings.Replace(valid, ` xmlns:x="urn:example"`, "", 1),
		"duplicate declaration":        strings.Replace(valid, `xmlns:x="urn:example"`, `xmlns:x="urn:example" xmlns:x="urn:other"`, 1),
		"duplicate resolved attribute": strings.Replace(valid, "<x:p>", `<x:p xmlns:y="urn:example" x:a="1" y:a="2">`, 1),
		"wrong xml prefix":             strings.Replace(valid, "<x:p>", `<x:p xmlns:xml="urn:wrong">`, 1),
		"processing instruction":       strings.Replace(valid, "data", `<?xml-stylesheet href="https://example.invalid/NEVER_FETCH"?>`, 1),
		"nonempty remove":              strings.ReplaceAll(valid, "set>", "remove>"),
		"nested remove":                strings.ReplaceAll(strings.Replace(valid, "data", "<x:child/>", 1), "set>", "remove>"),
		"second root":                  valid + valid,
		"trailing text":                valid + "untrusted",
		"unmatched end":                strings.Replace(valid, "</x:p>", "</x:other>", 1),
		"empty prop":                   `<propertyupdate xmlns="DAV:"><set><prop/></set></propertyupdate>`,
		"two prop containers":          `<propertyupdate xmlns="DAV:" xmlns:x="urn:x"><set><prop><x:p/></prop><prop><x:q/></prop></set></propertyupdate>`,
		"body bound":                   strings.Repeat(" ", MaxRequestBytes+1),
		"change bound":                 `<propertyupdate xmlns="DAV:" xmlns:x="urn:x"><set><prop>` + strings.Repeat(`<x:p/>`, MaxChanges+1) + `</prop></set></propertyupdate>`,
		"depth bound":                  strings.Replace(valid, "data", strings.Repeat("<x:n>", MaxValueDepth)+strings.Repeat("</x:n>", MaxValueDepth), 1),
	} {
		t.Run(name, func(t *testing.T) {
			changes, err := ParseUpdate(strings.NewReader(body))
			if err == nil || changes != nil {
				t.Fatal("invalid transaction returned an accepted prefix")
			}
		})
	}
}

func TestStandalonePropertyRequiresSelfContainedNamesAndExactEmptyRemoval(t *testing.T) {
	for _, body := range []string{`<x:p/>`, `<p/>`, `<x:p xmlns:x="urn:x"><x:child/></x:p>`, `<x:p xmlns:x="urn:x">value</x:p>`} {
		if _, err := Inspect(body, true); err == nil {
			t.Fatal("invalid or nonempty removal accepted")
		}
	}
	if name, err := Inspect(`<x:p xmlns:x="urn:x"/>`, true); err != nil || name != (xml.Name{Space: "urn:x", Local: "p"}) {
		t.Fatal("standalone empty property refused", err)
	}
}

func FuzzDAVPropertyMutation(f *testing.F) {
	for _, seed := range []string{
		`<propertyupdate xmlns="DAV:" xmlns:x="urn:example"><set><prop><x:p>data</x:p></prop></set></propertyupdate>`,
		`<!DOCTYPE x><propertyupdate xmlns="DAV:"/>`,
		`<propertyupdate xmlns="DAV:" xmlns:x="urn:example"><remove><prop><x:p/></prop></remove></propertyupdate>`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body string) {
		changes, err := ParseUpdate(strings.NewReader(body))
		if err != nil {
			if changes != nil {
				t.Fatal("refused XML returned partial operations")
			}
			return
		}
		if len(changes) == 0 || len(changes) > MaxChanges {
			t.Fatal("property transaction escaped its finite fanout")
		}
		for _, change := range changes {
			if change.Operation != "set" && change.Operation != "remove" {
				t.Fatal("XML granted an unknown control operation")
			}
			if _, err := Inspect(change.Property, change.Operation == "remove"); err != nil {
				t.Fatal("accepted property lost standalone namespace validity", err)
			}
		}
	})
}
