package webdav

import (
	"encoding/xml"
	"io"
	"strings"
	"testing"
	"time"
)

func TestReadPropertySelectionHasFiniteXMLGrammarAndNoEntityAuthority(t *testing.T) {
	for _, body := range []string{"", `<d:propfind xmlns:d="DAV:"><d:allprop/></d:propfind>`, `<?xml version="1.0"?><propfind xmlns="DAV:"><propname/></propfind>`, `<propfind xmlns="DAV:"><prop><getetag/><getcontentlength/><x:owner xmlns:x="urn:other"/></prop></propfind>`, `<propfind xmlns="DAV:"><allprop/><include><x:missing xmlns:x="urn:other"/></include></propfind>`} {
		if _, err := ParseSelection(strings.NewReader(body)); err != nil {
			t.Fatalf("ordinary finite property request refused: %v", err)
		}
	}
	for name, body := range map[string]string{
		"doctype":          `<!DOCTYPE propfind [<!ENTITY secret SYSTEM "file:///private/secret">]><propfind xmlns="DAV:"><allprop/></propfind>`,
		"entity":           `<propfind xmlns="DAV:"><prop><displayname>&secret;</displayname></prop></propfind>`,
		"nested":           `<propfind xmlns="DAV:"><prop><getetag><getetag/></getetag></prop></propfind>`,
		"two roots":        `<propfind xmlns="DAV:"><allprop/></propfind><propfind xmlns="DAV:"><allprop/></propfind>`,
		"two selectors":    `<propfind xmlns="DAV:"><allprop/><propname/></propfind>`,
		"unknown selector": `<propfind xmlns="DAV:"><execute/></propfind>`,
		"wrong namespace":  `<propfind xmlns="urn:other"><allprop/></propfind>`,
		"duplicate":        `<propfind xmlns="DAV:"><prop><getetag/><getetag/></prop></propfind>`,
		"too large":        strings.Repeat(" ", MaxRequestBytes+1),
		"too many":         `<propfind xmlns="DAV:"><prop>` + strings.Repeat(`<getetag/>`, MaxProperties+1) + `</prop></propfind>`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseSelection(strings.NewReader(body)); err == nil {
				t.Fatal("untrusted XML escaped the finite read grammar")
			}
		})
	}
}

func TestDAVVirtualNamesDecodeOnceWithoutPathCleaningOrHostNames(t *testing.T) {
	const base = "/v1/tenants/t/partners/p/dav/"
	for escaped, want := range map[string]string{base: "/", base + "folder/": "/folder", base + "a%20%26%20b/%E2%82%AC.txt": "/a & b/€.txt", base + "%252F.txt": "/%2F.txt"} {
		got, err := VirtualPath(escaped, base)
		if err != nil || got != want {
			t.Fatalf("once-decoded virtual name differs: %q %v", got, err)
		}
	}
	for _, tail := range []string{"../x", "%2e%2e/x", "a/%2F/b", "a%5cb", "a//b", "/", "a/./b", ".freightctl/receipt", "C%3A/private", "e%CC%81.txt"} {
		if _, err := VirtualPath(base+tail, base); err == nil {
			t.Errorf("ambiguous or control name accepted: %q", tail)
		}
	}
	if _, err := VirtualPath("/different/root/file", base); err == nil {
		t.Fatal("unrelated URL became a virtual path")
	}
}

func TestMultistatusPreservesEncodedHrefsKnownAndUnknownProperties(t *testing.T) {
	selection, err := ParseSelection(strings.NewReader(`<propfind xmlns="DAV:" xmlns:x="urn:other"><prop><getetag/><getcontentlength/><resourcetype/><x:missing/></prop></propfind>`))
	if err != nil {
		t.Fatal(err)
	}
	resources := []Resource{{Path: "/", Directory: true, Modified: time.Unix(0, 0)}, {Path: "/a & b/<report>.txt", Size: 23, ETag: `"immutable-revision"`}}
	body, err := Multistatus("/scoped/dav/", resources, selection)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Name      xml.Name `xml:"DAV: multistatus"`
		Responses []struct {
			Href   string `xml:"DAV: href"`
			Groups []struct {
				Status string `xml:"DAV: status"`
				Prop   struct {
					ETag     string    `xml:"DAV: getetag"`
					Size     string    `xml:"DAV: getcontentlength"`
					Missing  *struct{} `xml:"urn:other missing"`
					Resource struct {
						Collection *struct{} `xml:"DAV: collection"`
					} `xml:"DAV: resourcetype"`
				} `xml:"DAV: prop"`
			} `xml:"DAV: propstat"`
		} `xml:"DAV: response"`
	}
	if err := xml.Unmarshal(body, &result); err != nil || len(result.Responses) != 2 {
		t.Fatal("not a complete DAV XML multistatus", err)
	}
	root, file := result.Responses[0], result.Responses[1]
	if root.Href != "/scoped/dav/" || root.Groups[0].Prop.Resource.Collection == nil || file.Href != "/scoped/dav/a%20&%20b/%3Creport%3E.txt" || file.Groups[0].Prop.ETag != resources[1].ETag || file.Groups[0].Prop.Size != "23" || file.Groups[1].Status != "HTTP/1.1 404 Not Found" || file.Groups[1].Prop.Missing == nil {
		t.Fatal("property status, immutable validator, collection or scoped URL changed")
	}
	// Reparse every token: filenames must remain XML text, never markup.
	d := xml.NewDecoder(strings.NewReader(string(body)))
	for {
		_, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
}

func FuzzDAVPropertySelection(f *testing.F) {
	for _, seed := range []string{"", `<propfind xmlns="DAV:"><allprop/></propfind>`, `<propfind xmlns="DAV:"><prop><getetag/></prop></propfind>`, `<!DOCTYPE x><propfind xmlns="DAV:"><allprop/></propfind>`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body string) {
		selection, err := ParseSelection(strings.NewReader(body))
		if err != nil {
			return
		}
		if len(body) > MaxRequestBytes || len(selection.Names) > MaxProperties {
			t.Fatal("XML parser escaped its finite boundary")
		}
		encoded, err := Multistatus("/scoped/dav/", []Resource{{Path: "/artifact", Size: 7, ETag: `"revision"`}}, selection)
		if err != nil {
			t.Fatal("accepted request could not produce DAV XML", err)
		}
		var root struct {
			XMLName xml.Name `xml:"DAV: multistatus"`
		}
		if xml.Unmarshal(encoded, &root) != nil {
			t.Fatal("accepted request produced malformed DAV XML")
		}
	})
}
