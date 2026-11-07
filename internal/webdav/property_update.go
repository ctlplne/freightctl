package webdav

import (
	"encoding/xml"

	"github.com/ctlplne/freightctl/internal/namespaceprops"
)

// Only emit property names after the complete atomic mutation committed. Values
// are absent from this response; a later authorized PROPFIND reads current data.
func PropertyUpdateResponse(base string, r Resource, changes []namespaceprops.Change) ([]byte, error) {
	if err := namespaceprops.ValidateChanges(changes); err != nil {
		return nil, err
	}
	var b responseBuffer
	_, _ = b.Write([]byte(xml.Header))
	e := xml.NewEncoder(&b)
	dav := func(local string) xml.Name { return xml.Name{Space: "DAV:", Local: local} }
	start := func(local string) error { return e.EncodeToken(xml.StartElement{Name: dav(local)}) }
	end := func(local string) error { return e.EncodeToken(xml.EndElement{Name: dav(local)}) }
	for _, local := range []string{"multistatus", "response"} {
		if err := start(local); err != nil {
			return nil, err
		}
	}
	if err := element(e, dav("href"), Href(base, r)); err != nil {
		return nil, err
	}
	for _, local := range []string{"propstat", "prop"} {
		if err := start(local); err != nil {
			return nil, err
		}
	}
	seen := map[xml.Name]bool{}
	for _, change := range changes {
		name, err := namespaceprops.Inspect(change.Property, change.Operation == "remove")
		if err != nil {
			return nil, err
		}
		if !seen[name] {
			if err = element(e, name, ""); err != nil {
				return nil, err
			}
			seen[name] = true
		}
	}
	if err := end("prop"); err != nil {
		return nil, err
	}
	if err := element(e, dav("status"), "HTTP/1.1 200 OK"); err != nil {
		return nil, err
	}
	for _, local := range []string{"propstat", "response", "multistatus"} {
		if err := end(local); err != nil {
			return nil, err
		}
	}
	if err := e.Flush(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
