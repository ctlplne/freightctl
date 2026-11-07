// Package webdav encodes a declared read-only DAV profile. It owns no storage,
// credentials or authorization; callers must supply already authorized metadata.
package webdav

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/ctlplne/freightctl/internal/vpath"
)

var ErrRequest = errors.New("invalid DAV read request")

const MaxRequestBytes = 16 << 10
const MaxProperties = 32

type Selection struct {
	All, NamesOnly bool
	Names          []xml.Name
}

// ParseSelection does not resolve DTDs, entities, URLs or extension instructions.
// The finite grammar bounds both token count and the response's property fanout.
func ParseSelection(body io.Reader) (Selection, error) {
	b, err := io.ReadAll(io.LimitReader(body, MaxRequestBytes+1))
	if err != nil || len(b) > MaxRequestBytes {
		return Selection{}, ErrRequest
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return Selection{All: true}, nil
	}
	d := xml.NewDecoder(bytes.NewReader(b))
	var result Selection
	var stack []xml.Name
	selector, include, finished := "", false, false
	for count := 0; ; count++ {
		if count > 256 {
			return Selection{}, ErrRequest
		}
		token, err := d.Token()
		if err == io.EOF {
			if !finished || selector == "" {
				return Selection{}, ErrRequest
			}
			return result, nil
		}
		if err != nil {
			return Selection{}, ErrRequest
		}
		switch t := token.(type) {
		case xml.StartElement:
			for _, a := range t.Attr {
				if a.Name.Space != "xmlns" && a.Name.Local != "xmlns" && !(a.Name.Space == "http://www.w3.org/XML/1998/namespace" && a.Name.Local == "space") {
					return Selection{}, ErrRequest
				}
			}
			switch len(stack) {
			case 0:
				if finished || t.Name != (xml.Name{Space: "DAV:", Local: "propfind"}) {
					return Selection{}, ErrRequest
				}
			case 1:
				if t.Name.Space != "DAV:" {
					return Selection{}, ErrRequest
				}
				if t.Name.Local == "include" {
					if selector != "allprop" || include {
						return Selection{}, ErrRequest
					}
					include = true
				} else {
					if selector != "" || (t.Name.Local != "allprop" && t.Name.Local != "propname" && t.Name.Local != "prop") {
						return Selection{}, ErrRequest
					}
					selector = t.Name.Local
					result.All, result.NamesOnly = selector == "allprop", selector == "propname"
				}
			case 2:
				if (stack[1].Local != "prop" && stack[1].Local != "include") || t.Name.Space == "" || len(t.Name.Space) > 512 || len(t.Name.Local) > 128 || len(result.Names) >= MaxProperties {
					return Selection{}, ErrRequest
				}
				for _, previous := range result.Names {
					if previous == t.Name {
						return Selection{}, ErrRequest
					}
				}
				result.Names = append(result.Names, t.Name)
			default:
				return Selection{}, ErrRequest
			}
			stack = append(stack, t.Name)
		case xml.EndElement:
			if len(stack) == 0 || stack[len(stack)-1] != t.Name {
				return Selection{}, ErrRequest
			}
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				finished = true
			}
		case xml.CharData:
			if len(bytes.TrimSpace(t)) != 0 {
				return Selection{}, ErrRequest
			}
		case xml.Comment:
		case xml.ProcInst:
			if t.Target != "xml" || len(stack) != 0 || finished {
				return Selection{}, ErrRequest
			}
		default:
			return Selection{}, ErrRequest
		}
	}
}

// VirtualPath decodes each segment exactly once. Encoded slashes cannot change
// the namespace boundary, and dot segments never reach ServeMux's redirects.
func VirtualPath(escaped, base string) (string, error) {
	if !strings.HasPrefix(escaped, base) {
		return "", ErrRequest
	}
	tail := strings.TrimPrefix(escaped, base)
	if tail == "" {
		return "/", nil
	}
	tail = strings.TrimSuffix(tail, "/")
	if tail == "" {
		return "", ErrRequest
	}
	parts := strings.Split(tail, "/")
	for i, part := range parts {
		value, err := url.PathUnescape(part)
		if err != nil || strings.ContainsAny(value, "/\\") {
			return "", ErrRequest
		}
		parts[i] = value
	}
	virtual := "/" + strings.Join(parts, "/")
	canonical, err := vpath.Canonical(virtual)
	if err != nil || canonical != virtual || vpath.ControlPath(canonical) {
		return "", ErrRequest
	}
	return canonical, nil
}

type Resource struct {
	Path      string
	Directory bool
	Size      int64
	Modified  time.Time
	ETag      string
}

func Href(base string, r Resource) string {
	if r.Path == "/" {
		return base
	}
	parts := strings.Split(strings.TrimPrefix(r.Path, "/"), "/")
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	href := base + strings.Join(parts, "/")
	if r.Directory {
		href += "/"
	}
	return href
}

func element(e *xml.Encoder, name xml.Name, text string) error {
	return e.EncodeElement(text, xml.StartElement{Name: name})
}

// Multistatus builds the complete finite answer before any 207 header is sent.
// Unknown requested properties retain their namespace in a separate 404 group.
func Multistatus(base string, resources []Resource, selection Selection) ([]byte, error) {
	if len(resources) == 0 || len(resources) > 1001 {
		return nil, ErrRequest
	}
	var b bytes.Buffer
	b.WriteString(xml.Header)
	e := xml.NewEncoder(&b)
	dav := func(local string) xml.Name { return xml.Name{Space: "DAV:", Local: local} }
	var encodeErr error
	capture := func(err error) {
		if encodeErr == nil {
			encodeErr = err
		}
	}
	start := func(name string) { capture(e.EncodeToken(xml.StartElement{Name: dav(name)})) }
	end := func(name string) { capture(e.EncodeToken(xml.EndElement{Name: dav(name)})) }
	start("multistatus")
	for _, r := range resources {
		start("response")
		capture(element(e, dav("href"), Href(base, r)))
		names := []xml.Name{dav("displayname"), dav("resourcetype")}
		if r.Directory {
			names = append(names, dav("getlastmodified"))
		}
		if !r.Directory {
			names = append(names, dav("getcontentlength"), dav("getcontenttype"), dav("getetag"))
		}
		requested := selection.Names
		if selection.All || selection.NamesOnly {
			requested = append(append([]xml.Name{}, names...), selection.Names...)
		}
		var found, missing []xml.Name
		for _, name := range requested {
			available := false
			for _, known := range names {
				available = available || name == known
			}
			if available {
				duplicate := false
				for _, previous := range found {
					duplicate = duplicate || previous == name
				}
				if !duplicate {
					found = append(found, name)
				}
			} else {
				missing = append(missing, name)
			}
		}
		for group, properties := range [][]xml.Name{found, missing} {
			if len(properties) == 0 && !(group == 0 && len(requested) == 0) {
				continue
			}
			start("propstat")
			start("prop")
			for _, name := range properties {
				value := ""
				if group == 0 && !selection.NamesOnly {
					switch name.Local {
					case "displayname":
						value = path.Base(r.Path)
					case "getcontentlength":
						value = strconv.FormatInt(r.Size, 10)
					case "getcontenttype":
						value = "application/octet-stream"
					case "getlastmodified":
						value = r.Modified.UTC().Format(http.TimeFormat)
					case "getetag":
						value = r.ETag
					}
				}
				if name == dav("resourcetype") && r.Directory && group == 0 && !selection.NamesOnly {
					start("resourcetype")
					capture(element(e, dav("collection"), ""))
					end("resourcetype")
				} else {
					capture(element(e, name, value))
				}
			}
			end("prop")
			status := "HTTP/1.1 200 OK"
			if group == 1 {
				status = "HTTP/1.1 404 Not Found"
			}
			capture(element(e, dav("status"), status))
			end("propstat")
		}
		end("response")
	}
	end("multistatus")
	capture(e.Flush())
	if encodeErr != nil {
		return nil, encodeErr
	}
	return b.Bytes(), nil
}
