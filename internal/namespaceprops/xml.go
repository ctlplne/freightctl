// Package namespaceprops validates inert XML property data. It never resolves
// entities,fetches URIs or interprets a property as permission or executable code.
package namespaceprops

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"net/url"
	"sort"
	"strings"
	"unicode"
)

const MaxRequestBytes = 16 << 10
const MaxIntentBytes = 32 << 10
const MaxChanges = 32
const MaxValueDepth = 12
const xmlNamespace = "http://www.w3.org/XML/1998/namespace"
const xmlnsNamespace = "http://www.w3.org/2000/xmlns/"

var ErrXML = errors.New("invalid namespace property XML")

type Change struct {
	Operation string `json:"operation"`
	Property  string `json:"property_xml"`
}

type frame struct {
	raw, name             xml.Name
	attributes            []xml.Attr
	namespaces, inherited map[string]string
	ownNamespaces, ownXML map[string]bool
	controlAttrs          bool
	start, startEnd       int64
}
type event struct {
	token xml.Token
	frame frame
	depth int
	end   int64
}

func clone(source map[string]string) map[string]string {
	result := make(map[string]string, len(source))
	for k, v := range source {
		result[k] = v
	}
	return result
}
func validName(name xml.Name) bool {
	return name.Local != "" && !strings.Contains(name.Local, ":") && !strings.Contains(name.Space, ":") && len(name.Local) <= 128 && len(name.Space) <= 128
}
func resolve(name xml.Name, namespaces map[string]string, attribute bool) (xml.Name, error) {
	if !validName(name) {
		return xml.Name{}, ErrXML
	}
	if name.Space == "" && attribute {
		return name, nil
	}
	space, ok := namespaces[name.Space]
	if !ok && name.Space != "" {
		return xml.Name{}, ErrXML
	}
	return xml.Name{Space: space, Local: name.Local}, nil
}
func namespaceValue(value string) bool {
	return len(value) <= 512 && !strings.ContainsFunc(value, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) })
}

// RawToken permits retaining the original property subtree. Resolve names and
// enforce matching tags ourselves;unbound prefixes and duplicate attributes are
// refused rather than repaired. Namespace context is copied with each frame.
func document(body []byte, consume func(event) error) error {
	d := xml.NewDecoder(bytes.NewReader(body))
	var stack []frame
	root, finished, declaration := false, false, false
	for count := 0; ; count++ {
		if count >= 512 {
			return ErrXML
		}
		before := d.InputOffset()
		token, err := d.RawToken()
		if err == io.EOF {
			if !root || !finished || len(stack) != 0 {
				return ErrXML
			}
			return nil
		}
		if err != nil {
			return ErrXML
		}
		e := event{token: token, depth: len(stack), end: d.InputOffset()}
		switch t := token.(type) {
		case xml.StartElement:
			if len(stack) >= 16 || len(stack) == 0 && root {
				return ErrXML
			}
			f := frame{raw: t.Name, attributes: append([]xml.Attr(nil), t.Attr...), namespaces: map[string]string{"xml": xmlNamespace}, inherited: map[string]string{}, ownNamespaces: map[string]bool{}, ownXML: map[string]bool{}, start: before, startEnd: e.end}
			if len(stack) > 0 {
				f.namespaces = clone(stack[len(stack)-1].namespaces)
				f.inherited = clone(stack[len(stack)-1].inherited)
			}
			if len(t.Attr) > 64 {
				return ErrXML
			}
			for _, a := range t.Attr {
				prefix, isDeclaration := "", false
				if a.Name.Space == "xmlns" {
					prefix, isDeclaration = a.Name.Local, true
				} else if a.Name.Space == "" && a.Name.Local == "xmlns" {
					isDeclaration = true
				}
				if !isDeclaration {
					continue
				}
				if f.ownNamespaces[prefix] || prefix == "xmlns" || prefix != "" && a.Value == "" || !namespaceValue(a.Value) || a.Value == xmlnsNamespace || prefix == "xml" && a.Value != xmlNamespace || prefix != "xml" && a.Value == xmlNamespace {
					return ErrXML
				}
				f.ownNamespaces[prefix] = true
				f.namespaces[prefix] = a.Value
			}
			if len(f.namespaces) > 64 {
				return ErrXML
			}
			f.name, err = resolve(t.Name, f.namespaces, false)
			if err != nil {
				return err
			}
			seen := map[xml.Name]bool{}
			for _, a := range t.Attr {
				if a.Name.Space == "xmlns" || a.Name.Space == "" && a.Name.Local == "xmlns" {
					continue
				}
				name, err := resolve(a.Name, f.namespaces, true)
				if err != nil || seen[name] {
					return ErrXML
				}
				seen[name] = true
				if name.Space != xmlNamespace {
					f.controlAttrs = true
					continue
				}
				if name.Local != "lang" && name.Local != "space" && name.Local != "base" {
					f.controlAttrs = true
					continue
				}
				if len(a.Value) > 512 || name.Local == "space" && a.Value != "default" && a.Value != "preserve" {
					return ErrXML
				}
				value := a.Value
				if name.Local == "base" {
					base, err := url.Parse(f.inherited["base"])
					if err != nil {
						return ErrXML
					}
					next, err := url.Parse(value)
					if err != nil {
						return ErrXML
					}
					value = base.ResolveReference(next).String()
				}
				f.inherited[name.Local] = value
				f.ownXML[name.Local] = true
			}
			if len(stack) == 0 {
				root = true
			}
			e.frame = f
			if err = consume(e); err != nil {
				return err
			}
			stack = append(stack, f)
		case xml.EndElement:
			if len(stack) == 0 || stack[len(stack)-1].raw != t.Name {
				return ErrXML
			}
			e.depth = len(stack) - 1
			e.frame = stack[e.depth]
			if err = consume(e); err != nil {
				return err
			}
			stack = stack[:e.depth]
			if len(stack) == 0 {
				finished = true
			}
		case xml.CharData:
			if len(stack) == 0 && len(bytes.TrimSpace(t)) != 0 {
				return ErrXML
			}
			if err = consume(e); err != nil {
				return err
			}
		case xml.Comment:
			if err = consume(e); err != nil {
				return err
			}
		case xml.ProcInst:
			if t.Target != "xml" || len(stack) != 0 || root || declaration {
				return ErrXML
			}
			declaration = true
			if err = consume(e); err != nil {
				return err
			}
		default:
			return ErrXML
		}
	}
}

// Make the property's inherited XML context explicit. Keep the original mixed
// content and prefix spelling,including prefixes used only in text values.
func retained(body []byte, f frame, end int64) (string, error) {
	if f.start < 0 || f.startEnd <= f.start || end < f.startEnd || end > int64(len(body)) {
		return "", ErrXML
	}
	opening := body[f.start:f.startEnd]
	position := len(opening) - 1
	if position < 0 || opening[position] != '>' {
		return "", ErrXML
	}
	if position > 0 && opening[position-1] == '/' {
		position--
	}
	var tag bytes.Buffer
	qualified := func(name xml.Name) string {
		if name.Space != "" {
			return name.Space + ":" + name.Local
		}
		return name.Local
	}
	tag.WriteByte('<')
	tag.WriteString(qualified(f.raw))
	attribute := func(name, value string) {
		tag.WriteByte(' ')
		tag.WriteString(name)
		tag.WriteString(`="`)
		_ = xml.EscapeText(&tag, []byte(value))
		tag.WriteByte('"')
	}
	for _, a := range f.attributes {
		value := a.Value
		if a.Name.Space == "xml" && a.Name.Local == "base" {
			value = f.inherited["base"]
		}
		attribute(qualified(a.Name), value)
	}
	keys := make([]string, 0, len(f.namespaces))
	for prefix := range f.namespaces {
		keys = append(keys, prefix)
	}
	sort.Strings(keys)
	for _, prefix := range keys {
		if prefix == "xml" || f.ownNamespaces[prefix] {
			continue
		}
		name := "xmlns"
		if prefix != "" {
			name += ":" + prefix
		}
		attribute(name, f.namespaces[prefix])
	}
	for _, name := range []string{"base", "lang", "space"} {
		if value, ok := f.inherited[name]; ok && !f.ownXML[name] {
			attribute("xml:"+name, value)
		}
	}
	if position < len(opening)-1 {
		tag.WriteString("/>")
	} else {
		tag.WriteByte('>')
	}
	if tag.Len()+int(end-f.startEnd) > MaxIntentBytes {
		return "", ErrXML
	}
	var result bytes.Buffer
	result.Write(tag.Bytes())
	result.Write(body[f.startEnd:end])
	return result.String(), nil
}

// Inspect validates one self-contained property document. Values remain data,
// and removal names cannot smuggle nested content or executable instructions.
func Inspect(property string, empty bool) (xml.Name, error) {
	if len(property) == 0 || len(property) > MaxIntentBytes {
		return xml.Name{}, ErrXML
	}
	var name xml.Name
	err := document([]byte(property), func(e event) error {
		switch t := e.token.(type) {
		case xml.ProcInst:
			return ErrXML
		case xml.StartElement:
			if e.depth >= MaxValueDepth || empty && e.depth > 0 {
				return ErrXML
			}
			if e.depth == 0 {
				name = e.frame.name
				if name.Space == "" {
					return ErrXML
				}
			}
		case xml.CharData:
			if empty && len(bytes.TrimSpace(t)) != 0 {
				return ErrXML
			}
		}
		return nil
	})
	return name, err
}

// ParseUpdate preserves document order. Any malformed or oversized part refuses
// the whole request;no prefix of a property transaction is returned as accepted.
func ParseUpdate(reader io.Reader) ([]Change, error) {
	body, err := io.ReadAll(io.LimitReader(reader, MaxRequestBytes+1))
	if err != nil || len(body) > MaxRequestBytes {
		return nil, ErrXML
	}
	var changes []Change
	operation := ""
	props, items := 0, 0
	err = document(body, func(e event) error {
		switch t := e.token.(type) {
		case xml.StartElement:
			if e.depth < 3 && e.frame.controlAttrs {
				return ErrXML
			}
			switch e.depth {
			case 0:
				if e.frame.name != (xml.Name{Space: "DAV:", Local: "propertyupdate"}) {
					return ErrXML
				}
			case 1:
				if e.frame.name.Space != "DAV:" || (e.frame.name.Local != "set" && e.frame.name.Local != "remove") {
					return ErrXML
				}
				operation = e.frame.name.Local
				props = 0
			case 2:
				if e.frame.name != (xml.Name{Space: "DAV:", Local: "prop"}) || props != 0 {
					return ErrXML
				}
				props++
				items = 0
			default:
				if e.depth >= 3+MaxValueDepth || operation == "remove" && e.depth > 3 {
					return ErrXML
				}
				if e.depth == 3 {
					if e.frame.name.Space == "" {
						return ErrXML
					}
					items++
				}
			}
		case xml.EndElement:
			if e.depth == 3 {
				property, err := retained(body, e.frame, e.end)
				if err != nil {
					return err
				}
				if _, err = Inspect(property, operation == "remove"); err != nil {
					return err
				}
				changes = append(changes, Change{Operation: operation, Property: property})
				encoded, err := json.Marshal(changes)
				if err != nil || len(encoded) > MaxIntentBytes || len(changes) > MaxChanges {
					return ErrXML
				}
			}
			if e.depth == 2 && items == 0 || e.depth == 1 && props != 1 || e.depth == 0 && len(changes) == 0 {
				return ErrXML
			}
		case xml.CharData:
			if (e.depth < 4 || operation == "remove") && len(bytes.TrimSpace(t)) != 0 {
				return ErrXML
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return changes, nil
}
