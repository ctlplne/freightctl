package checks

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

var xmlLocalName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,127}$`)
var xmlNamespace = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*:[A-Za-z0-9._~:/?#@!$&'()*+,;=%\[\]-]+$`)

func validXMLPolicy(p *XMLRecordPolicy) bool {
	if p == nil || !xmlLocalName.MatchString(p.Root) || !xmlLocalName.MatchString(p.Record) || len(p.Namespace) > 512 {
		return false
	}
	if p.Namespace == "" {
		return true
	}
	return xmlNamespace.MatchString(p.Namespace) && p.Namespace != "http://www.w3.org/XML/1998/namespace" && p.Namespace != "http://www.w3.org/2000/xmlns/"
}

func xmlSpace(b []byte) bool {
	for _, c := range b {
		if c != ' ' && c != '\t' && c != '\r' && c != '\n' {
			return false
		}
	}
	return true
}

func xmlCharacters(b []byte) bool {
	if !utf8.Valid(b) {
		return false
	}
	for _, r := range string(b) {
		if !(r == 9 || r == 10 || r == 13 || r >= 0x20 && r <= 0xd7ff || r >= 0xe000 && r <= 0xfffd || r >= 0x10000 && r <= 0x10ffff) {
			return false
		}
	}
	return true
}

var xmlDeclaration = regexp.MustCompile(`^[ \t\r\n]*version[ \t\r\n]*=[ \t\r\n]*(?:"1\.0"|'1\.0')(?:[ \t\r\n]+encoding[ \t\r\n]*=[ \t\r\n]*(?:"(?i:UTF-8)"|'(?i:UTF-8)'))?(?:[ \t\r\n]+standalone[ \t\r\n]*=[ \t\r\n]*(?:"(?:yes|no)"|'(?:yes|no)'))?[ \t\r\n]*$`)

func validXMLDeclaration(data []byte) bool {
	// Explicit separators,ordered attributes and matching quotes are required.
	// A generic element decoder also accepts adjacent attributes without spaces.
	return len(data) <= 1024 && xmlDeclaration.Match(data)
}

func xmlRootMatches(s xml.StartElement, p *XMLRecordPolicy) bool {
	if s.Name.Local != p.Root || s.Name.Space != "" && (!xmlLocalName.MatchString(s.Name.Space) || strings.HasPrefix(strings.ToLower(s.Name.Space), "xml")) {
		return false
	}
	if p.Namespace == "" && s.Name.Space == "" && len(s.Attr) == 0 {
		return true
	}
	if len(s.Attr) != 1 {
		return false
	}
	a := s.Attr[0]
	if a.Value != p.Namespace {
		return false
	}
	if s.Name.Space == "" {
		return a.Name.Space == "" && a.Name.Local == "xmlns"
	}
	return p.Namespace != "" && a.Name.Space == "xmlns" && a.Name.Local == s.Name.Space
}

func validateXMLRecords(ctx context.Context, p Policy, file store.File, policyHash string, input io.Reader) (Report, error) {
	report := Report{Engine: policyEngine(p), FileID: file.ID, SHA256: file.SHA256, PolicyHash: policyHash}
	hash := secure.NewDigest()
	bounded := &budgetReader{ctx: ctx, reader: io.LimitReader(input, p.MaxBytes+1), hash: hash, remaining: p.MaxRecordBytes + 4096}
	d := xml.NewDecoder(bounded)
	// RawToken exposes the actual prefix. Match our own fixed-depth stack and
	// one root declaration,so an unbound prefix cannot masquerade as a URI.
	depth, column := 0, -1
	var root, record, field xml.Name
	var seen []bool
	var cell []byte
	closed, declared := false, false
	span := int64(0)
	fail := func(code string) (Report, error) {
		report.Code = code
		report.Bytes = bounded.total
		report.Row = max(int64(1), report.Rows)
		if column >= 0 {
			report.Column = column + 1
		}
		if ctx.Err() != nil {
			return report, ctx.Err()
		}
		return report, nil
	}
	reset := func() { span = d.InputOffset(); bounded.remaining = p.MaxRecordBytes + 4096 }
	for {
		before := d.InputOffset()
		token, err := d.RawToken()
		report.Bytes = bounded.total
		if err != nil {
			if errors.Is(err, errRecordBudget) {
				return fail("record_byte_limit")
			}
			if errors.Is(err, io.EOF) && closed && depth == 0 {
				break
			}
			return fail("malformed_xml")
		}
		if d.InputOffset()-span > int64(p.MaxRecordBytes) {
			return fail("record_byte_limit")
		}
		if bounded.total > p.MaxBytes {
			return fail("file_byte_limit")
		}
		switch v := token.(type) {
		case xml.Directive:
			return fail("unsupported_xml_construct")
		case xml.ProcInst:
			if depth != 0 || closed || declared || before != 0 && before != 3 || v.Target != "xml" || !validXMLDeclaration(v.Inst) {
				return fail("unsupported_xml_construct")
			}
			declared = true
		case xml.Comment:
			if !xmlCharacters(v) {
				return fail("malformed_xml")
			}
		case xml.CharData:
			if !xmlCharacters(v) {
				return fail("malformed_xml")
			}
			if depth == 3 {
				if len(cell)+len(v) > p.Columns[column].MaxBytes {
					return fail("invalid_cell")
				}
				cell = append(cell, v...)
			} else {
				if before == 0 && bytes.HasPrefix(v, []byte{0xef, 0xbb, 0xbf}) {
					v = v[3:]
				}
				if !xmlSpace(v) {
					return fail("unexpected_xml_text")
				}
			}
		case xml.StartElement:
			if closed {
				return fail("malformed_xml")
			}
			switch depth {
			case 0:
				if !xmlRootMatches(v, p.XML) {
					return fail("xml_root_or_namespace")
				}
				root = v.Name
				depth = 1
				reset()
			case 1:
				if v.Name != (xml.Name{Space: root.Space, Local: p.XML.Record}) || len(v.Attr) != 0 {
					return fail("unexpected_xml_record")
				}
				record = v.Name
				depth = 2
				seen = make([]bool, len(p.Columns))
				report.Rows++
				if report.Rows > p.MaxRows {
					return fail("row_limit")
				}
			case 2:
				if v.Name.Space != root.Space || len(v.Attr) != 0 {
					return fail("xml_field_or_namespace")
				}
				column = -1
				for i, c := range p.Columns {
					if v.Name.Local == c.Name {
						column = i
						break
					}
				}
				if column < 0 {
					return fail("unknown_field")
				}
				if seen[column] {
					return fail("duplicate_field")
				}
				seen[column] = true
				field = v.Name
				cell = cell[:0]
				depth = 3
			default:
				return fail("non_scalar_record")
			}
		case xml.EndElement:
			switch depth {
			case 3:
				if v.Name != field {
					return fail("malformed_xml")
				}
				if !validCell(p.Columns[column], string(cell)) {
					return fail("invalid_cell")
				}
				depth = 2
				column = -1
			case 2:
				if v.Name != record {
					return fail("malformed_xml")
				}
				for i, c := range p.Columns {
					if c.Required && !seen[i] {
						column = i
						return fail("missing_field")
					}
				}
				depth = 1
				reset()
			case 1:
				if v.Name != root {
					return fail("malformed_xml")
				}
				depth = 0
				closed = true
				reset()
			default:
				return fail("malformed_xml")
			}
		default:
			return fail("malformed_xml")
		}
	}
	if bounded.total != file.Size || hex.EncodeToString(hash.Sum(nil)) != file.SHA256 {
		report.Code = "source_integrity_changed"
		return report, nil
	}
	report.Code = policySuccess(p)
	return report, nil
}
