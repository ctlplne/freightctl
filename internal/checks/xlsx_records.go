package checks

import (
	"context"
	"encoding/xml"
	"errors"
	"io"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/ctlplne/freightctl/internal/zipcontainer"
)

// XLSXContract is the deterministic workbook parser contract. It does not grant
// custody acceptance,release,forwarding or execution. The intake policy/API/UI
// binding must be completed before this parser becomes a supported intake kind.
type XLSXContract struct {
	Sheet            string
	DateMode         string // iso_text,serial_1900 or serial_1904;never inferred from a style
	Columns          []Column
	MaxRows          int64
	MaxRecordBytes   int
	MaxSharedStrings int
	MaxSharedBytes   int64
	Container        zipcontainer.Limits
}

type XLSXReport struct {
	Code   string `json:"code"`
	Rows   int64  `json:"rows"`
	Row    int64  `json:"row,omitempty"`
	Column int    `json:"column,omitempty"`
}

const xlsxMain = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
const xlsxOffice = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/"
const xlsxRelationships = "http://schemas.openxmlformats.org/package/2006/relationships"
const xlsxContentTypes = "http://schemas.openxmlformats.org/package/2006/content-types"
const xlsxMime = "application/vnd.openxmlformats-officedocument.spreadsheetml."

type xlsxFailure struct {
	code   string
	row    int64
	column int
}

func (e *xlsxFailure) Error() string { return e.code }
func xlsxFail(code string) error     { return &xlsxFailure{code: code} }

type xlsxEvent struct {
	Token          xml.Token
	Path           []xml.Name
	Before, Offset int64
}

func xlsxAttribute(s xml.StartElement, space, local string) string {
	for _, a := range s.Attr {
		if a.Name == (xml.Name{Space: space, Local: local}) {
			return a.Value
		}
	}
	return ""
}

// The pinned decoder has no entity table or CharsetReader. Bounded reads stop a
// huge text/attribute token before decoder growth. Known namespace URIs contain
// characters illegal in a prefix,so its unresolved-prefix fallback cannot match
// any namespace used for document semantics here. Exact paths prevent wrapping.
func walkXLSX(ctx context.Context, input io.Reader, limit int, root xml.Name, visit func(xlsxEvent) error) error {
	b := &budgetReader{ctx: ctx, reader: input, hash: io.Discard, remaining: limit + 4096}
	d := xml.NewDecoder(b)
	stack := make([]xml.Name, 0, 16)
	closed, declared, started := false, false, false
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		before := d.InputOffset()
		token, err := d.Token()
		if err != nil {
			if errors.Is(err, io.EOF) && closed && len(stack) == 0 {
				return nil
			}
			if errors.Is(err, errRecordBudget) {
				return xlsxFail("xlsx_token_limit")
			}
			return xlsxFail("malformed_xlsx_xml")
		}
		if d.InputOffset()-before > int64(limit) {
			return xlsxFail("xlsx_token_limit")
		}
		b.remaining = limit + 4096
		switch v := token.(type) {
		case xml.Directive:
			return xlsxFail("unsupported_xlsx_xml")
		case xml.ProcInst:
			if started || closed || declared || before != 0 && before != 3 || v.Target != "xml" || !validXMLDeclaration(v.Inst) {
				return xlsxFail("unsupported_xlsx_xml")
			}
			declared = true
		case xml.Comment:
			if !xmlCharacters(v) {
				return xlsxFail("malformed_xlsx_xml")
			}
		case xml.StartElement:
			if closed || len(stack) >= 32 || len(v.Attr) > 64 {
				return xlsxFail("xlsx_structure_limit")
			}
			if !started {
				if v.Name != root {
					return xlsxFail("xlsx_part_root")
				}
				started = true
			}
			seen := map[xml.Name]bool{}
			for _, a := range v.Attr {
				if seen[a.Name] || !xmlCharacters([]byte(a.Value)) {
					return xlsxFail("malformed_xlsx_xml")
				}
				seen[a.Name] = true
			}
			if v.Name.Space == xlsxMain {
				switch v.Name.Local {
				case "f", "definedNames", "externalReferences", "oleObjects", "controls", "extLst", "drawing", "legacyDrawing", "hyperlinks":
					return xlsxFail("unsupported_xlsx_active_content")
				}
			}
			if v.Name.Local == "AlternateContent" {
				return xlsxFail("unsupported_xlsx_active_content")
			}
			stack = append(stack, v.Name)
			if err = visit(xlsxEvent{token, stack, before, d.InputOffset()}); err != nil {
				return err
			}
		case xml.EndElement:
			if len(stack) == 0 || stack[len(stack)-1] != v.Name {
				return xlsxFail("malformed_xlsx_xml")
			}
			if err = visit(xlsxEvent{token, stack, before, d.InputOffset()}); err != nil {
				return err
			}
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				closed = true
			}
		case xml.CharData:
			if before == 0 && strings.HasPrefix(string(v), "\ufeff") {
				v = v[3:]
				token = v
			}
			if !xmlCharacters(v) || len(stack) == 0 && !xmlSpace(v) {
				return xlsxFail("malformed_xlsx_xml")
			}
			if err = visit(xlsxEvent{token, stack, before, d.InputOffset()}); err != nil {
				return err
			}
		}
	}
}

type xlsxRelationship struct{ kind, target string }
type xlsxSheet struct{ name, id string }

type xlsxWorkbook struct {
	z            *zipcontainer.ZIP
	c            XLSXContract
	types        map[string]string
	parts        map[string]bool
	rels         map[string]map[string]xlsxRelationship
	strings      []string
	stringBytes  int64
	stringRefs   int64
	declaredRefs int64
	report       XLSXReport
}

func validSheetName(s string) bool {
	if s == "" || !utf8.ValidString(s) || utf8.RuneCountInString(s) > 31 || strings.ContainsAny(s, `[]:*?/\`) || strings.HasPrefix(s, "'") || strings.HasSuffix(s, "'") {
		return false
	}
	for _, r := range s {
		if r < 32 || r == 127 {
			return false
		}
	}
	return true
}

// ValidateXLSX streams explicit,typed table data from a ZIP32 SpreadsheetML
// workbook. Formula caches,external links,macros and unsupported active parts
// cannot become data. It never uses a floating point number or evaluates a cell.
func ValidateXLSX(ctx context.Context, c XLSXContract, input io.ReaderAt, size int64) (XLSXReport, error) {
	r := XLSXReport{}
	if ctx.Err() != nil {
		return r, ctx.Err()
	}
	if !validSheetName(c.Sheet) || c.DateMode != "iso_text" && c.DateMode != "serial_1900" && c.DateMode != "serial_1904" || c.MaxSharedStrings < 1 || c.MaxSharedBytes < 1 {
		return r, ErrInput
	}
	p, err := Normalize(Policy{Schema: 1, Kind: "csv", Columns: c.Columns, MaxRows: c.MaxRows, MaxRecordBytes: c.MaxRecordBytes})
	if err != nil {
		return r, err
	}
	c.Columns, c.MaxRows, c.MaxRecordBytes = p.Columns, p.MaxRows, p.MaxRecordBytes
	w := &xlsxWorkbook{c: c, types: map[string]string{}, parts: map[string]bool{}, rels: map[string]map[string]xlsxRelationship{}, declaredRefs: -1}
	w.z, err = zipcontainer.Open(ctx, input, size, c.Container)
	if err == nil {
		for _, e := range w.z.Entries() {
			w.parts[e.Name] = true
		}
		err = w.validate(ctx)
	}
	if err != nil {
		if ctx.Err() != nil {
			return w.report, ctx.Err()
		}
		var failure *xlsxFailure
		switch {
		case errors.As(err, &failure):
			w.report.Code, w.report.Row, w.report.Column = failure.code, failure.row, failure.column
		case errors.Is(err, zipcontainer.ErrInput):
			return w.report, ErrInput
		case errors.Is(err, zipcontainer.ErrLimit):
			w.report.Code = "xlsx_container_limit"
		case errors.Is(err, zipcontainer.ErrIntegrity):
			w.report.Code = "xlsx_member_integrity"
		default:
			w.report.Code = "invalid_xlsx_package"
		}
		return w.report, nil
	}
	w.report.Code = "valid_xlsx_records"
	return w.report, nil
}

func (w *xlsxWorkbook) xml(ctx context.Context, name string, root xml.Name, visit func(xlsxEvent) error) error {
	return w.z.Read(ctx, name, func(r io.Reader) error { return walkXLSX(ctx, r, w.c.MaxRecordBytes, root, visit) })
}

func (w *xlsxWorkbook) contentTypes(ctx context.Context) error {
	defaults, overrides := map[string]string{}, map[string]string{}
	err := w.xml(ctx, "[Content_Types].xml", xml.Name{Space: xlsxContentTypes, Local: "Types"}, func(e xlsxEvent) error {
		s, ok := e.Token.(xml.StartElement)
		if !ok || len(e.Path) == 1 {
			return nil
		}
		if len(e.Path) != 2 || s.Name.Space != xlsxContentTypes {
			return xlsxFail("invalid_xlsx_content_types")
		}
		typeName := xlsxAttribute(s, "", "ContentType")
		if typeName == "" {
			return xlsxFail("invalid_xlsx_content_types")
		}
		switch s.Name.Local {
		case "Default":
			ext := xlsxAttribute(s, "", "Extension")
			if ext == "" || strings.ContainsAny(ext, ".:/\\%?#") || defaults[strings.ToLower(ext)] != "" {
				return xlsxFail("invalid_xlsx_content_types")
			}
			defaults[strings.ToLower(ext)] = typeName
		case "Override":
			name := xlsxAttribute(s, "", "PartName")
			if !strings.HasPrefix(name, "/") || !w.parts[name[1:]] || overrides[name[1:]] != "" {
				return xlsxFail("invalid_xlsx_content_types")
			}
			overrides[name[1:]] = typeName
		default:
			return xlsxFail("invalid_xlsx_content_types")
		}
		if len(defaults)+len(overrides) > w.c.Container.MaxEntries+16 {
			return xlsxFail("xlsx_structure_limit")
		}
		return nil
	})
	if err != nil {
		return err
	}
	for name := range w.parts {
		if name == "[Content_Types].xml" {
			continue
		}
		t := overrides[name]
		if t == "" {
			t = defaults[strings.ToLower(strings.TrimPrefix(path.Ext(name), "."))]
		}
		switch t {
		case xlsxMime + "sheet.main+xml", xlsxMime + "worksheet+xml", xlsxMime + "styles+xml", xlsxMime + "sharedStrings+xml", "application/vnd.openxmlformats-officedocument.theme+xml", "application/vnd.openxmlformats-package.core-properties+xml", "application/vnd.openxmlformats-officedocument.extended-properties+xml", "application/vnd.openxmlformats-officedocument.custom-properties+xml", "application/vnd.openxmlformats-package.relationships+xml":
			w.types[name] = t
		default:
			return xlsxFail("unsupported_xlsx_part")
		}
		if strings.HasSuffix(name, ".rels") != (t == "application/vnd.openxmlformats-package.relationships+xml") {
			return xlsxFail("invalid_xlsx_content_types")
		}
	}
	return nil
}

func (w *xlsxWorkbook) relationships(ctx context.Context, name string) error {
	owner := ""
	if name != "_rels/.rels" {
		if path.Base(path.Dir(name)) != "_rels" || !strings.HasSuffix(name, ".rels") {
			return xlsxFail("invalid_xlsx_relationships")
		}
		owner = path.Join(path.Dir(path.Dir(name)), strings.TrimSuffix(path.Base(name), ".rels"))
		if !w.parts[owner] {
			return xlsxFail("invalid_xlsx_relationships")
		}
	}
	rels := map[string]xlsxRelationship{}
	err := w.xml(ctx, name, xml.Name{Space: xlsxRelationships, Local: "Relationships"}, func(e xlsxEvent) error {
		s, ok := e.Token.(xml.StartElement)
		if !ok || len(e.Path) == 1 {
			return nil
		}
		if len(e.Path) != 2 || s.Name != (xml.Name{Space: xlsxRelationships, Local: "Relationship"}) {
			return xlsxFail("invalid_xlsx_relationships")
		}
		id, kind, target, mode := xlsxAttribute(s, "", "Id"), xlsxAttribute(s, "", "Type"), xlsxAttribute(s, "", "Target"), xlsxAttribute(s, "", "TargetMode")
		if id == "" || len(id) > 128 || rels[id].kind != "" || mode != "" && mode != "Internal" || target == "" || strings.ContainsAny(target, `\:%?#`) || strings.HasPrefix(target, "//") {
			return xlsxFail("unsupported_xlsx_relationship")
		}
		if strings.HasPrefix(target, "/") {
			target = target[1:]
		} else {
			target = path.Join(path.Dir(owner), target)
		}
		if path.Clean(target) != target || target == ".." || strings.HasPrefix(target, "../") || !w.parts[target] {
			return xlsxFail("invalid_xlsx_relationships")
		}
		var want string
		switch kind {
		case xlsxOffice + "officeDocument":
			want = xlsxMime + "sheet.main+xml"
		case xlsxOffice + "worksheet":
			want = xlsxMime + "worksheet+xml"
		case xlsxOffice + "styles":
			want = xlsxMime + "styles+xml"
		case xlsxOffice + "sharedStrings":
			want = xlsxMime + "sharedStrings+xml"
		case xlsxOffice + "theme":
			want = "application/vnd.openxmlformats-officedocument.theme+xml"
		case xlsxOffice + "extended-properties":
			want = "application/vnd.openxmlformats-officedocument.extended-properties+xml"
		case xlsxOffice + "custom-properties":
			want = "application/vnd.openxmlformats-officedocument.custom-properties+xml"
		case "http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties":
			want = "application/vnd.openxmlformats-package.core-properties+xml"
		default:
			return xlsxFail("unsupported_xlsx_relationship")
		}
		if owner == "" {
			if kind != xlsxOffice+"officeDocument" && kind != xlsxOffice+"extended-properties" && kind != xlsxOffice+"custom-properties" && kind != "http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" {
				return xlsxFail("unsupported_xlsx_relationship")
			}
		} else if w.types[owner] == xlsxMime+"sheet.main+xml" {
			if kind != xlsxOffice+"worksheet" && kind != xlsxOffice+"styles" && kind != xlsxOffice+"sharedStrings" && kind != xlsxOffice+"theme" {
				return xlsxFail("unsupported_xlsx_relationship")
			}
		} else {
			return xlsxFail("unsupported_xlsx_relationship")
		}
		if w.types[target] != want {
			return xlsxFail("invalid_xlsx_relationships")
		}
		if len(rels) >= w.c.Container.MaxEntries {
			return xlsxFail("xlsx_structure_limit")
		}
		rels[id] = xlsxRelationship{kind, target}
		return nil
	})
	if err == nil {
		w.rels[owner] = rels
	}
	return err
}

// ST_Xstring escapes apply to each individual <t>,not to the concatenation of
// rich-text runs. Decode once,so _x005F_x0041_ remains the literal _x0041_.
func xlsxString(value string) (string, error) {
	out := make([]byte, 0, len(value))
	escape := func(i int) (rune, bool) {
		if len(value)-i < 7 || value[i] != '_' || value[i+1] != 'x' || value[i+6] != '_' {
			return 0, false
		}
		n, err := strconv.ParseUint(value[i+2:i+6], 16, 16)
		return rune(n), err == nil
	}
	for i := 0; i < len(value); {
		r, ok := escape(i)
		if !ok {
			out = append(out, value[i])
			i++
			continue
		}
		i += 7
		if utf16.IsSurrogate(r) {
			low, ok := escape(i)
			if !ok || r < 0xd800 || r > 0xdbff || low < 0xdc00 || low > 0xdfff {
				return "", xlsxFail("invalid_xlsx_string")
			}
			r = utf16.DecodeRune(r, low)
			i += 7
		}
		if r == 0 || r == 0xfffe || r == 0xffff {
			return "", xlsxFail("invalid_xlsx_string")
		}
		out = utf8.AppendRune(out, r)
	}
	return string(out), nil
}

type xlsxText struct {
	raw, value   strings.Builder
	mode         int // 0 empty,1 plain,2 rich
	run, runText bool
}

func (s *xlsxText) reset() {
	s.raw.Reset()
	s.value.Reset()
	s.mode = 0
	s.run = false
	s.runText = false
}
func (s *xlsxText) start(p []xml.Name, item string) error {
	local := p[len(p)-1].Local
	parent := ""
	if len(p) > 1 {
		parent = p[len(p)-2].Local
	}
	switch local {
	case "r":
		if parent != item || s.mode == 1 || s.run {
			return xlsxFail("invalid_xlsx_string")
		}
		s.mode = 2
		s.run = true
		s.runText = false
	case "t":
		if parent == item {
			if s.mode != 0 {
				return xlsxFail("invalid_xlsx_string")
			}
			s.mode = 1
		} else if parent == "r" && len(p) > 2 && p[len(p)-3].Local == item && s.run && !s.runText {
			s.runText = true
		} else {
			return xlsxFail("invalid_xlsx_string")
		}
		s.raw.Reset()
	case "rPr":
		if parent != "r" || !s.run || s.runText {
			return xlsxFail("invalid_xlsx_string")
		}
	default:
		if parent == item {
			return xlsxFail("invalid_xlsx_string")
		}
	}
	return nil
}
func (s *xlsxText) text(b []byte) error {
	if s.raw.Len()+len(b) > 64<<10 {
		return xlsxFail("invalid_xlsx_string")
	}
	s.raw.Write(b)
	return nil
}
func (s *xlsxText) end(local string) error {
	if local == "r" {
		if !s.runText {
			return xlsxFail("invalid_xlsx_string")
		}
		s.run = false
	}
	if local == "t" {
		v, err := xlsxString(s.raw.String())
		if err != nil {
			return err
		}
		if s.value.Len()+len(v) > 64<<10 {
			return xlsxFail("invalid_xlsx_string")
		}
		s.value.WriteString(v)
	}
	return nil
}

func (w *xlsxWorkbook) validate(ctx context.Context) error {
	if err := w.contentTypes(ctx); err != nil {
		return err
	}
	for name, t := range w.types {
		if t == "application/vnd.openxmlformats-package.relationships+xml" {
			if err := w.relationships(ctx, name); err != nil {
				return err
			}
		}
	}
	workbook := ""
	for _, r := range w.rels[""] {
		if r.kind == xlsxOffice+"officeDocument" {
			if workbook != "" {
				return xlsxFail("invalid_xlsx_workbook")
			}
			workbook = r.target
		}
	}
	if workbook == "" {
		return xlsxFail("invalid_xlsx_workbook")
	}
	seenNames, seenIDs := map[string]bool{}, map[string]bool{}
	var sheets []xlsxSheet
	date1904, sheetList := false, false
	err := w.xml(ctx, workbook, xml.Name{Space: xlsxMain, Local: "workbook"}, func(e xlsxEvent) error {
		s, ok := e.Token.(xml.StartElement)
		if !ok {
			return nil
		}
		if s.Name.Space != xlsxMain {
			return xlsxFail("unsupported_xlsx_workbook")
		}
		if s.Name.Local == "workbookPr" {
			if len(e.Path) != 2 {
				return xlsxFail("invalid_xlsx_workbook")
			}
			switch xlsxAttribute(s, "", "date1904") {
			case "", "0", "false":
			case "1", "true":
				date1904 = true
			default:
				return xlsxFail("invalid_xlsx_workbook")
			}
		}
		if s.Name.Local == "sheets" {
			if len(e.Path) != 2 || sheetList {
				return xlsxFail("invalid_xlsx_workbook")
			}
			sheetList = true
		}
		if s.Name.Local == "sheet" {
			if len(e.Path) != 3 || e.Path[1].Local != "sheets" {
				return xlsxFail("invalid_xlsx_workbook")
			}
			name, id := xlsxAttribute(s, "", "name"), xlsxAttribute(s, strings.TrimSuffix(xlsxOffice, "/"), "id")
			if !validSheetName(name) || seenNames[strings.ToLower(name)] || id == "" || seenIDs[id] || w.rels[workbook][id].kind != xlsxOffice+"worksheet" {
				return xlsxFail("invalid_xlsx_sheet")
			}
			if len(sheets) >= w.c.Container.MaxEntries {
				return xlsxFail("xlsx_structure_limit")
			}
			seenNames[strings.ToLower(name)], seenIDs[id] = true, true
			sheets = append(sheets, xlsxSheet{name, id})
		}
		return nil
	})
	if err != nil {
		return err
	}
	if w.c.DateMode == "serial_1900" && date1904 || w.c.DateMode == "serial_1904" && !date1904 {
		return xlsxFail("xlsx_date_system_mismatch")
	}
	selected, shared := "", ""
	referenced := map[string]bool{workbook: true}
	for _, s := range sheets {
		target := w.rels[workbook][s.id].target
		if referenced[target] {
			return xlsxFail("invalid_xlsx_sheet")
		}
		referenced[target] = true
		if s.name == w.c.Sheet {
			selected = target
		}
	}
	if selected == "" {
		return xlsxFail("xlsx_sheet_not_found")
	}
	for _, r := range w.rels[workbook] {
		if r.kind == xlsxOffice+"sharedStrings" {
			if shared != "" {
				return xlsxFail("invalid_xlsx_strings")
			}
			shared = r.target
			referenced[shared] = true
		}
	}
	for name, t := range w.types {
		if (t == xlsxMime+"sheet.main+xml" || t == xlsxMime+"worksheet+xml" || t == xlsxMime+"sharedStrings+xml") && !referenced[name] {
			return xlsxFail("unreferenced_xlsx_part")
		}
	}
	if shared != "" {
		if err = w.shared(ctx, shared); err != nil {
			return err
		}
	}
	for _, s := range sheets {
		if err = w.worksheet(ctx, w.rels[workbook][s.id].target, s.name == w.c.Sheet); err != nil {
			return err
		}
	}
	if w.declaredRefs >= 0 && w.stringRefs != w.declaredRefs {
		return xlsxFail("invalid_xlsx_strings")
	}
	for name, t := range w.types {
		var root xml.Name
		switch t {
		case xlsxMime + "styles+xml":
			root = xml.Name{Space: xlsxMain, Local: "styleSheet"}
		case "application/vnd.openxmlformats-officedocument.theme+xml":
			root = xml.Name{Space: "http://schemas.openxmlformats.org/drawingml/2006/main", Local: "theme"}
		case "application/vnd.openxmlformats-package.core-properties+xml":
			root = xml.Name{Space: "http://schemas.openxmlformats.org/package/2006/metadata/core-properties", Local: "coreProperties"}
		case "application/vnd.openxmlformats-officedocument.extended-properties+xml":
			root = xml.Name{Space: "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties", Local: "Properties"}
		case "application/vnd.openxmlformats-officedocument.custom-properties+xml":
			root = xml.Name{Space: "http://schemas.openxmlformats.org/officeDocument/2006/custom-properties", Local: "Properties"}
		default:
			continue
		}
		if err = w.xml(ctx, name, root, func(xlsxEvent) error { return nil }); err != nil {
			return err
		}
	}
	return w.z.Verify(ctx)
}

func (w *xlsxWorkbook) shared(ctx context.Context, name string) error {
	var value xlsxText
	var declaredUnique = int64(-1)
	inItem := false
	err := w.xml(ctx, name, xml.Name{Space: xlsxMain, Local: "sst"}, func(e xlsxEvent) error {
		switch s := e.Token.(type) {
		case xml.StartElement:
			if s.Name.Space != xlsxMain {
				return xlsxFail("invalid_xlsx_strings")
			}
			if len(e.Path) == 1 {
				for _, item := range []struct {
					name   string
					target *int64
				}{{"count", &w.declaredRefs}, {"uniqueCount", &declaredUnique}} {
					v := xlsxAttribute(s, "", item.name)
					if v != "" {
						n, err := xlsxIndex(v, 1<<31-1)
						if err != nil {
							return err
						}
						*item.target = n
					}
				}
			}
			if s.Name.Local == "si" {
				if len(e.Path) != 2 || inItem || len(w.strings) >= w.c.MaxSharedStrings {
					return xlsxFail("xlsx_shared_string_limit")
				}
				inItem = true
				value.reset()
			}
			if inItem && s.Name.Local != "si" {
				if err := value.start(e.Path, "si"); err != nil {
					return err
				}
			}
		case xml.CharData:
			if len(e.Path) > 0 && e.Path[len(e.Path)-1].Local == "t" {
				if !inItem {
					return xlsxFail("xlsx_shared_string_limit")
				}
				if err := value.text(s); err != nil {
					return err
				}
			} else if !xmlSpace(s) {
				return xlsxFail("invalid_xlsx_strings")
			}
		case xml.EndElement:
			if inItem {
				if err := value.end(s.Name.Local); err != nil {
					return err
				}
				if w.stringBytes+int64(value.value.Len()) > w.c.MaxSharedBytes {
					return xlsxFail("xlsx_shared_string_limit")
				}
			}
			if s.Name.Local == "si" {
				w.strings = append(w.strings, value.value.String())
				w.stringBytes += int64(value.value.Len())
				inItem = false
			}
		}
		return nil
	})
	if err == nil && declaredUnique >= 0 && declaredUnique != int64(len(w.strings)) {
		return xlsxFail("invalid_xlsx_strings")
	}
	return err
}

var xlsxDigits = regexp.MustCompile(`^[0-9]+$`)
var xlsxAddress = regexp.MustCompile(`^([A-Z]{1,3})([1-9][0-9]{0,6})$`)
var xlsxNumeric = regexp.MustCompile(`^([+-]?)([0-9]+)(?:\.([0-9]+))?(?:[eE]([+-]?[0-9]{1,4}))?$`)

func xlsxIndex(value string, maximum int64) (int64, error) {
	if len(value) > 10 || !xlsxDigits.MatchString(value) {
		return 0, xlsxFail("invalid_xlsx_index")
	}
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil || n > maximum {
		return 0, xlsxFail("invalid_xlsx_index")
	}
	return n, nil
}

func xlsxNumber(value string, maximum int) (string, error) {
	parts := xlsxNumeric.FindStringSubmatch(value)
	if parts == nil {
		return "", xlsxFail("invalid_cell")
	}
	if parts[4] == "" {
		return value, nil
	}
	exponent, err := strconv.Atoi(parts[4])
	if err != nil || exponent < -maximum || exponent > maximum {
		return "", xlsxFail("invalid_cell")
	}
	digits := parts[2] + parts[3]
	point := len(parts[2]) + exponent
	var number string
	switch {
	case point <= 0:
		number = "0." + strings.Repeat("0", -point) + digits
	case point >= len(digits):
		number = digits + strings.Repeat("0", point-len(digits))
	default:
		number = digits[:point] + "." + digits[point:]
	}
	if len(number)+len(parts[1]) > maximum {
		return "", xlsxFail("invalid_cell")
	}
	return parts[1] + number, nil
}

func (w *xlsxWorkbook) cellValue(kind, raw, inline string) (string, string, error) {
	switch kind {
	case "inlineStr":
		return inline, "text", nil
	case "s":
		n, err := xlsxIndex(raw, int64(len(w.strings))-1)
		if err != nil {
			return "", "", err
		}
		w.stringRefs++
		return w.strings[n], "text", nil
	case "", "n":
		return raw, "number", nil
	case "d":
		if !validCell(Column{Type: "date", Required: true, MaxBytes: 10}, raw) {
			return "", "", xlsxFail("invalid_cell")
		}
		return raw, "date", nil
	default:
		return "", "", xlsxFail("unsupported_xlsx_cell_type")
	}
}

func (w *xlsxWorkbook) typedCell(c Column, value string, category string) bool {
	if value == "" {
		return !c.Required
	}
	if c.Type == "text" {
		return category == "text" && validCell(c, value)
	}
	if c.Type == "date" {
		if w.c.DateMode == "iso_text" {
			return (category == "text" || category == "date") && validCell(c, value)
		}
		if category != "number" {
			return false
		}
		date, err := xlsxSerialDate(w.c.DateMode, value)
		return err == nil && validCell(c, date)
	}
	if category != "number" {
		return false
	}
	number, err := xlsxNumber(value, c.MaxBytes)
	return err == nil && validCell(c, number)
}

func xlsxSerialDate(mode, value string) (string, error) {
	serial, err := xlsxIndex(value, 2958465)
	if err != nil || mode != "serial_1900" && mode != "serial_1904" || mode == "serial_1900" && (serial == 0 || serial == 60) {
		return "", xlsxFail("invalid_cell")
	}
	base := time.Date(1899, 12, 31, 0, 0, 0, 0, time.UTC)
	if mode == "serial_1904" {
		base = time.Date(1904, 1, 1, 0, 0, 0, 0, time.UTC)
	} else if serial > 60 {
		serial--
	}
	date := base.AddDate(0, 0, int(serial))
	if date.Year() > 9999 {
		return "", xlsxFail("invalid_cell")
	}
	return date.Format("2006-01-02"), nil
}

func (w *xlsxWorkbook) worksheet(ctx context.Context, name string, selected bool) error {
	row, lastRow, column, lastColumn := int64(0), int64(0), -1, -1
	var rowStart int64
	var raw strings.Builder
	var inline xlsxText
	kind := ""
	seenValues, seenInline := false, false
	rowValues := make([]string, len(w.c.Columns))
	rowText := make([]string, len(w.c.Columns))
	seenSheetData := false
	err := w.xml(ctx, name, xml.Name{Space: xlsxMain, Local: "worksheet"}, func(e xlsxEvent) error {
		fail := func(code string) error { return &xlsxFailure{code: code, row: row, column: column + 1} }
		if row > 0 && e.Offset-rowStart > int64(w.c.MaxRecordBytes) {
			return fail("record_byte_limit")
		}
		switch s := e.Token.(type) {
		case xml.StartElement:
			if s.Name.Space != xlsxMain {
				return fail("unsupported_xlsx_worksheet")
			}
			switch s.Name.Local {
			case "sheetData":
				if len(e.Path) != 2 || seenSheetData {
					return fail("invalid_xlsx_sheet_data")
				}
				seenSheetData = true
			case "row":
				if len(e.Path) != 3 || e.Path[1].Local != "sheetData" {
					return fail("invalid_xlsx_row")
				}
				n, err := xlsxIndex(xlsxAttribute(s, "", "r"), 1048576)
				if err != nil || n != lastRow+1 {
					return fail("xlsx_row_order_or_gap")
				}
				if n > w.c.MaxRows+1 {
					return fail("row_limit")
				}
				row, rowStart, lastColumn = n, e.Before, -1
				clear(rowValues)
				clear(rowText)
			case "c":
				if len(e.Path) != 4 || e.Path[2].Local != "row" {
					return fail("invalid_xlsx_cell")
				}
				address := xlsxAddress.FindStringSubmatch(xlsxAttribute(s, "", "r"))
				if address == nil {
					return fail("invalid_xlsx_cell")
				}
				n, _ := strconv.ParseInt(address[2], 10, 64)
				index := 0
				for _, v := range address[1] {
					index = index*26 + int(v-'A'+1)
				}
				index--
				if n != row || index <= lastColumn || index >= 128 || selected && index >= len(w.c.Columns) {
					return fail("invalid_xlsx_cell")
				}
				column, lastColumn = index, index
				kind = xlsxAttribute(s, "", "t")
				raw.Reset()
				inline.reset()
				seenValues, seenInline = false, false
				if style := xlsxAttribute(s, "", "s"); style != "" {
					if _, err := xlsxIndex(style, 65535); err != nil {
						return err
					}
				}
			case "v":
				if len(e.Path) != 5 || e.Path[3].Local != "c" || seenValues || seenInline || kind == "inlineStr" {
					return fail("invalid_xlsx_cell")
				}
				seenValues = true
			case "is":
				if len(e.Path) != 5 || e.Path[3].Local != "c" || seenValues || seenInline || kind != "inlineStr" {
					return fail("invalid_xlsx_cell")
				}
				seenInline = true
			case "t":
				if !(len(e.Path) == 6 && e.Path[4].Local == "is" || len(e.Path) == 7 && e.Path[4].Local == "is" && e.Path[5].Local == "r") {
					return fail("invalid_xlsx_cell")
				}
			}
			if seenInline && len(e.Path) > 5 && e.Path[4].Local == "is" {
				if err := inline.start(e.Path, "is"); err != nil {
					return err
				}
			}
		case xml.CharData:
			if len(e.Path) > 0 {
				switch e.Path[len(e.Path)-1].Local {
				case "v":
					if raw.Len()+len(s) > 64<<10 {
						return fail("invalid_cell")
					}
					raw.Write(s)
				case "t":
					if err := inline.text(s); err != nil {
						return err
					}
				default:
					if !xmlSpace(s) {
						return fail("invalid_xlsx_text")
					}
				}
			}
		case xml.EndElement:
			if seenInline && len(e.Path) > 5 && e.Path[4].Local == "is" {
				if err := inline.end(s.Name.Local); err != nil {
					return err
				}
			}
			if s.Name.Local == "c" {
				if e.Offset-rowStart > int64(w.c.MaxRecordBytes) {
					return fail("record_byte_limit")
				}
				value, textual, err := w.cellValue(kind, raw.String(), inline.value.String())
				if err != nil {
					return err
				}
				if selected {
					rowValues[column], rowText[column] = value, textual
				}
			}
			if s.Name.Local == "row" {
				if e.Offset-rowStart > int64(w.c.MaxRecordBytes) {
					return fail("record_byte_limit")
				}
				if selected {
					for i, c := range w.c.Columns {
						if row == 1 {
							if rowText[i] != "text" || rowValues[i] != c.Name {
								return &xlsxFailure{code: "header_mismatch", row: row, column: i + 1}
							}
						} else if !w.typedCell(c, rowValues[i], rowText[i]) {
							return &xlsxFailure{code: "invalid_cell", row: row, column: i + 1}
						}
					}
					if row > 1 {
						w.report.Rows++
					}
				}
				lastRow = row
				row = 0
				column = -1
			}
		}
		return nil
	})
	if err == nil && (!seenSheetData || selected && lastRow == 0) {
		return xlsxFail("invalid_header")
	}
	return err
}
