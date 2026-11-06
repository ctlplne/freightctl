package checks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

func xmlRecordsPolicy(t testing.TB) Policy {
	t.Helper()
	var p Policy
	if err := json.Unmarshal([]byte(`{"schema_version":4,"kind":"xml_records","columns":[{"name":"account","type":"text","required":true,"max_bytes":32},{"name":"amount","type":"decimal","required":true,"max_bytes":32,"precision":12,"scale":2},{"name":"day","type":"date","required":true,"max_bytes":10}],"max_bytes":8192,"max_rows":4,"max_record_bytes":1024,"timeout_seconds":2,"xml":{"root":"records","record":"record","namespace":""}}`), &p); err != nil {
		t.Fatal(err)
	}
	return p
}

const xmlGoodRecord = `<record><account>0001</account><amount>100.01</amount><day>2026-10-28</day></record>`

func TestXMLRecordsRejectEntitiesAmbiguousNamespacesAndNonScalarData(t *testing.T) {
	p := xmlRecordsPolicy(t)
	valid := "<records>" + xmlGoodRecord + "</records>"
	for _, body := range []string{
		"<records/>", valid, "\xef\xbb\xbf" + `<?xml version='1.0' encoding='utf-8' standalone='yes'?>` + valid,
		strings.Replace(valid, "0001", "000&#49;", 1), strings.Replace(valid, "0001", "<![CDATA[0001]]>", 1),
		"<!--inert-->" + strings.Replace(valid, "100.01", "100<!--inert-->.01", 1) + "<!--inert-->",
	} {
		f := store.File{Size: int64(len(body)), SHA256: secure.Digest([]byte(body))}
		r, e := Validate(t.Context(), p, f, "", strings.NewReader(body))
		if e != nil || r.Code != "valid_xml_records" {
			t.Fatal("valid bounded XML refused", e, r.Code)
		}
	}
	for _, body := range []string{
		"", valid + "<records/>", strings.TrimSuffix(valid, "</records>"), strings.Replace(valid, "</account>", "</amount>", 1),
		strings.Replace(valid, "</account>", "</account><account>0002</account>", 1), strings.Replace(valid, "<day>", "<unknown>", 1),
		strings.Replace(valid, "0001", "<account>0001</account>", 1), strings.Replace(valid, "<account>", `<account execute="yes">`, 1),
		strings.Replace(valid, "<record>", `<record xmlns="urn:foreign">`, 1), strings.Replace(valid, "<records>", `<records href="https://never-contact.invalid/">`, 1),
		strings.Replace(valid, "<account>", "<foreign:account>", 1), strings.Replace(valid, "0001", "&external;", 1),
		`<!DOCTYPE records [<!ENTITY external SYSTEM "file:///never-open">]>` + valid,
		`<!DOCTYPE records SYSTEM "https://never-contact.invalid/dtd">` + valid,
		`<?xml-stylesheet href="https://never-contact.invalid/style"?>` + valid,
		strings.Replace(valid, "0001", "&#0;", 1), "<!--\x00-->" + valid, "<!--\xff-->" + valid,
		`<?xml version="1.1"?>` + valid, `<?xml encoding="UTF-8" version="1.0"?>` + valid, `<?xml version="1.0" version="1.0"?>` + valid,
		`<?xml version='1.0'encoding='UTF-8'?>` + valid,
		`<?xml version="1.0" encoding="ISO-8859-1"?>` + valid, " " + `<?xml version="1.0"?>` + valid,
		strings.Replace(valid, "100.01", "1e2", 1), strings.Replace(valid, "2026-10-28", "2026-02-30", 1), strings.Replace(valid, "0001", "", 1),
	} {
		f := store.File{Size: int64(len(body)), SHA256: secure.Digest([]byte(body))}
		r, e := Validate(t.Context(), p, f, "", strings.NewReader(body))
		if e != nil || r.Code == "valid_xml_records" {
			t.Fatal("unsafe or malformed XML passed", e, r.Code)
		}
		wire, _ := json.Marshal(r)
		for _, secret := range []string{"never-open", "never-contact", "0002", "2026-02-30"} {
			if bytes.Contains(wire, []byte(secret)) {
				t.Fatal("untrusted XML content leaked in report")
			}
		}
	}
	p.XML.Namespace = "urn:freightctl:records"
	for _, body := range []string{
		`<records xmlns="urn:freightctl:records">` + xmlGoodRecord + `</records>`,
		`<p:records xmlns:p="urn:freightctl:records"><p:record><p:account>0001</p:account><p:amount>100.01</p:amount><p:day>2026-10-28</p:day></p:record></p:records>`,
	} {
		f := store.File{Size: int64(len(body)), SHA256: secure.Digest([]byte(body))}
		r, e := Validate(t.Context(), p, f, "", strings.NewReader(body))
		if e != nil || r.Code != "valid_xml_records" {
			t.Fatal("declared exact namespace refused", e, r.Code)
		}
	}
	for _, body := range []string{valid, `<p:records>` + xmlGoodRecord + `</p:records>`, `<records xmlns="urn:freightctl:records"><record><account xmlns="">0001</account><amount>100.01</amount><day>2026-10-28</day></record></records>`, `<records xmlns="urn:freightctl:records"><record><q:account>0001</q:account><amount>100.01</amount><day>2026-10-28</day></record></records>`} {
		f := store.File{Size: int64(len(body)), SHA256: secure.Digest([]byte(body))}
		r, e := Validate(t.Context(), p, f, "", strings.NewReader(body))
		if e != nil || r.Code == "valid_xml_records" {
			t.Fatal("changed/unbound namespace accepted", e)
		}
	}
}

func TestXMLRecordsBoundsSourcePolicyAndCancellation(t *testing.T) {
	p := xmlRecordsPolicy(t)
	input := &fixedCountingReader{input: strings.NewReader("<records>" + strings.Repeat(" ", 100000))}
	p.MaxBytes = 1 << 20
	r, e := Validate(t.Context(), p, store.File{Size: 100009}, "", input)
	if e != nil || r.Code != "record_byte_limit" || input.bytes > 2*(p.MaxRecordBytes+4096) {
		t.Fatal("XML whitespace escaped bounded token growth", e, r.Code, input.bytes)
	}
	body := "<records>" + xmlGoodRecord + "</records>"
	f := store.File{Size: int64(len(body)), SHA256: strings.Repeat("f", 64)}
	r, e = Validate(t.Context(), xmlRecordsPolicy(t), f, "", strings.NewReader(body))
	if e != nil || r.Code != "source_integrity_changed" {
		t.Fatal("XML source changed", e, r.Code)
	}
	for _, change := range []func(*Policy){func(p *Policy) { p.XML = nil }, func(p *Policy) { p.XML.Root = "a:b" }, func(p *Policy) { p.XML.Namespace = "http://www.w3.org/2000/xmlns/" }, func(p *Policy) { p.Columns[0].Name = "non XML name" }, func(p *Policy) { p.Columns[0].Width = 1 }, func(p *Policy) { p.Schema, p.Kind = 2, "json_records" }} {
		bad := xmlRecordsPolicy(t)
		change(&bad)
		if _, e := Normalize(bad); !errors.Is(e, ErrInput) {
			t.Fatal("ambiguous XML policy accepted", e)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := Validate(ctx, xmlRecordsPolicy(t), f, "", strings.NewReader(body)); !errors.Is(e, context.Canceled) {
		t.Fatal("XML cancellation ignored", e)
	}
	base := xmlRecordsPolicy(t)
	normalized, e := Normalize(base)
	if e != nil {
		t.Fatal(e)
	}
	base.XML.Root = "changed"
	if normalized.XML.Root != "records" {
		t.Fatal("normalization retained mutable XML control alias")
	}
}

func FuzzXMLRecordsContract(f *testing.F) {
	f.Add([]byte("<records>" + xmlGoodRecord + "</records>"))
	f.Add([]byte(`<!DOCTYPE records SYSTEM "file:///never-open"><records/>`))
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > 8192 {
			return
		}
		p := xmlRecordsPolicy(t)
		file := store.File{Size: int64(len(body)), SHA256: secure.Digest(body)}
		r, e := Validate(t.Context(), p, file, "", bytes.NewReader(body))
		if e != nil {
			if errors.Is(e, context.DeadlineExceeded) && r.Code != "valid_xml_records" {
				return
			}
			t.Fatal(e)
		}
		if r.Code == "valid_xml_records" {
			if r.Engine != "freightctl-xml-records-v1" || r.Bytes != file.Size || r.Rows > p.MaxRows {
				t.Fatal("invalid XML success evidence")
			}
			file.SHA256 = strings.Repeat("f", 64)
			changed, e := Validate(t.Context(), p, file, "", bytes.NewReader(body))
			if e == nil && changed.Code == "valid_xml_records" {
				t.Fatal("XML immutable source changed")
			}
		}
	})
}

func TestXMLRecordsBindScalarStructureAndCompleteImmutableBytes(t *testing.T) {
	body := `<?xml version="1.0" encoding="UTF-8"?><records><record><account>0001</account><amount>100.01</amount><day>2026-10-28</day></record></records>`
	file := store.File{Size: int64(len(body)), SHA256: secure.Digest([]byte(body))}
	r, err := Validate(context.Background(), xmlRecordsPolicy(t), file, strings.Repeat("a", 64), strings.NewReader(body))
	if err != nil || r.Code != "valid_xml_records" || r.Engine != "freightctl-xml-records-v1" || r.Rows != 1 || r.Bytes != file.Size || r.SHA256 != file.SHA256 {
		t.Fatal("XML contract not enforced on exact complete source", err, r.Code)
	}
}
