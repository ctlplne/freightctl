package custody

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
)

func sealRecordFixture() sealRecord {
	id := "11111111-1111-4111-8111-111111111111"
	return sealRecord{Schema: 1, Store: id, Object: Name(id, id, id), Size: 12, SHA256: secure.Digest([]byte("synthetic exact bytes")), Volume: ^uint64(0), FileID: strings.Repeat("a", 32)}
}

func TestSealCompletionRecordRequiresExactPhysicalObjectAndCanonicalMeaning(t *testing.T) {
	p := sealRecordFixture()
	wire, err := encodeSealRecord(p)
	if err != nil || validateSealRecord(wire, p) != nil {
		t.Fatal("exact native completion record refused", err)
	}
	for _, mutate := range []func(*sealRecord){
		func(p *sealRecord) { p.Schema++ },
		func(p *sealRecord) { p.Store = secure.NewID() },
		func(p *sealRecord) { p.Object = Name(p.Store, p.Store, secure.NewID()) },
		func(p *sealRecord) { p.Size++ },
		func(p *sealRecord) { p.SHA256 = secure.Digest([]byte("different bytes")) },
		func(p *sealRecord) { p.Volume-- },
		func(p *sealRecord) { p.FileID = strings.Repeat("b", 32) },
		func(p *sealRecord) { p.FileID = strings.Repeat("0", 32) },
	} {
		changed := p
		mutate(&changed)
		raw, err := json.Marshal(changed)
		if err != nil || validateSealRecord(raw, p) == nil {
			t.Fatal("copied,stale or substituted completion record qualified", err)
		}
	}
	for _, raw := range [][]byte{
		bytes.Replace(wire, []byte(`"size_bytes":12`), []byte(`"size_bytes":12,"size_bytes":12`), 1),
		bytes.Replace(wire, []byte(`"schema_version"`), []byte(`"SCHEMA_VERSION"`), 1),
		append(append([]byte{}, wire...), []byte(`{}`)...),
		append(append([]byte{}, wire...), '\n'),
		append([]byte(`{"approved":true,`), wire[1:]...),
		bytes.Repeat([]byte("x"), maximumSealRecord+1),
	} {
		if validateSealRecord(raw, p) == nil {
			t.Fatal("ambiguous or unbounded metadata became persistence evidence")
		}
	}
}

func TestSealExtendedAttributeFrameRefusesOtherNamesEntriesAndHiddenBytes(t *testing.T) {
	for _, value := range [][]byte{nil, []byte("x"), []byte("xy"), []byte("xyz"), []byte("abcd"), bytes.Repeat([]byte("x"), maximumSealRecord)} {
		wire, err := encodeSealEA(value)
		if err != nil {
			t.Fatal(err)
		}
		for _, pad := range []bool{false, true} {
			raw := append([]byte{}, wire...)
			if pad {
				raw = append(raw, make([]byte, ((len(raw)+3)&^3)-len(raw))...)
			}
			got, err := decodeSealEA(raw)
			if err != nil || !bytes.Equal(got, value) {
				t.Fatal("exact bounded EA frame refused", err)
			}
		}
	}
	if _, err := encodeSealEA(bytes.Repeat([]byte("x"), maximumSealRecord+1)); err == nil {
		t.Fatal("unbounded marker encoded")
	}
	wire, _ := encodeSealEA([]byte("exact"))
	for _, mutate := range []func([]byte){
		func(b []byte) { binary.LittleEndian.PutUint32(b[:4], 4) },
		func(b []byte) { b[4] = 0x80 },
		func(b []byte) { b[5]-- },
		func(b []byte) { b[8] = 'X' },
		func(b []byte) { b[8+len(sealEAName)] = 'x' },
		func(b []byte) { binary.LittleEndian.PutUint16(b[6:8], maximumSealRecord+1) },
	} {
		changed := append([]byte{}, wire...)
		mutate(changed)
		if _, err := decodeSealEA(changed); err == nil {
			t.Fatal("untrusted name,entry,flag or length became a flush record")
		}
	}
	for _, extra := range [][]byte{[]byte("hidden"), {0, 0, 0, 0}} {
		if _, err := decodeSealEA(append(append([]byte{}, wire...), extra...)); err == nil {
			t.Fatal("trailing EA data accepted")
		}
	}
}
