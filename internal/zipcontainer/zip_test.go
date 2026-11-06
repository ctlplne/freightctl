package zipcontainer

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"strings"
	"testing"
)

func limits() Limits {
	return Limits{MaxBytes: 1 << 20, MaxEntries: 16, MaxDirectoryBytes: 16 << 10, MaxEntryBytes: 64 << 10, MaxExpandedBytes: 128 << 10, MaxRatio: 100, MaxNameBytes: 256, MaxDepth: 8}
}

type part struct {
	name, body string
	method     uint16
	mode       fs.FileMode
}

func fixture(t testing.TB, parts ...part) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for _, p := range parts {
		h := &zip.FileHeader{Name: p.name, Method: p.method}
		if p.mode != 0 {
			h.SetMode(p.mode)
		}
		s, err := w.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = io.WriteString(s, p.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestZIPContainerReadsEveryPartWithoutExtractingOrChangingBytes(t *testing.T) {
	parts := []part{{"[Content_Types].xml", "<Types/>", zip.Store, 0}, {"xl/worksheets/sheet1.xml", "<worksheet>0001 &amp; 100.01</worksheet>", zip.Deflate, 0}}
	b := fixture(t, parts...)
	z, err := Open(context.Background(), bytes.NewReader(b), int64(len(b)), limits())
	if err != nil {
		t.Fatal(err)
	}
	entries := z.Entries()
	if len(entries) != 2 || entries[1].Name != parts[1].name || entries[1].ExpandedBytes != int64(len(parts[1].body)) {
		t.Fatal("inventory differs from actual parts")
	}
	entries[0].Name = "replaced"
	if z.Entries()[0].Name != parts[0].name {
		t.Fatal("caller mutated container inventory")
	}
	for _, p := range parts {
		var actual []byte
		err = z.Read(context.Background(), p.name, func(r io.Reader) error {
			var e error
			actual, e = io.ReadAll(r)
			return e
		})
		if err != nil || string(actual) != p.body {
			t.Fatal("member bytes changed", err)
		}
	}
	if err = z.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = z.Read(context.Background(), "absent", func(io.Reader) error { t.Fatal("missing part callback"); return nil }); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing part did not refuse", err)
	}
}

func TestZIPContainerRejectsUnsafePathsAliasesSpecialFilesAndCompression(t *testing.T) {
	for _, name := range []string{"../private", "/absolute", "a/../b", "a//b", "a/./b", `a\b`, "C:payload", "a%2fb", "a#b", "a?b", "line\nname", "trailing/", "", "é.xml", "a b"} {
		body := "private-cell-value"
		if strings.HasSuffix(name, "/") {
			body = ""
		}
		b := fixture(t, part{name: name, body: body})
		_, err := Open(context.Background(), bytes.NewReader(b), int64(len(b)), limits())
		if !errors.Is(err, ErrFormat) || strings.Contains(err.Error(), name) && name != "" {
			t.Fatalf("unsafe name was accepted or echoed: %q", name)
		}
	}
	for _, ps := range [][]part{
		{{name: "a.xml"}, {name: "a.xml"}},
		{{name: "a.xml"}, {name: "A.xml"}},
		{{name: "a.xml", mode: fs.ModeSymlink | 0600}},
		{{name: "a.xml", mode: fs.ModeNamedPipe | 0600}},
		{{name: "a.xml", mode: fs.ModeDevice | 0600}},
	} {
		b := fixture(t, ps...)
		if _, err := Open(context.Background(), bytes.NewReader(b), int64(len(b)), limits()); !errors.Is(err, ErrFormat) {
			t.Fatal("duplicate,alias or special member admitted", err)
		}
	}
	b := fixture(t, part{name: "a", body: "x"})
	c := bytes.Index(b, []byte{'P', 'K', 1, 2})
	for _, mutate := range []func([]byte){
		func(b []byte) { binary.LittleEndian.PutUint16(b[c+10:], 99) },
		func(b []byte) { b[c+8] |= 1 },
		func(b []byte) { b[c+8] |= 0x40 },
		func(b []byte) { binary.LittleEndian.PutUint16(b[c+34:], 1) },
		func(b []byte) { binary.LittleEndian.PutUint32(b[c+24:], 0xffffffff) },
	} {
		bad := bytes.Clone(b)
		mutate(bad)
		if _, err := Open(context.Background(), bytes.NewReader(bad), int64(len(bad)), limits()); !errors.Is(err, ErrFormat) {
			t.Fatal("unsupported ZIP feature admitted", err)
		}
	}
}

type observedReader struct {
	r              *bytes.Reader
	bytes, largest int
}

func (r *observedReader) ReadAt(p []byte, off int64) (int, error) {
	r.largest = max(r.largest, len(p))
	n, err := r.r.ReadAt(p, off)
	r.bytes += n
	return n, err
}

func TestZIPContainerBoundsBeforeAllocationAndBeforeDecompression(t *testing.T) {
	b := fixture(t, part{name: "a", body: "12345"}, part{name: "b", body: "67890"})
	for _, change := range []func(*Limits){
		func(l *Limits) { l.MaxBytes = int64(len(b) - 1) },
		func(l *Limits) { l.MaxEntries = 1 },
		func(l *Limits) { l.MaxDirectoryBytes = 46 },
		func(l *Limits) { l.MaxEntryBytes = 4 },
		func(l *Limits) { l.MaxExpandedBytes = 9 },
		func(l *Limits) { l.MaxNameBytes = 0 },
	} {
		l := limits()
		change(&l)
		r := &observedReader{r: bytes.NewReader(b)}
		_, err := Open(context.Background(), r, int64(len(b)), l)
		if err == nil || r.bytes > 2*len(b) || r.largest > 65557 {
			t.Fatal("container budget not enforced before parser allocation", err, r.bytes, r.largest)
		}
	}
	for _, p := range []part{{name: "a/b/c", body: "x"}, {name: "private-long-name", body: "x"}, {name: "a", body: strings.Repeat("0", 32768), method: zip.Deflate}} {
		l := limits()
		l.MaxDepth, l.MaxNameBytes, l.MaxRatio = 2, 10, 2
		body := fixture(t, p)
		if _, err := Open(context.Background(), bytes.NewReader(body), int64(len(body)), l); !errors.Is(err, ErrLimit) {
			t.Fatal("path or expansion budget escaped", err)
		}
	}
	// False EOCD entry counts must be refused before archive/zip can allocate.
	bad := bytes.Clone(b)
	e := len(bad) - 22
	binary.LittleEndian.PutUint16(bad[e+8:], 65534)
	binary.LittleEndian.PutUint16(bad[e+10:], 65534)
	r := &observedReader{r: bytes.NewReader(bad)}
	if _, err := Open(context.Background(), r, int64(len(bad)), limits()); !errors.Is(err, ErrLimit) || r.bytes > len(bad) {
		t.Fatal("hostile directory count reached allocation", err, r.bytes)
	}
}

func TestZIPContainerRejectsSplitViewOverlapsDescriptorsAndTruncation(t *testing.T) {
	b := fixture(t, part{name: "a.xml", body: "private-first"}, part{name: "b.xml", body: "second"})
	c := bytes.Index(b, []byte{'P', 'K', 1, 2})
	e := len(b) - 22
	for _, mutate := range []func([]byte){
		func(b []byte) { b[30] = 'z' },
		func(b []byte) { b[6] ^= 8 },
		func(b []byte) { b[8] = 8 },
		func(b []byte) { b[c-1] ^= 1 },
		func(b []byte) { binary.LittleEndian.PutUint32(b[c+42:], 1) },
		func(b []byte) { binary.LittleEndian.PutUint16(b[e+4:], 1) },
		func(b []byte) { binary.LittleEndian.PutUint16(b[e+10:], 1) },
		func(b []byte) { binary.LittleEndian.PutUint32(b[e+12:], 0xffffffff) },
		func(b []byte) { binary.LittleEndian.PutUint32(b[e+16:], uint32(c-1)) },
	} {
		bad := bytes.Clone(b)
		mutate(bad)
		if _, err := Open(context.Background(), bytes.NewReader(bad), int64(len(bad)), limits()); !errors.Is(err, ErrFormat) {
			t.Fatal("split view or corrupt descriptor admitted", err)
		}
	}
	for _, bad := range [][]byte{b[:len(b)-1], append(bytes.Clone(b), 'x'), append([]byte("executable-prefix"), b...)} {
		if _, err := Open(context.Background(), bytes.NewReader(bad), int64(len(bad)), limits()); !errors.Is(err, ErrFormat) {
			t.Fatal("truncated,appended or prefixed container admitted", err)
		}
	}
}

func TestZIPContainerChecksCRCOfUnreadPartsAndHonorsCancellation(t *testing.T) {
	b := fixture(t, part{name: "a", body: "private-cell-value"})
	b[31] ^= 1
	z, err := Open(context.Background(), bytes.NewReader(b), int64(len(b)), limits())
	if err != nil {
		t.Fatal(err)
	}
	// A consumer that reads nothing cannot turn an unchecked part into a pass.
	if err = z.Read(context.Background(), "a", func(io.Reader) error { return nil }); !errors.Is(err, ErrIntegrity) {
		t.Fatal("unread corrupt part bypassed CRC", err)
	}
	if err = z.Verify(context.Background()); !errors.Is(err, ErrIntegrity) {
		t.Fatal("unselected corrupt part bypassed CRC", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = Open(ctx, bytes.NewReader(b), int64(len(b)), limits()); !errors.Is(err, context.Canceled) {
		t.Fatal("open ignored canceled context", err)
	}
	if err = z.Verify(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("verification ignored canceled context", err)
	}
	if err = z.Read(context.Background(), "a", func(io.Reader) error { return context.DeadlineExceeded }); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("consumer failure ignored", err)
	}
}

func TestZIPContainerRequiresCRCCheckEvenWhenStoredCRCIsZero(t *testing.T) {
	// A producer that can seek need not use a data descriptor. Go's ZIP reader
	// treats a zero CRC in this case as absent; our acceptance must still check it.
	b := fixture(t, part{name: "a", body: "private-cell-value"})
	c := bytes.Index(b, []byte{'P', 'K', 1, 2})
	crc, compressed, expanded := number(b[c:], 16), number(b[c:], 20), number(b[c:], 24)
	b = append(bytes.Clone(b[:c-16]), b[c:]...)
	c -= 16
	binary.LittleEndian.PutUint16(b[6:], word(b, 6)&^8)
	binary.LittleEndian.PutUint16(b[c+8:], word(b[c:], 8)&^8)
	binary.LittleEndian.PutUint32(b[14:], crc)
	binary.LittleEndian.PutUint32(b[18:], compressed)
	binary.LittleEndian.PutUint32(b[22:], expanded)
	binary.LittleEndian.PutUint32(b[len(b)-22+16:], uint32(c))
	z, err := Open(context.Background(), bytes.NewReader(b), int64(len(b)), limits())
	if err != nil || z.Verify(context.Background()) != nil {
		t.Fatal("valid descriptor-free ZIP refused", err)
	}
	binary.LittleEndian.PutUint32(b[14:], 0)
	binary.LittleEndian.PutUint32(b[c+16:], 0)
	z, err = Open(context.Background(), bytes.NewReader(b), int64(len(b)), limits())
	if err != nil {
		t.Fatal(err)
	}
	if err = z.Verify(context.Background()); !errors.Is(err, ErrIntegrity) {
		t.Fatal("zero stored CRC disabled integrity verification", err)
	}
}

func TestZIPContainerEmptyArchiveStillHonorsRevokedParentContext(t *testing.T) {
	b := fixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	z, err := Open(ctx, bytes.NewReader(b), int64(len(b)), limits())
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if err = z.Verify(context.Background()); !errors.Is(err, context.Canceled) {
		t.Fatal("empty container bypassed its canceled parent", err)
	}
}

func FuzzZIPContainer(f *testing.F) {
	f.Add(fixture(f, part{name: "a.xml", body: "<a/>", method: zip.Deflate}))
	f.Add([]byte("PK\x05\x06"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65536 {
			return
		}
		ctx := context.Background()
		z, err := Open(ctx, bytes.NewReader(b), int64(len(b)), limits())
		if err == nil {
			if len(z.Entries()) > limits().MaxEntries {
				t.Fatal("entry count escaped limits")
			}
			_ = z.Verify(ctx)
		}
	})
}
