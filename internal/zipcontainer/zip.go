// Package zipcontainer reads bounded ZIP32 document containers without extracting
// paths, launching a process, fetching a resource or opening a nested archive.
// It validates allocation-driving metadata before handing bytes to archive/zip.
package zipcontainer

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"hash"
	"hash/crc32"
	"io"
	"path"
	"slices"
	"strings"
	"sync/atomic"
)

var (
	ErrInput       = errors.New("invalid container policy")
	ErrFormat      = errors.New("unsupported or ambiguous container")
	ErrLimit       = errors.New("container processing limit")
	ErrIntegrity   = errors.New("container member integrity failure")
	ErrNotFound    = errors.New("container part not found")
	ErrUnavailable = errors.New("container source unavailable")
)

// Limits are product input-processing limits selected by the calling policy.
// They are unrelated to CI runner capacity. No defaults silently widen a policy.
type Limits struct {
	MaxBytes          int64
	MaxEntries        int
	MaxDirectoryBytes int64
	MaxEntryBytes     int64
	MaxExpandedBytes  int64
	MaxRatio          uint32
	MaxNameBytes      int
	MaxDepth          int
}

type Entry struct {
	Name            string
	CompressedBytes int64
	ExpandedBytes   int64
	Method          uint16
}

type member struct {
	Entry
	flags, version, clock, date uint16
	crc                         uint32
	offset, data                int64
	file                        *zip.File
}

// ZIP retains a ReaderAt over the caller's immutable source. The source and the
// parent context must remain valid throughout use. Callers separately bind the
// whole source length/digest and obtain release authority through ordinary custody.
type ZIP struct {
	entries     []member
	ctx         context.Context
	unavailable *atomic.Bool
}

type contextSource struct {
	ctx         context.Context
	source      io.ReaderAt
	size        int64
	unavailable *atomic.Bool
}

func (r contextSource) ReadAt(p []byte, off int64) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if off < 0 || off > r.size || int64(len(p)) > r.size-off {
		return 0, io.EOF
	}
	n, err := r.source.ReadAt(p, off)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		r.unavailable.Store(true)
		return n, ErrUnavailable
	}
	return n, err
}

func policyOK(l Limits) bool {
	return l.MaxBytes > 0 && l.MaxBytes < 1<<32 && l.MaxEntries > 0 && l.MaxEntries < 65535 &&
		l.MaxDirectoryBytes > 0 && l.MaxEntryBytes > 0 && l.MaxExpandedBytes > 0 && l.MaxRatio > 0 &&
		l.MaxNameBytes > 0 && l.MaxNameBytes <= 65535 && l.MaxDepth > 0
}

func readAt(r io.ReaderAt, offset int64, n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := r.ReadAt(b, offset); err != nil {
		return nil, ErrFormat
	}
	return b, nil
}

var le = binary.LittleEndian

func word(b []byte, p int) uint16   { return le.Uint16(b[p : p+2]) }
func number(b []byte, p int) uint32 { return le.Uint32(b[p : p+4]) }

func validName(name string, l Limits) error {
	if name == "" || path.Clean(name) != name || strings.HasPrefix(name, "/") || strings.HasSuffix(name, "/") || name == "." || name == ".." || strings.HasPrefix(name, "../") {
		return ErrFormat
	}
	for _, c := range []byte(name) {
		// OPC part paths have no URI escapes,fragments,queries or drive prefixes
		// in this profile. No host path normalization or percent decoding occurs.
		if c < 0x21 || c > 0x7e || strings.ContainsRune(`\:%?#`, rune(c)) {
			return ErrFormat
		}
	}
	if len(name) > l.MaxNameBytes || strings.Count(name, "/")+1 > l.MaxDepth {
		return ErrLimit
	}
	return nil
}

func validExtra(b []byte) bool {
	for len(b) > 0 {
		if len(b) < 4 || int(word(b, 2)) > len(b)-4 {
			return false
		}
		switch word(b, 0) {
		case 0x0001, 0x7075, 0x6375, 0x9901:
			// ZIP64,alternate Unicode names/comments and AES encryption would
			// introduce another interpretation outside this exact profile.
			return false
		}
		b = b[4+int(word(b, 2)):]
	}
	return true
}

// Open validates EOCD,central-directory and local-header agreement before
// archive/zip allocates its entry collection. Only stored/deflated regular files
// in one contiguous ZIP32 volume are accepted. Member contents are not yet read.
func Open(ctx context.Context, input io.ReaderAt, size int64, l Limits) (*ZIP, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !policyOK(l) || input == nil {
		return nil, ErrInput
	}
	if size > l.MaxBytes {
		return nil, ErrLimit
	}
	if size < 22 {
		return nil, ErrFormat
	}
	fault := &atomic.Bool{}
	r := contextSource{ctx: ctx, source: input, size: size, unavailable: fault}
	entries, err := inspect(r, size, l)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if fault.Load() {
		return nil, ErrUnavailable
	}
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	z, err := zip.NewReader(r, size)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if fault.Load() {
		return nil, ErrUnavailable
	}
	if err != nil || len(z.File) != len(entries) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrFormat
	}
	for i, f := range z.File {
		m := &entries[i]
		offset, e := f.DataOffset()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if fault.Load() {
			return nil, ErrUnavailable
		}
		if e != nil || f.Name != m.Name || f.Flags != m.flags || f.Method != m.Method || f.CRC32 != m.crc ||
			f.CompressedSize64 != uint64(m.CompressedBytes) || f.UncompressedSize64 != uint64(m.ExpandedBytes) || offset != m.data || !f.Mode().IsRegular() {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, ErrFormat
		}
		m.file = f
	}
	return &ZIP{entries: entries, ctx: ctx, unavailable: fault}, nil
}

func inspect(r io.ReaderAt, size int64, l Limits) ([]member, error) {
	tailSize := int(min(size, 22+65535))
	tail, err := readAt(r, size-int64(tailSize), tailSize)
	if err != nil {
		return nil, err
	}
	end := -1
	for i := len(tail) - 22; i >= 0; i-- {
		if number(tail, i) == 0x06054b50 && i+22+int(word(tail, i+20)) == len(tail) {
			if end >= 0 {
				return nil, ErrFormat
			}
			end = i
		}
	}
	if end < 0 {
		return nil, ErrFormat
	}
	e := tail[end:]
	count := int(word(e, 10))
	directory, directoryBytes := int64(number(e, 16)), int64(number(e, 12))
	if word(e, 4) != 0 || word(e, 6) != 0 || word(e, 8) != word(e, 10) || count == 65535 || directory == 0xffffffff || directoryBytes == 0xffffffff || directory+directoryBytes != size-int64(tailSize)+int64(end) {
		return nil, ErrFormat
	}
	if count > l.MaxEntries || directoryBytes > l.MaxDirectoryBytes {
		return nil, ErrLimit
	}
	if directoryBytes < int64(count)*46 {
		return nil, ErrFormat
	}
	entries := make([]member, 0, count)
	seen := make(map[string]bool, count)
	offset, expanded := directory, int64(0)
	for range count {
		if directory+directoryBytes-offset < 46 {
			return nil, ErrFormat
		}
		h, err := readAt(r, offset, 46)
		if err != nil || number(h, 0) != 0x02014b50 {
			return nil, ErrFormat
		}
		nameBytes, extraBytes, commentBytes := int(word(h, 28)), int(word(h, 30)), int(word(h, 32))
		length := int64(46 + nameBytes + extraBytes + commentBytes)
		if length > directory+directoryBytes-offset || word(h, 34) != 0 || word(h, 6) > 20 || word(h, 8)&^uint16(0x080e) != 0 || word(h, 10) != zip.Store && word(h, 10) != zip.Deflate || number(h, 20) == 0xffffffff || number(h, 24) == 0xffffffff || number(h, 42) == 0xffffffff {
			return nil, ErrFormat
		}
		if nameBytes > l.MaxNameBytes {
			return nil, ErrLimit
		}
		name, err := readAt(r, offset+46, nameBytes)
		if err != nil {
			return nil, err
		}
		if err = validName(string(name), l); err != nil {
			return nil, err
		}
		if seen[strings.ToLower(string(name))] {
			return nil, ErrFormat
		}
		seen[strings.ToLower(string(name))] = true
		extra, err := readAt(r, offset+46+int64(nameBytes), extraBytes)
		if err != nil || !validExtra(extra) {
			return nil, ErrFormat
		}
		m := member{Entry: Entry{string(name), int64(number(h, 20)), int64(number(h, 24)), word(h, 10)}, flags: word(h, 8), version: word(h, 6), clock: word(h, 12), date: word(h, 14), crc: number(h, 16), offset: int64(number(h, 42))}
		if m.Method == zip.Store && m.CompressedBytes != m.ExpandedBytes || m.CompressedBytes == 0 && m.ExpandedBytes != 0 {
			return nil, ErrFormat
		}
		if m.ExpandedBytes > l.MaxEntryBytes || m.ExpandedBytes > l.MaxExpandedBytes-expanded || uint64(m.ExpandedBytes) > uint64(max(int64(1), m.CompressedBytes))*uint64(l.MaxRatio) {
			return nil, ErrLimit
		}
		expanded += m.ExpandedBytes
		entries = append(entries, m)
		offset += length
	}
	if offset != directory+directoryBytes {
		return nil, ErrFormat
	}
	// Local order need not equal central order. Validate physical spans in order
	// without mutating the central index used by archive/zip and relationship IDs.
	order := make([]int, len(entries))
	for i := range order {
		order[i] = i
	}
	slices.SortFunc(order, func(a, b int) int {
		if entries[a].offset < entries[b].offset {
			return -1
		}
		if entries[a].offset > entries[b].offset {
			return 1
		}
		return 0
	})
	next := int64(0)
	for i, index := range order {
		m := &entries[index]
		limit := directory
		if i+1 < len(order) {
			limit = entries[order[i+1]].offset
		}
		if m.offset != next || limit-m.offset < 30 {
			return nil, ErrFormat
		}
		h, err := readAt(r, m.offset, 30)
		if err != nil || number(h, 0) != 0x04034b50 || word(h, 4) != m.version || word(h, 6) != m.flags || word(h, 8) != m.Method || word(h, 10) != m.clock || word(h, 12) != m.date || int(word(h, 26)) != len(m.Name) {
			return nil, ErrFormat
		}
		nameBytes, extraBytes := len(m.Name), int(word(h, 28))
		m.data = m.offset + 30 + int64(nameBytes+extraBytes)
		dataEnd := m.data + m.CompressedBytes
		if dataEnd > limit {
			return nil, ErrFormat
		}
		name, err := readAt(r, m.offset+30, nameBytes)
		if err != nil || !bytes.Equal(name, []byte(m.Name)) {
			return nil, ErrFormat
		}
		extra, err := readAt(r, m.offset+30+int64(nameBytes), extraBytes)
		if err != nil || !validExtra(extra) {
			return nil, ErrFormat
		}
		if m.flags&8 == 0 {
			if number(h, 14) != m.crc || int64(number(h, 18)) != m.CompressedBytes || int64(number(h, 22)) != m.ExpandedBytes || dataEnd != limit {
				return nil, ErrFormat
			}
		} else {
			if number(h, 14) != 0 && number(h, 14) != m.crc || number(h, 18) != 0 && int64(number(h, 18)) != m.CompressedBytes || number(h, 22) != 0 && int64(number(h, 22)) != m.ExpandedBytes {
				return nil, ErrFormat
			}
			n := limit - dataEnd
			if n != 12 && n != 16 {
				return nil, ErrFormat
			}
			d, err := readAt(r, dataEnd, int(n))
			if err != nil {
				return nil, err
			}
			if n == 16 {
				if number(d, 0) != 0x08074b50 {
					return nil, ErrFormat
				}
				d = d[4:]
			}
			if number(d, 0) != m.crc || int64(number(d, 4)) != m.CompressedBytes || int64(number(d, 8)) != m.ExpandedBytes {
				return nil, ErrFormat
			}
		}
		next = limit
	}
	if next != directory {
		return nil, ErrFormat
	}
	return entries, nil
}

func (z *ZIP) Entries() []Entry {
	entries := make([]Entry, len(z.entries))
	for i, m := range z.entries {
		entries[i] = m.Entry
	}
	return entries
}

type contextReader struct {
	ctx  context.Context
	r    io.Reader
	n    int64
	hash hash.Hash32
	err  error
}

func (r *contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := r.r.Read(p)
	r.n += int64(n)
	_, _ = r.hash.Write(p[:n])
	if err != nil && !errors.Is(err, io.EOF) {
		r.err = err
	}
	return n, err
}

// Read passes a bounded member stream to a trusted parser,then drains it to EOF
// to check the actual length and CRC even if that parser stops reading early.
// A callback error refuses the operation immediately; it never establishes a pass.
func (z *ZIP) Read(ctx context.Context, name string, consume func(io.Reader) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := z.ctx.Err(); err != nil {
		return err
	}
	if z.unavailable.Load() {
		return ErrUnavailable
	}
	if consume == nil {
		return ErrInput
	}
	for _, m := range z.entries {
		if m.Name != name {
			continue
		}
		r, err := m.file.Open()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if z.ctx.Err() != nil {
			return z.ctx.Err()
		}
		if z.unavailable.Load() {
			return ErrUnavailable
		}
		if err != nil {
			if z.ctx.Err() != nil {
				return z.ctx.Err()
			}
			if z.unavailable.Load() {
				return ErrUnavailable
			}
			return ErrIntegrity
		}
		defer r.Close()
		stream := &contextReader{ctx: ctx, r: io.LimitReader(r, m.ExpandedBytes+1), hash: crc32.NewIEEE()}
		if err = consume(stream); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if z.ctx.Err() != nil {
				return z.ctx.Err()
			}
			if stream.err != nil {
				return ErrIntegrity
			}
			return err
		}
		_, err = io.CopyBuffer(io.Discard, stream, make([]byte, 32<<10))
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if z.ctx.Err() != nil {
			return z.ctx.Err()
		}
		if z.unavailable.Load() {
			return ErrUnavailable
		}
		if err != nil || stream.err != nil || stream.n != m.ExpandedBytes || stream.hash.Sum32() != m.crc {
			return ErrIntegrity
		}
		return nil
	}
	return ErrNotFound
}

// Verify fully reads every member,including parts that a worksheet parser does
// not select. It does not recursively interpret member contents.
func (z *ZIP) Verify(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := z.ctx.Err(); err != nil {
		return err
	}
	for _, m := range z.entries {
		if err := z.Read(ctx, m.Name, func(io.Reader) error { return nil }); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return z.ctx.Err()
}
