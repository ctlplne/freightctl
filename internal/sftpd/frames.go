package sftpd

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/ctlplne/freightctl/internal/vpath"
)

var errPacket = errors.New("SFTP packet exceeds the supported framing or attribute contract")

type attributes struct {
	size     *int64
	mode     *uint32
	modified *time.Time
}
type frameStream struct {
	io.ReadWriteCloser
	ctx               context.Context
	cancel            context.CancelFunc
	credit            chan struct{}
	mu                sync.Mutex
	current           attributes
	input             []byte
	offset, packets   int
	outputHeader      [4]byte
	outputHeaderBytes int
	outputRemaining   uint32
}

func newFrameStream(ctx context.Context, stream io.ReadWriteCloser) *frameStream {
	ctx, cancel := context.WithCancel(ctx)
	f := &frameStream{ReadWriteCloser: stream, ctx: ctx, cancel: cancel, credit: make(chan struct{}, 1)}
	f.credit <- struct{}{}
	return f
}
func (f *frameStream) Close() error           { f.cancel(); return f.ReadWriteCloser.Close() }
func (f *frameStream) Attributes() attributes { f.mu.Lock(); defer f.mu.Unlock(); return f.current }
func virtualPath(raw string) (string, error) {
	if len(raw) > 1024 {
		return "", vpath.ErrPath
	}
	parts := []string{}
	for _, part := range strings.Split(raw, "/") {
		switch part {
		case "", ".":
			continue
		case "..":
			if len(parts) == 0 {
				return "", vpath.ErrPath
			}
			parts = parts[:len(parts)-1]
		default:
			parts = append(parts, part)
		}
	}
	return vpath.Canonical("/" + strings.Join(parts, "/"))
}
func wireString(body []byte) (string, []byte, error) {
	if len(body) < 4 {
		return "", nil, errPacket
	}
	n := binary.BigEndian.Uint32(body[:4])
	body = body[4:]
	if n > 1024 || int(n) > len(body) {
		return "", nil, errPacket
	}
	return string(body[:n]), body[n:], nil
}
func parseAttributes(flags uint32, body []byte) (attributes, error) {
	var a attributes
	if flags & ^uint32(0x0d) != 0 {
		return a, errPacket
	} // Ownership and extension attributes are unsupported.
	if flags&1 != 0 {
		if len(body) < 8 {
			return a, errPacket
		}
		n := binary.BigEndian.Uint64(body[:8])
		if n > 1<<30 {
			return a, errPacket
		}
		size := int64(n)
		a.size = &size
		body = body[8:]
	}
	if flags&4 != 0 {
		if len(body) < 4 {
			return a, errPacket
		}
		mode := binary.BigEndian.Uint32(body[:4])
		if mode & ^uint32(0100777) != 0 && mode & ^uint32(040777) != 0 {
			return a, errPacket
		}
		mode &= 0777
		a.mode = &mode
		body = body[4:]
	}
	if flags&8 != 0 {
		if len(body) < 8 {
			return a, errPacket
		}
		modified := time.Unix(int64(binary.BigEndian.Uint32(body[4:8])), 0).UTC()
		a.modified = &modified
		body = body[8:]
	}
	if len(body) != 0 {
		return a, errPacket
	}
	return a, nil
}

// Inspect raw paths before the library cleans them, and retain creation attrs
// that its Request interface does not expose. Framing is serialized, so these
// attributes belong to the one command currently being processed.
func inspectPacket(body []byte) (attributes, error) {
	var a attributes
	if len(body) < 1 {
		return a, errPacket
	}
	kind := body[0]
	if kind == 1 {
		if len(body) != 5 || binary.BigEndian.Uint32(body[1:]) != 3 {
			return a, errPacket
		}
		return a, nil
	}
	if len(body) < 5 {
		return a, errPacket
	}
	rest := body[5:]
	switch kind {
	case 3, 7, 9, 11, 13, 14, 15, 16, 17, 18:
		raw, tail, err := wireString(rest)
		if err != nil {
			return a, err
		}
		if _, err = virtualPath(raw); err != nil {
			return a, err
		}
		rest = tail
		if kind == 3 {
			if len(rest) < 8 {
				return a, errPacket
			}
			flags := binary.BigEndian.Uint32(rest[:4])
			if flags & ^uint32(0x3f) != 0 {
				return a, errPacket
			}
			rest = rest[4:]
		}
		if kind == 3 || kind == 9 || kind == 14 {
			if len(rest) < 4 {
				return a, errPacket
			}
			return parseAttributes(binary.BigEndian.Uint32(rest[:4]), rest[4:])
		}
		if kind == 18 {
			target, _, err := wireString(rest)
			if err != nil {
				return a, err
			}
			_, err = virtualPath(target)
			return a, err
		}
	case 10:
		_, tail, err := wireString(rest)
		if err != nil || len(tail) < 4 {
			return a, errPacket
		}
		return parseAttributes(binary.BigEndian.Uint32(tail[:4]), tail[4:])
	case 200:
		extension, tail, err := wireString(rest)
		if err != nil {
			return a, err
		}
		if extension == "posix-rename@openssh.com" {
			for i := 0; i < 2; i++ {
				raw, next, err := wireString(tail)
				if err != nil {
					return a, err
				}
				if _, err = virtualPath(raw); err != nil {
					return a, err
				}
				tail = next
			}
			if len(tail) != 0 {
				return a, errPacket
			}
		}
	}
	return a, nil
}
func (f *frameStream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if f.offset == len(f.input) {
		select {
		case <-f.ctx.Done():
			return 0, f.ctx.Err()
		case <-f.credit:
		}
		if f.packets >= 100000 {
			return 0, errPacket
		}
		f.packets++
		header := make([]byte, 4)
		if _, err := io.ReadFull(f.ReadWriteCloser, header); err != nil {
			return 0, err
		}
		size := binary.BigEndian.Uint32(header)
		if size < 1 || size > 256<<10 {
			return 0, errPacket
		}
		packet := make([]byte, int(size)+4)
		copy(packet, header)
		if _, err := io.ReadFull(f.ReadWriteCloser, packet[4:]); err != nil {
			return 0, err
		}
		attrs, err := inspectPacket(packet[4:])
		if err != nil {
			return 0, err
		}
		f.mu.Lock()
		f.current = attrs
		f.mu.Unlock()
		f.input = packet
		f.offset = 0
	}
	n := copy(p, f.input[f.offset:])
	f.offset += n
	return n, nil
}
func (f *frameStream) Write(p []byte) (int, error) {
	n, err := f.ReadWriteCloser.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	if err != nil {
		f.cancel()
		return n, err
	}
	pending := p[:n]
	for len(pending) > 0 {
		if f.outputRemaining == 0 {
			count := copy(f.outputHeader[f.outputHeaderBytes:], pending)
			f.outputHeaderBytes += count
			pending = pending[count:]
			if f.outputHeaderBytes < 4 {
				break
			}
			f.outputRemaining = binary.BigEndian.Uint32(f.outputHeader[:])
			f.outputHeaderBytes = 0
			if f.outputRemaining < 1 || f.outputRemaining > 256<<10 {
				f.cancel()
				return n, errPacket
			}
		}
		take := len(pending)
		if uint32(take) > f.outputRemaining {
			take = int(f.outputRemaining)
		}
		pending = pending[take:]
		f.outputRemaining -= uint32(take)
		if f.outputRemaining == 0 {
			select {
			case f.credit <- struct{}{}:
			default:
				f.cancel()
				return n, errPacket
			}
		}
	}
	return n, nil
}
