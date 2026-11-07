package scanner

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/protectedfs"
)

var detectionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

func record(reader *bufio.Reader) (string, error) {
	var data [2049]byte
	for i := 0; i < len(data); i++ {
		b, err := reader.ReadByte()
		if err != nil {
			return "", ErrProtocol
		}
		if b == 0 {
			if !utf8.Valid(data[:i]) {
				return "", ErrProtocol
			}
			return string(data[:i]), nil
		}
		if b < 32 || b > 126 {
			return "", ErrProtocol
		}
		data[i] = b
	}
	return "", ErrProtocol
}
func write(w io.Writer, data []byte) error {
	n, err := w.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	return nil
}

// Scan sends only an exact source stream, never a daemon-visible filesystem
// path. One IDSESSION ties before/after engine versions to one private socket.
// Concurrent bounded reply reading avoids a deadlock on early engine errors.
func Scan(ctx context.Context, d Definition, now time.Time, source io.Reader, size int64, digest string, check func() error) (*Result, error) {
	if err := Validate(d, now); err != nil {
		return nil, err
	}
	if size < 0 || size > d.MaxBytes || !hashPattern.MatchString(digest) {
		return nil, ErrInput
	}
	if err := ConfigurationCurrent(ctx, d); err != nil {
		return nil, err
	}
	before, err := os.Lstat(d.Socket)
	if err != nil || before.Mode()&os.ModeSocket == 0 {
		return nil, ErrUnavailable
	}
	socket, err := protectedfs.OpenPrivateSocket(d.Socket)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer socket.Close()
	ctx, cancel := context.WithTimeout(ctx, time.Duration(d.TimeoutSeconds)*time.Second)
	defer cancel()
	dialer := net.Dialer{Timeout: 2 * time.Second}
	connection, err := dialer.DialContext(ctx, "unix", d.Socket)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer connection.Close()
	after, err := os.Lstat(d.Socket)
	if err != nil || !os.SameFile(before, after) || socket.Validate() != nil {
		return nil, ErrUnavailable
	}
	deadline, _ := ctx.Deadline()
	if err = connection.SetDeadline(deadline); err != nil {
		return nil, ErrUnavailable
	}
	stop, closed := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(closed)
		select {
		case <-ctx.Done():
			_ = connection.Close()
		case <-stop:
		}
	}()
	defer func() { close(stop); <-closed }()
	reader := bufio.NewReaderSize(connection, 4096)
	if err = write(connection, []byte("zIDSESSION\x00zVERSION\x00")); err != nil {
		return nil, ErrUnavailable
	}
	version, err := record(reader)
	if err != nil || version != "1: "+d.ExpectedVersion {
		return nil, ErrUnavailable
	}
	parsed, err := ParseVersion(d.ExpectedVersion)
	if err != nil {
		return nil, ErrProtocol
	}
	if err = check(); err != nil {
		return nil, err
	}
	if err = write(connection, []byte("zINSTREAM\x00")); err != nil {
		return nil, ErrUnavailable
	}
	type written struct {
		count  int64
		digest string
		err    error
	}
	done := make(chan written, 1)
	var terminatorReady atomic.Bool
	go func() {
		h := secure.NewDigest()
		buffer := make([]byte, 32<<10)
		defer secure.Clear(buffer)
		var total int64
		var header [4]byte
		fail := func(err error) { done <- written{err: err}; _ = connection.Close() }
		for total < size {
			if err := ctx.Err(); err != nil {
				fail(err)
				return
			}
			if err := check(); err != nil {
				fail(err)
				return
			}
			n, err := io.ReadFull(source, buffer[:min(int64(len(buffer)), size-total)])
			if err != nil {
				fail(ErrSource)
				return
			}
			binary.BigEndian.PutUint32(header[:], uint32(n))
			if err = write(connection, header[:]); err == nil {
				err = write(connection, buffer[:n])
			}
			if err != nil {
				fail(ErrUnavailable)
				return
			}
			h.Write(buffer[:n])
			total += int64(n)
		}
		var tail [1]byte
		n, err := source.Read(tail[:])
		if n != 0 || err != io.EOF || hex.EncodeToString(h.Sum(nil)) != digest {
			fail(ErrSource)
			return
		}
		terminatorReady.Store(true)
		header = [4]byte{}
		err = write(connection, header[:])
		done <- written{count: total, digest: hex.EncodeToString(h.Sum(nil)), err: err}
	}()
	response, readErr := record(reader)
	if readErr != nil || !terminatorReady.Load() {
		cancel()
		_ = connection.Close()
	}
	sent := <-done
	if sent.err != nil {
		return nil, sent.err
	}
	if readErr != nil || !terminatorReady.Load() {
		return nil, ErrUnavailable
	}
	result := &Result{Backend: Backend, Version: parsed, VersionSHA256: secure.Digest([]byte(d.ExpectedVersion)), ConfigurationSHA256: d.ConfigurationSHA256, ResponseSHA256: secure.Digest([]byte(response)), Bytes: sent.count, SHA256: sent.digest}
	if response == "2: stream: OK" {
		result.Verdict = "clean"
	} else {
		name := strings.TrimSuffix(strings.TrimPrefix(response, "2: stream: "), " FOUND")
		if !strings.HasPrefix(response, "2: stream: ") || !strings.HasSuffix(response, " FOUND") || !detectionPattern.MatchString(name) {
			return nil, ErrProtocol
		}
		result.Verdict = "detected"
		result.DetectionSHA256 = secure.Digest([]byte(name))
		if strings.HasPrefix(name, "Heuristics.Limits.") || strings.HasPrefix(name, "Heuristics.Encrypted.") {
			result.Verdict = "blocked"
		}
	}
	if err = write(connection, []byte("zVERSION\x00")); err != nil {
		return nil, ErrUnavailable
	}
	version, err = record(reader)
	if err != nil || version != "3: "+d.ExpectedVersion {
		return nil, ErrUnavailable
	}
	if err = write(connection, []byte("zEND\x00")); err != nil {
		return nil, ErrUnavailable
	}
	if _, err = reader.ReadByte(); err != io.EOF {
		return nil, ErrProtocol
	}
	if err = check(); err != nil {
		return nil, err
	}
	if err = ConfigurationCurrent(ctx, d); err != nil {
		return nil, err
	}
	if err = socket.Validate(); err != nil {
		return nil, ErrUnavailable
	}
	return result, nil
}
