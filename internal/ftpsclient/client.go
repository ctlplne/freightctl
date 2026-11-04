// Package ftpsclient implements the bounded FTPS wire operations needed by the
// delivery/collection adapters. It grants no domain authority or publication
// guarantee. Callers must supply the live lease/policy guard and private staging.
package ftpsclient

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/vpath"
)

const MaxFile int64 = 1 << 30
const MaxMetadata int64 = 32 << 10

var ErrInput = errors.New("invalid FTPS operation or configured bound")
var ErrReply = errors.New("invalid or oversized FTPS receiver reply")
var ErrConnection = errors.New("FTPS receiver connection failed")
var ErrAuthority = errors.New("FTPS live authority check failed")
var ErrIntegrity = errors.New("FTPS exact stream integrity failed")
var ErrCompletionUnknown = errors.New("FTPS transfer completion reply was not confirmed")
var ErrPublicationUnknown = errors.New("FTPS rename publication outcome is uncertain")

// ReplyError contains only a parsed status code. Peer-controlled prose never
// becomes operator evidence, an instruction, a path, or a credential-bearing log.
type ReplyError struct{ Code int }

func (e *ReplyError) Error() string { return fmt.Sprintf("FTPS receiver status %03d", e.Code) }

type reply struct {
	code  int
	lines []string
}
type Client struct {
	mu        sync.Mutex
	transport *secure.FTPSClientTransport
	reader    *bufio.Reader
	ctx       context.Context
	guard     func() error
	commands  int
}

func validPath(value string) bool {
	canonical, err := vpath.Canonical(value)
	return err == nil && canonical == value && !vpath.ControlPath(value)
}
func validHash(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func (c *Client) check() error {
	if err := c.ctx.Err(); err != nil {
		c.Close()
		return err
	}
	if err := c.guard(); err != nil {
		c.Close()
		return ErrAuthority
	}
	return nil
}
func (c *Client) Close() error { return c.transport.Close() }

// New authenticates only after verified TLS, then requires encrypted data and
// binary bytes. There is no plaintext, CCC, active-mode or arbitrary command API.
func New(ctx context.Context, d secure.FTPSDestination, guard func() error) (result *Client, err error) {
	phase := "request"
	defer func() {
		if err != nil {
			err = fmt.Errorf("FTPS connection phase %s: %w", phase, err)
		}
	}()
	if guard == nil {
		return nil, ErrInput
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if guard() != nil {
		return nil, ErrAuthority
	}
	phase = "transport"
	t, err := secure.DialFTPSClient(ctx, d)
	if err != nil {
		return nil, secure.ErrFTPSClient
	}
	c := &Client{transport: t, reader: bufio.NewReaderSize(t, 4096), ctx: ctx, guard: guard}
	ok := false
	defer func() {
		if !ok {
			c.Close()
		}
	}()
	phase = "greeting"
	r, err := c.readReply()
	if err == nil && r.code == 120 {
		r, err = c.readReply()
	}
	if err != nil {
		return nil, err
	}
	if r.code != 220 {
		return nil, &ReplyError{r.code}
	}
	if d.Mode == "explicit" {
		phase = "auth-tls"
		if _, err = c.command("AUTH", "TLS", 234); err != nil {
			return nil, err
		}
		if c.reader.Buffered() != 0 {
			return nil, ErrReply
		}
		phase = "control-tls"
		if err = t.SecureControl(); err != nil {
			return nil, secure.ErrFTPSClient
		}
	}
	phase = "username"
	if _, err = c.command("USER", d.User, 331); err != nil {
		return nil, err
	}
	phase = "credential-reference"
	password, err := secure.ReadFTPSPassword(d)
	if err != nil {
		return nil, err
	}
	packet := secure.ProtectBytes(make([]byte, 5+len(password.Bytes)+2))
	copy(packet.Bytes, []byte("PASS "))
	copy(packet.Bytes[5:], password.Bytes)
	copy(packet.Bytes[len(packet.Bytes)-2:], []byte("\r\n"))
	password.Close()
	phase = "password"
	err = c.writePacket(packet.Bytes)
	packet.Close()
	if err != nil {
		return nil, err
	}
	r, err = c.readReply()
	if err != nil {
		return nil, err
	}
	if r.code != 230 {
		return nil, &ReplyError{r.code}
	}
	for _, cmd := range [][2]string{{"PBSZ", "0"}, {"PROT", "P"}, {"TYPE", "I"}} {
		phase = "data-protection"
		if _, err = c.command(cmd[0], cmd[1], 200); err != nil {
			return nil, err
		}
	}
	ok = true
	return c, nil
}

func (c *Client) writePacket(packet []byte) error {
	if err := c.check(); err != nil {
		return err
	}
	if c.commands >= 64 {
		return ErrInput
	}
	c.commands++
	for len(packet) > 0 {
		n, err := c.transport.Write(packet)
		if err != nil || n <= 0 {
			c.Close()
			return ErrConnection
		}
		packet = packet[n:]
	}
	return nil
}
func (c *Client) command(verb, arg string, codes ...int) (reply, error) {
	if strings.ContainsAny(arg, "\r\n\x00") || len(arg) > 1024 {
		return reply{}, ErrInput
	}
	packet := verb
	if arg != "" {
		packet += " " + arg
	}
	packet += "\r\n"
	if err := c.writePacket([]byte(packet)); err != nil {
		return reply{}, err
	}
	r, err := c.readReply()
	if err != nil {
		return r, err
	}
	for _, n := range codes {
		if r.code == n {
			return r, nil
		}
	}
	return r, &ReplyError{r.code}
}

// readReply bounds each line, total bytes and multiline count before converting
// peer text to strings. The reader cannot grow in response to an endless line.
func (c *Client) readReply() (reply, error) {
	fail := func() (reply, error) { c.Close(); return reply{}, ErrReply }
	var r reply
	total := 0
	for i := 0; i < 64; i++ {
		line, err := c.reader.ReadSlice('\n')
		if err != nil || len(line) < 2 || line[len(line)-2] != '\r' {
			return fail()
		}
		total += len(line)
		if total > 64<<10 {
			return fail()
		}
		text := string(line[:len(line)-2])
		if i == 0 {
			if len(text) < 4 || text[0] < '1' || text[0] > '5' || text[1] < '0' || text[1] > '9' || text[2] < '0' || text[2] > '9' || (text[3] != ' ' && text[3] != '-') {
				return fail()
			}
			r.code = int(text[0]-'0')*100 + int(text[1]-'0')*10 + int(text[2]-'0')
			r.lines = append(r.lines, text)
			if text[3] == ' ' {
				return r, nil
			}
		} else {
			r.lines = append(r.lines, text)
			if strings.HasPrefix(text, fmt.Sprintf("%03d ", r.code)) {
				return r, nil
			}
		}
	}
	return fail()
}

func passivePort(r reply) (int, error) {
	text := r.lines[len(r.lines)-1]
	start := strings.LastIndex(text, "(")
	end := strings.Index(text[start+1:], ")")
	if start < 0 || end < 0 {
		return 0, ErrReply
	}
	value := text[start+1 : start+1+end]
	var port int
	if r.code == 229 {
		if len(value) < 5 || value[0] < 33 || value[0] > 126 || value[0] != value[1] || value[0] != value[2] || value[0] != value[len(value)-1] {
			return 0, ErrReply
		}
		var err error
		for _, digit := range value[3 : len(value)-1] {
			if digit < '0' || digit > '9' {
				return 0, ErrReply
			}
		}
		port, err = strconv.Atoi(value[3 : len(value)-1])
		if err != nil {
			return 0, ErrReply
		}
	} else if r.code == 227 {
		parts := strings.Split(value, ",")
		if len(parts) != 6 {
			return 0, ErrReply
		}
		numbers := make([]int, 6)
		for i, s := range parts {
			if s == "" {
				return 0, ErrReply
			}
			for _, c := range s {
				if c < '0' || c > '9' {
					return 0, ErrReply
				}
			}
			n, err := strconv.Atoi(s)
			if err != nil || n < 0 || n > 255 {
				return 0, ErrReply
			}
			numbers[i] = n
		}
		port = numbers[4]*256 + numbers[5]
	} else {
		return 0, ErrReply
	}
	if port < 1024 || port > 65535 {
		return 0, ErrReply
	}
	return port, nil
}
func (c *Client) openTransfer(verb, name string, offset int64) (*secure.FTPSClientData, error) {
	r, err := c.command("EPSV", "", 229)
	var status *ReplyError
	if errors.As(err, &status) && (status.Code == 500 || status.Code == 502 || status.Code == 522) {
		r, err = c.command("PASV", "", 227)
	}
	if err != nil {
		return nil, err
	}
	port, err := passivePort(r)
	if err != nil {
		c.Close()
		return nil, err
	}
	if err = c.check(); err != nil {
		return nil, err
	}
	d, err := c.transport.OpenData(port)
	if err != nil {
		c.Close()
		return nil, secure.ErrFTPSClient
	}
	fail := func(err error) (*secure.FTPSClientData, error) { d.Abort(); c.Close(); return nil, err }
	if offset > 0 {
		if _, err = c.command("REST", strconv.FormatInt(offset, 10), 350); err != nil {
			return fail(err)
		}
	}
	if _, err = c.command(verb, name, 125, 150); err != nil {
		return fail(err)
	}
	if err = d.Handshake(); err != nil {
		return fail(secure.ErrFTPSClient)
	}
	return d, nil
}

func (c *Client) Size(name string) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.size(name)
}

func (c *Client) size(name string) (int64, error) {
	if !validPath(name) {
		return 0, ErrInput
	}
	r, err := c.command("SIZE", name, 213)
	if err != nil {
		return 0, err
	}
	value := strings.TrimPrefix(r.lines[len(r.lines)-1], "213 ")
	if value == "" {
		return 0, ErrReply
	}
	for _, v := range value {
		if v < '0' || v > '9' {
			c.Close()
			return 0, ErrReply
		}
	}
	size, err := strconv.ParseInt(value, 10, 64)
	if err != nil || size < 0 || size > MaxFile {
		c.Close()
		return 0, ErrReply
	}
	return size, nil
}

// ReadBounded reads small, untrusted metadata whose digest is not known yet.
// It returns no bytes until the declared length, EOF, TLS shutdown, completion
// reply and live guard all pass. This is not a producer signature or a file
// acceptance decision. Callers must validate and durably bind the exact bytes.
// Payload reads keep using RetrieveToStage with a known immutable digest.
func (c *Client) ReadBounded(name string, maximum int64) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !validPath(name) || name == "/" || maximum < 1 || maximum > MaxMetadata {
		return nil, ErrInput
	}
	size, err := c.size(name)
	if err != nil {
		return nil, err
	}
	if size > maximum {
		return nil, ErrInput
	}
	d, err := c.openTransfer("RETR", name, 0)
	if err != nil {
		return nil, err
	}
	body := make([]byte, size)
	verified := false
	defer func() {
		if !verified {
			secure.Clear(body)
			d.Abort()
			c.Close()
		}
	}()
	if err = c.check(); err != nil {
		return nil, err
	}
	if _, err = io.ReadFull(d, body); err != nil {
		return nil, ErrIntegrity
	}
	var tail [1]byte
	if n, e := d.Read(tail[:]); n != 0 || e != io.EOF {
		return nil, ErrIntegrity
	}
	if err = c.check(); err != nil {
		return nil, err
	}
	if err = d.Close(); err != nil {
		return nil, ErrCompletionUnknown
	}
	r, err := c.readReply()
	if err != nil || r.code != 226 && r.code != 250 {
		return nil, ErrCompletionUnknown
	}
	if err = c.check(); err != nil {
		return nil, err
	}
	verified = true
	return body, nil
}

type StoreResult struct {
	BytesSent               int64
	CompletionReplyObserved bool
}

// StoreStage sends a source opened at offset zero, verifies its complete digest,
// and optionally restarts the remote stream at offset. It does not verify a
// retained remote prefix or publish a business file. Use private approved staging
// and independently retrieve/verify before any separately governed publication.
func (c *Client) StoreStage(name string, source io.Reader, size, offset int64, sha256 string) (out StoreResult, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !validPath(name) || source == nil || size < 0 || size > MaxFile || offset < 0 || offset > size || !validHash(sha256) {
		return out, ErrInput
	}
	hash := secure.NewDigest()
	buffer := make([]byte, 32<<10)
	defer secure.Clear(buffer)
	var consumed int64
	for consumed < offset {
		if err = c.check(); err != nil {
			return out, err
		}
		n, e := io.ReadFull(source, buffer[:min(int64(len(buffer)), offset-consumed)])
		if e != nil {
			return out, ErrIntegrity
		}
		hash.Write(buffer[:n])
		consumed += int64(n)
	}
	d, err := c.openTransfer("STOR", name, offset)
	if err != nil {
		return out, err
	}
	clean := false
	defer func() {
		if !clean {
			d.Abort()
			c.Close()
		}
	}()
	for consumed < size {
		if err = c.check(); err != nil {
			return out, err
		}
		n, e := io.ReadFull(source, buffer[:min(int64(len(buffer)), size-consumed)])
		if e != nil {
			return out, ErrIntegrity
		}
		hash.Write(buffer[:n])
		written := 0
		for written < n {
			if err = c.check(); err != nil {
				return out, err
			}
			count, e := d.Write(buffer[written:n])
			out.BytesSent += int64(count)
			written += count
			if e != nil || count <= 0 {
				return out, ErrConnection
			}
		}
		consumed += int64(n)
	}
	var tail [1]byte
	if n, e := source.Read(tail[:]); n != 0 || e != io.EOF {
		return out, ErrIntegrity
	}
	if fmt.Sprintf("%x", hash.Sum(nil)) != sha256 {
		return out, ErrIntegrity
	}
	if err = c.check(); err != nil {
		return out, err
	}
	if err = d.Close(); err != nil {
		return out, ErrCompletionUnknown
	}
	clean = true
	r, e := c.readReply()
	if e != nil || r.code != 226 && r.code != 250 {
		c.Close()
		return out, ErrCompletionUnknown
	}
	out.CompletionReplyObserved = true
	return out, nil
}

// RetrieveToStage verifies exact length, digest, EOF and final reply. The writer
// must be private staging (or io.Discard); it receives bytes before verification.
func (c *Client) RetrieveToStage(name string, target io.Writer, size int64, sha256 string) (err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !validPath(name) || target == nil || size < 0 || size > MaxFile || !validHash(sha256) {
		return ErrInput
	}
	d, err := c.openTransfer("RETR", name, 0)
	if err != nil {
		return err
	}
	clean := false
	defer func() {
		if !clean {
			d.Abort()
			c.Close()
		}
	}()
	hash := secure.NewDigest()
	buffer := make([]byte, 32<<10)
	defer secure.Clear(buffer)
	var consumed int64
	for consumed < size {
		if err = c.check(); err != nil {
			return err
		}
		n, e := io.ReadFull(d, buffer[:min(int64(len(buffer)), size-consumed)])
		if e != nil {
			return ErrIntegrity
		}
		hash.Write(buffer[:n])
		if err = c.check(); err != nil {
			return err
		}
		written, e := target.Write(buffer[:n])
		if e != nil || written != n {
			return ErrIntegrity
		}
		consumed += int64(n)
	}
	var tail [1]byte
	if n, e := d.Read(tail[:]); n != 0 || e != io.EOF {
		return ErrIntegrity
	}
	if fmt.Sprintf("%x", hash.Sum(nil)) != sha256 {
		return ErrIntegrity
	}
	if err = d.Close(); err != nil {
		return ErrCompletionUnknown
	}
	clean = true
	r, e := c.readReply()
	if e != nil || r.code != 226 && r.code != 250 {
		c.Close()
		return ErrCompletionUnknown
	}
	return nil
}

// Rename exposes only the wire operation. FTP does not promise atomic exclusive
// no-replace or fsync. The caller must commit publication intent and possess an
// explicit receiver contract before using it. No automatic retry is performed.
func (c *Client) Rename(from, to string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !validPath(from) || !validPath(to) || from == "/" || to == "/" {
		return ErrInput
	}
	if _, err := c.command("RNFR", from, 350); err != nil {
		return err
	}
	if _, err := c.command("RNTO", to, 250); err != nil {
		c.Close()
		return ErrPublicationUnknown
	}
	return nil
}
