package sftpd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"strconv"
	"strings"
	"unicode/utf8"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/vpath"
)

var errSCP = errors.New("legacy SCP request exceeds the supported file profile")

type scpCommand struct {
	Receive, Directory bool
	Path               string
}

// Parse literal shell-style quoting without evaluating a shell language.
// Unquoted substitutions,operators,globs and home expansion are refused.
func scpWords(raw string) ([]string, error) {
	if len(raw) == 0 || len(raw) > 2048 || !utf8.ValidString(raw) || strings.ContainsAny(raw, "\x00\r\n\t") {
		return nil, errSCP
	}
	var words []string
	var word strings.Builder
	var quote byte
	active := false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if quote == '\'' {
			if c == '\'' {
				quote = 0
			} else {
				word.WriteByte(c)
			}
			continue
		}
		if c == '\\' {
			if i+1 == len(raw) {
				return nil, errSCP
			}
			i++
			if quote == '"' && !strings.ContainsRune("\\\"$`", rune(raw[i])) {
				word.WriteByte('\\')
			}
			word.WriteByte(raw[i])
			active = true
			continue
		}
		if quote == '"' {
			if c == '"' {
				quote = 0
			} else if c == '$' || c == '`' {
				return nil, errSCP
			} else {
				word.WriteByte(c)
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote, active = c, true
		case ' ':
			if active {
				words = append(words, word.String())
				word.Reset()
				active = false
			}
		default:
			if c < 32 || c == 127 || strings.ContainsRune("$`;|&<>(){}*?[]~", rune(c)) {
				return nil, errSCP
			}
			word.WriteByte(c)
			active = true
		}
		if len(words) > 8 {
			return nil, errSCP
		}
	}
	if quote != 0 {
		return nil, errSCP
	}
	if active {
		words = append(words, word.String())
	}
	return words, nil
}

func parseSCPCommand(raw string) (scpCommand, error) {
	var command scpCommand
	words, err := scpWords(raw)
	if err != nil || len(words) < 3 || len(words) > 8 || words[0] != "scp" {
		return command, errSCP
	}
	var role byte
	seen := map[byte]bool{}
	terminated := false
	i := 1
	for ; i < len(words)-1; i++ {
		flag := words[i]
		if flag == "--" {
			terminated = true
			i++
			break
		}
		if len(flag) < 2 || flag[0] != '-' {
			return command, errSCP
		}
		for j := 1; j < len(flag); j++ {
			c := flag[j]
			if seen[c] || !strings.ContainsRune("tfvd", rune(c)) {
				return command, errSCP
			}
			seen[c] = true
			if c == 't' || c == 'f' {
				if role != 0 {
					return command, errSCP
				}
				role = c
			}
		}
	}
	if i != len(words)-1 || role == 0 || role == 'f' && seen['d'] {
		return command, errSCP
	}
	p := words[i]
	if strings.HasPrefix(p, "-") && !terminated {
		return command, errSCP
	}
	if p == "." {
		p = "/"
	} else if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if len(p) > 1 {
		p = strings.TrimSuffix(p, "/")
	}
	canonical, err := vpath.Canonical(p)
	if err != nil || canonical != p || vpath.ControlPath(p) || p == "/" && role == 'f' {
		return command, errSCP
	}
	return scpCommand{Receive: role == 't', Directory: seen['d'], Path: p}, nil
}

func scpLine(reader *bufio.Reader) ([]byte, error) {
	line, err := reader.ReadSlice('\n')
	if err != nil || len(line) < 2 || len(line) > 2048 {
		return nil, errSCP
	}
	return line[:len(line)-1], nil
}

func scpHeader(line []byte, maximum int64) (uint32, int64, string, error) {
	if len(line) < 9 || line[0] != 'C' || line[5] != ' ' {
		return 0, 0, "", errSCP
	}
	for _, c := range line[1:5] {
		if c < '0' || c > '7' {
			return 0, 0, "", errSCP
		}
	}
	mode, _ := strconv.ParseUint(string(line[1:5]), 8, 16)
	if mode > 0777 {
		return 0, 0, "", errSCP
	}
	rest := string(line[6:])
	length, name, found := strings.Cut(rest, " ")
	if !found || len(length) < 1 || len(length) > 19 {
		return 0, 0, "", errSCP
	}
	for _, c := range length {
		if c < '0' || c > '9' {
			return 0, 0, "", errSCP
		}
	}
	size, err := strconv.ParseInt(length, 10, 64)
	canonical, pathErr := vpath.Canonical("/" + name)
	if err != nil || size > maximum || pathErr != nil || canonical != "/"+name || path.Base(canonical) != name || vpath.ControlPath(canonical) {
		return 0, 0, "", errSCP
	}
	return uint32(mode), size, name, nil
}

func scpAck(reader *bufio.Reader) error {
	code, err := reader.ReadByte()
	if err != nil {
		return err
	}
	if code == 0 {
		return nil
	}
	if code == 1 || code == 2 {
		_, _ = scpLine(reader)
	}
	return errSCP
}

func (s *Service) LegacySCP(raw string) (secure.SSHSubsystem, error) {
	command, err := parseSCPCommand(raw)
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context, principal secure.SSHPrincipal, stream io.ReadWriteCloser) error {
		scope := store.Scope{Tenant: principal.Tenant, Partner: principal.Partner, Actor: principal.Actor, SSHKeyFingerprint: principal.Fingerprint, AuthorityRevision: principal.AuthorityRevision, SessionID: secure.NewID()}
		transaction, err := s.Custody.DB.Begin(ctx, scope)
		if err != nil {
			return err
		}
		defer transaction.Tx.Rollback(ctx)
		permission := "read"
		if command.Receive {
			permission = "write"
		}
		if err = transaction.Require(permission); err == nil {
			_, err = transaction.Append(ctx, "ProtocolSessionStarted", scope.SessionID, map[string]any{"protocol": "scp-legacy-file-v1", "fingerprint": principal.Fingerprint, "authority_revision": principal.AuthorityRevision, "receiving": command.Receive})
		}
		if err == nil {
			err = transaction.Tx.Commit(ctx)
		}
		if err == nil {
			if command.Receive {
				err = s.scpReceive(ctx, scope, command, stream)
			} else {
				err = s.scpSend(ctx, scope, command, stream)
			}
		}
		if err != nil {
			// Never echo an untrusted name,credential,storage path or raw error.
			_, _ = io.WriteString(stream, "\x02artifact transfer failed\n")
			// EOF is a normal SFTP subsystem shutdown,not a successful SCP
			// transfer. Never let that transport convention hide a failed file.
			return errSCP
		}
		return nil
	}, nil
}

func (s *Service) scpReceive(ctx context.Context, scope store.Scope, command scpCommand, stream io.ReadWriteCloser) error {
	entry, err := s.Custody.StatPath(ctx, scope, command.Path)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	directory := entry != nil && entry.Kind == "dir"
	if command.Directory && !directory || entry != nil && entry.Kind != "file" && !directory || s.Custody.NamespaceMaxEntries < 1 {
		return errSCP
	}
	if _, err = stream.Write([]byte{0}); err != nil {
		return err
	}
	reader := bufio.NewReaderSize(stream, 4096)
	buffer := make([]byte, 32<<10)
	defer clear(buffer)
	for files := 0; files < s.Custody.NamespaceMaxEntries; files++ {
		_, err := reader.Peek(1)
		if err == io.EOF && files > 0 {
			return nil
		}
		if err != nil || !directory && files > 0 {
			return errSCP
		}
		line, err := scpLine(reader)
		if err != nil {
			return err
		}
		mode, size, name, err := scpHeader(line, s.Custody.MaxFile)
		if err != nil {
			return err
		}
		target := command.Path
		if directory {
			target = path.Join(target, name)
		}
		select {
		case s.writers <- struct{}{}:
		default:
			return errSCP
		}
		err = func() (failure error) {
			defer func() { <-s.writers }()
			writer, err := s.Custody.OpenRevisionWriter(ctx, scope, target, custody.WriteOptions{Create: true, Truncate: true, Mode: &mode})
			if err != nil {
				return err
			}
			defer func() {
				if failure != nil {
					writer.TransferError(failure)
				}
				closeErr := writer.Close()
				if failure == nil {
					failure = closeErr
				}
			}()
			if _, err = stream.Write([]byte{0}); err != nil {
				return err
			}
			for offset := int64(0); offset < size; {
				chunk := buffer[:int(min(int64(len(buffer)), size-offset))]
				if _, err = io.ReadFull(reader, chunk); err != nil {
					return err
				}
				n, err := writer.WriteAt(chunk, offset)
				if err != nil || n != len(chunk) {
					return errors.Join(errSCP, err)
				}
				offset += int64(n)
			}
			return scpAck(reader)
		}()
		if err != nil {
			return err
		}
		// This is the durability acknowledgement;Close above has committed.
		if _, err = stream.Write([]byte{0}); err != nil {
			return err
		}
	}
	if _, err = reader.Peek(1); err == io.EOF {
		return nil
	}
	return errSCP
}

func (s *Service) scpSend(ctx context.Context, scope store.Scope, command scpCommand, stream io.ReadWriteCloser) error {
	entry, err := s.Custody.StatPath(ctx, scope, command.Path)
	if err != nil || entry.Kind != "file" {
		return errors.Join(errSCP, err)
	}
	file, reader, err := s.Custody.OpenPathReader(ctx, scope, command.Path)
	if err != nil {
		return err
	}
	defer reader.Close()
	if file.ID != entry.FileID || file.Size != entry.Size {
		return store.ErrRevision
	}
	peer := bufio.NewReaderSize(stream, 4096)
	if err = scpAck(peer); err != nil {
		return err
	}
	name := path.Base(command.Path)
	if _, _, _, err = scpHeader([]byte(fmt.Sprintf("C%04o %d %s", entry.Mode, file.Size, name)), s.Custody.MaxFile); err != nil {
		return err
	}
	if _, err = fmt.Fprintf(stream, "C%04o %d %s\n", entry.Mode, file.Size, name); err != nil {
		return err
	}
	if err = scpAck(peer); err != nil {
		return err
	}
	buffer := make([]byte, 32<<10)
	defer clear(buffer)
	for offset := int64(0); offset < file.Size; {
		chunk := buffer[:int(min(int64(len(buffer)), file.Size-offset))]
		n, readErr := reader.ReadAt(chunk, offset)
		if n != len(chunk) || readErr != nil && readErr != io.EOF {
			return errors.Join(errSCP, readErr)
		}
		if n, err = stream.Write(chunk); err != nil || n != len(chunk) {
			return errors.Join(errSCP, err)
		}
		offset += int64(n)
	}
	if _, err = reader.ReadAt(nil, file.Size); err != nil && err != io.EOF {
		return err
	}
	if _, err = stream.Write([]byte{0}); err != nil {
		return err
	}
	return scpAck(peer)
}
