package delivery

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path"
	"regexp"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/vpath"
	"github.com/pkg/sftp"
)

var collectionName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// CollectionPeer exposes only reads. It shares the existing pinned SSH and
// bounded SFTP decoder; a collector cannot obtain the client's mutation API.
type CollectionPeer struct {
	client    *sftp.Client
	stream    io.Closer
	directory string
}

func OpenCollectionPeer(ctx context.Context, destination secure.SSHDestination, directory string, check func() error) (*CollectionPeer, error) {
	if check == nil {
		return nil, errors.New("collection authority check required")
	}
	canonical, err := vpath.Canonical(directory)
	if err != nil || canonical != directory || vpath.ControlPath(directory) {
		return nil, errors.New("invalid collection directory")
	}
	if e := check(); e != nil {
		return nil, e
	}
	c, stream, e := connect(ctx, &Definition{Destination: destination})
	if e != nil {
		return nil, e
	}
	p := &CollectionPeer{client: c, stream: stream, directory: directory}
	if e = remoteDirectory(c, directory); e == nil {
		e = check()
	}
	if e != nil {
		p.Close()
		return nil, e
	}
	return p, nil
}
func (p *CollectionPeer) Close() error {
	// Closing the raw transport first also releases a blocked SFTP request.
	e := p.stream.Close()
	_ = p.client.Close()
	return e
}
func (p *CollectionPeer) open(name string, size int64) (*sftp.File, error) {
	if !collectionName.MatchString(name) || size < 0 {
		return nil, errors.New("invalid collection object")
	}
	full := path.Join(p.directory, name)
	st, e := p.client.Lstat(full)
	if e != nil {
		return nil, e
	}
	if !st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0 || st.Size() != size {
		return nil, errors.New("collection object differs")
	}
	f, e := p.client.Open(full)
	if e != nil {
		return nil, e
	}
	st, e = f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Size() != size {
		f.Close()
		return nil, errors.New("collection descriptor differs")
	}
	return f, nil
}
func (p *CollectionPeer) ReadManifest(ctx context.Context, name string, check func() error) ([]byte, error) {
	if check == nil || !collectionName.MatchString(name) {
		return nil, errors.New("invalid manifest name")
	}
	if e := check(); e != nil {
		return nil, e
	}
	st, e := p.client.Lstat(path.Join(p.directory, name))
	if e != nil {
		return nil, e
	}
	if !st.Mode().IsRegular() || st.Size() < 1 || st.Size() > 32<<10 {
		return nil, errors.New("manifest exceeds bound or is not regular")
	}
	f, e := p.open(name, st.Size())
	if e != nil {
		return nil, e
	}
	defer f.Close()
	data := make([]byte, st.Size())
	if _, e = io.ReadFull(f, data); e != nil {
		return nil, e
	}
	var tail [1]byte
	if n, e := f.Read(tail[:]); n != 0 || e != io.EOF {
		return nil, errors.New("manifest changed while reading")
	}
	if e = ctx.Err(); e != nil {
		return nil, e
	}
	if e = check(); e != nil {
		return nil, e
	}
	if e = f.Close(); e != nil {
		return nil, e
	}
	return data, nil
}
func (p *CollectionPeer) CopyVerified(ctx context.Context, name string, size int64, digest string, output io.Writer, check func() error) error {
	if check == nil || output == nil || len(digest) != 64 {
		return errors.New("invalid collection verification")
	}
	if _, e := hex.DecodeString(digest); e != nil {
		return e
	}
	if e := check(); e != nil {
		return e
	}
	f, e := p.open(name, size)
	if e != nil {
		return e
	}
	defer f.Close()
	h := secure.NewDigest()
	buffer := make([]byte, 32<<10)
	var copied int64
	for copied < size {
		if e = ctx.Err(); e != nil {
			return e
		}
		if e = check(); e != nil {
			return e
		}
		n, e := io.ReadFull(f, buffer[:min(int64(len(buffer)), size-copied)])
		if e != nil {
			return e
		}
		h.Write(buffer[:n])
		written, e := output.Write(buffer[:n])
		if e != nil {
			return e
		}
		if written != n {
			return io.ErrShortWrite
		}
		copied += int64(n)
	}
	var tail [1]byte
	if n, e := f.Read(tail[:]); n != 0 || e != io.EOF {
		return errors.New("collection source grew")
	}
	if hex.EncodeToString(h.Sum(nil)) != digest {
		return errors.New("collection source digest differs from ready manifest")
	}
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Size() != size {
		return errors.New("collection source changed")
	}
	if e = check(); e != nil {
		return e
	}
	return f.Close()
}
