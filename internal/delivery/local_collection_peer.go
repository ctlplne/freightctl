package delivery

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/protectedfs"
)

var ErrLocalSource = errors.New("local collection root,object or current authority differs")

// LocalCollectionPeer exposes only reads from one reviewed physical directory.
// It cannot publish,remove,rename or execute producer files. Admission and final
// custody acceptance remain ordinary workflow operations,not filesystem rights.
type LocalCollectionPeer struct {
	root      *os.Root
	directory string
	identity  string
	info      os.FileInfo
	closed    bool
}

func openLocalCollectionRoot(ctx context.Context, directory string, check func() error) (*LocalCollectionPeer, error) {
	if check == nil || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, ErrLocalSource
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := check(); err != nil {
		return nil, err
	}
	before, err := os.Lstat(directory)
	if err != nil || !before.IsDir() {
		return nil, errors.Join(ErrLocalSource, err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, err
	}
	dir, err := root.Open(".")
	if err != nil {
		root.Close()
		return nil, err
	}
	info, statErr := dir.Stat()
	identity, idErr := localCollectionRootIdentity(dir)
	err = errors.Join(statErr, idErr, protectedfs.ValidateDirectory(dir), dir.Close())
	if err != nil || !os.SameFile(before, info) {
		root.Close()
		return nil, errors.Join(ErrLocalSource, err)
	}
	p := &LocalCollectionPeer{root: root, directory: directory, identity: identity, info: info}
	if err = p.current(ctx, check); err != nil {
		p.Close()
		return nil, err
	}
	return p, nil
}

// InspectLocalCollectionRoot is metadata only. The operator must explicitly
// bind its returned physical fingerprint to an approved connection revision.
func InspectLocalCollectionRoot(ctx context.Context, directory string, check func() error) (string, error) {
	p, err := openLocalCollectionRoot(ctx, directory, check)
	if err != nil {
		return "", err
	}
	identity := p.identity
	if err = p.Close(); err != nil {
		return "", err
	}
	return identity, nil
}

func OpenLocalCollectionPeer(ctx context.Context, directory, identity string, check func() error) (*LocalCollectionPeer, error) {
	if !localCollectionDigest(identity) {
		return nil, ErrLocalSource
	}
	p, err := openLocalCollectionRoot(ctx, directory, check)
	if err != nil {
		return nil, err
	}
	if p.identity != identity {
		p.Close()
		return nil, ErrLocalSource
	}
	return p, nil
}

func (p *LocalCollectionPeer) Close() error {
	if p == nil || p.closed {
		return os.ErrClosed
	}
	p.closed = true
	return p.root.Close()
}

func (p *LocalCollectionPeer) current(ctx context.Context, check func() error) error {
	if p == nil || p.closed {
		return os.ErrClosed
	}
	if check == nil {
		return ErrLocalSource
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := check(); err != nil {
		return err
	}
	current, err := os.Lstat(p.directory)
	if err != nil || !current.IsDir() || !os.SameFile(p.info, current) {
		return errors.Join(ErrLocalSource, err)
	}
	dir, err := p.root.Open(".")
	if err != nil {
		return err
	}
	identity, idErr := localCollectionRootIdentity(dir)
	err = errors.Join(idErr, protectedfs.ValidateDirectory(dir), dir.Close())
	if err != nil || identity != p.identity {
		return errors.Join(ErrLocalSource, err)
	}
	return nil
}

func localCollectionDigest(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func localCollectionName(name string) bool {
	if !collectionName.MatchString(name) || strings.HasSuffix(name, ".") {
		return false
	}
	base := strings.ToUpper(strings.SplitN(name, ".", 2)[0])
	return base != "CON" && base != "PRN" && base != "AUX" && base != "NUL" && !(len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '1' && base[3] <= '9')
}

func (p *LocalCollectionPeer) open(ctx context.Context, name string, size int64, check func() error) (*os.File, error) {
	if !localCollectionName(name) || size < 0 || size > 1<<30 {
		return nil, ErrLocalSource
	}
	if err := p.current(ctx, check); err != nil {
		return nil, err
	}
	before, err := p.root.Lstat(name)
	if err != nil || !before.Mode().IsRegular() || before.Size() != size {
		return nil, errors.Join(ErrLocalSource, err)
	}
	f, err := p.root.Open(name)
	if err != nil {
		return nil, err
	}
	actual, statErr := f.Stat()
	err = errors.Join(statErr, protectedfs.ValidateFile(f))
	if err != nil || !os.SameFile(before, actual) || actual.Size() != size {
		f.Close()
		return nil, errors.Join(ErrLocalSource, err)
	}
	return f, nil
}

func (p *LocalCollectionPeer) fileCurrent(f *os.File, name string, size int64) error {
	before, err := p.root.Lstat(name)
	if err != nil || !before.Mode().IsRegular() || before.Size() != size {
		return errors.Join(ErrLocalSource, err)
	}
	actual, err := f.Stat()
	if err != nil || !os.SameFile(before, actual) || actual.Size() != size {
		return errors.Join(ErrLocalSource, err)
	}
	if err = protectedfs.ValidateFile(f); err != nil {
		return errors.Join(ErrLocalSource, err)
	}
	return nil
}

func (p *LocalCollectionPeer) ReadManifest(ctx context.Context, name string, check func() error) ([]byte, error) {
	if !localCollectionName(name) {
		return nil, ErrLocalSource
	}
	if err := p.current(ctx, check); err != nil {
		return nil, err
	}
	info, err := p.root.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 32<<10 {
		return nil, errors.Join(ErrLocalSource, err)
	}
	f, err := p.open(ctx, name, info.Size(), check)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (32<<10)+1))
	if err != nil || len(data) != int(info.Size()) || len(data) > 32<<10 {
		return nil, errors.Join(ErrLocalSource, err)
	}
	if err = p.current(ctx, check); err != nil {
		return nil, err
	}
	if err = p.fileCurrent(f, name, info.Size()); err != nil {
		return nil, err
	}
	return data, nil
}

// Output must be unpublished private staging. Like the other collection peers,
// this can leave partial staged bytes on error;only ordinary verified custody
// acceptance can make them available to any recipient.
func (p *LocalCollectionPeer) CopyVerified(ctx context.Context, name string, size int64, digest string, output io.Writer, check func() error) error {
	if output == nil || !localCollectionDigest(digest) {
		return ErrLocalSource
	}
	f, err := p.open(ctx, name, size, check)
	if err != nil {
		return err
	}
	defer f.Close()
	hash := secure.NewDigest()
	buffer := make([]byte, 32<<10)
	defer secure.Clear(buffer)
	var count int64
	for count < size {
		if err = p.current(ctx, check); err != nil {
			return err
		}
		if err = p.fileCurrent(f, name, size); err != nil {
			return err
		}
		n, readErr := io.ReadFull(f, buffer[:min(int64(len(buffer)), size-count)])
		if readErr != nil {
			return errors.Join(ErrLocalSource, readErr)
		}
		if err = p.current(ctx, check); err != nil {
			return err
		}
		if err = p.fileCurrent(f, name, size); err != nil {
			return err
		}
		written, writeErr := output.Write(buffer[:n])
		if writeErr != nil {
			return writeErr
		}
		if written != n {
			return io.ErrShortWrite
		}
		hash.Write(buffer[:n])
		count += int64(n)
	}
	var tail [1]byte
	n, end := f.Read(tail[:])
	if n != 0 || end != io.EOF || hex.EncodeToString(hash.Sum(nil)) != digest {
		return ErrLocalSource
	}
	if err = p.fileCurrent(f, name, size); err != nil {
		return err
	}
	return p.current(ctx, check)
}
