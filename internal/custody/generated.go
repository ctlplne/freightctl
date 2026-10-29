package custody

import (
	"context"
	"encoding/hex"
	"io"
	"os"

	secure "github.com/ctlplne/freightctl/internal/crypto"
)

type generatedWriter struct {
	ctx            context.Context
	writer         io.Writer
	maximum, count int64
}

func (w *generatedWriter) Write(p []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	if int64(len(p)) > w.maximum-w.count {
		return 0, ErrCapacity
	}
	n, err := w.writer.Write(p)
	w.count += int64(n)
	return n, err
}

// StageGenerated seals a bounded internally generated artifact. Caller reserves
// quota under the same PostgreSQL custody lock used by ordinary acceptance.
// Failure before sealing removes only this new partial object. After success,
// retain the sealed object even if its later SQL acceptance is uncertain.
func (d *Disk) StageGenerated(ctx context.Context, name string, maximum int64, generate func(io.Writer) error) (int64, string, error) {
	if !validName(name) || maximum < 1 || maximum > (1<<30)+(16<<20) {
		return 0, "", ErrCapacity
	}
	if err := d.CheckIdentity(); err != nil {
		return 0, "", err
	}
	f, err := d.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return 0, "", err
	}
	sealed := false
	defer func() {
		_ = f.Close()
		if !sealed {
			_ = d.root.Remove(name)
			_ = d.sync()
		}
	}()
	h := secure.NewDigest()
	writer := &generatedWriter{ctx: ctx, writer: io.MultiWriter(f, h), maximum: maximum}
	if err = generate(writer); err != nil {
		return 0, "", err
	}
	if err = ctx.Err(); err != nil {
		return 0, "", err
	}
	if err = f.Chmod(0400); err == nil {
		err = f.Sync()
	}
	if err != nil {
		return 0, "", err
	}
	if err = f.Close(); err != nil {
		return 0, "", err
	}
	if err = d.sync(); err != nil {
		return 0, "", err
	}
	sealed = true
	return writer.count, hex.EncodeToString(h.Sum(nil)), nil
}
