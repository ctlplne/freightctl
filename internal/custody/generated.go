package custody

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"os"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/protectedfs"
)

// GeneratedSlotState observes only an intent-owned flat object name. Partial
// objects from process death are retained; retries use another approved slot.
func (d *Disk) GeneratedSlotState(ctx context.Context, name string) (string, error) {
	if !validName(name) {
		return "", ErrInput
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := d.CheckIdentity(); err != nil {
		return "", err
	}
	file, err := d.openObject(name)
	if errors.Is(err, os.ErrNotExist) {
		return "absent", nil
	}
	if err != nil {
		return "", err
	}
	defer file.Close()
	state, err := protectedfs.Protection(file)
	if err != nil {
		return "", ErrIntegrity
	}
	switch state {
	case protectedfs.PrivateWritable:
		return "partial", nil
	case protectedfs.PrivateSealed:
		complete, err := checkSealPersistence(file, d.identity, name, -1, "")
		if err != nil {
			return "", err
		}
		if !complete {
			return "partial", nil
		}
		return "sealed", nil
	}
	return "", ErrIntegrity
}

// VerifyGenerated re-establishes exact bytes and persistence after uncertainty.
// This never modifies or deletes an existing private object.
func (d *Disk) VerifyGenerated(ctx context.Context, name string, size int64, hash string) error {
	if !validName(name) {
		return ErrInput
	}
	exists, partial, err := d.recheckObject(ctx, name, size, hash)
	if err != nil {
		return err
	}
	if !exists || partial {
		return ErrIntegrity
	}
	return nil
}

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
	f, err := protectedfs.CreateAt(d.root, name)
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
	if err = d.sealObject(f, name, writer.count, hex.EncodeToString(h.Sum(nil))); err != nil {
		return 0, "", err
	}
	sealed = true
	return writer.count, hex.EncodeToString(h.Sum(nil)), nil
}
