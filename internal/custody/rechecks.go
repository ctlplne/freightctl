package custody

import (
	"context"
	"errors"
	"io"
	"os"

	"github.com/ctlplne/freightctl/internal/protectedfs"
	"github.com/ctlplne/freightctl/internal/store"
)

type recheckReader struct {
	ctx    context.Context
	source io.Reader
	check  func() error
}

func (r recheckReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if err := r.check(); err != nil {
		return 0, err
	}
	return r.source.Read(p[:min(len(p), 32<<10)])
}

// recheckObject distinguishes untouched, incomplete, and verified immutable
// intent-owned objects. Incomplete objects stay in place; they are never erased
// to obtain a pass. Three pre-approved slot pairs bound interrupted staging.
func (d *Disk) recheckObject(ctx context.Context, name string, size int64, digest string) (exists, partial bool, err error) {
	observed, err := d.openObject(name)
	if errors.Is(err, os.ErrNotExist) {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	state, inspectErr := protectedfs.Protection(observed)
	closeErr := observed.Close()
	if inspectErr != nil || closeErr != nil {
		return false, false, errors.Join(ErrIntegrity, inspectErr, closeErr)
	}
	if state == protectedfs.PrivateWritable {
		return true, true, nil
	}
	if state != protectedfs.PrivateSealed {
		return false, false, ErrIntegrity
	}
	file, err := d.VerifiedContext(ctx, name, size, digest)
	if err != nil {
		return false, false, err
	}
	defer file.Close()
	// Verification after an uncertain commit must establish persistence now,
	// including a process death after sealing but before the original sync.
	if err = file.Sync(); err != nil {
		return false, false, err
	}
	if err = d.sync(); err != nil {
		return false, false, err
	}
	return true, false, nil
}

// MaterializeRecheck runs inside the caller's current authority, approved-intent,
// namespace and quota transaction. It neither commits nor publishes a file.
func (s *Service) MaterializeRecheck(ctx context.Context, t *store.Transaction, r *store.FileRecheck, source store.File, slots []store.RecheckSlot, target *store.PathCommand, reuse *store.FileSignature, admission func() error) (*store.File, *store.FileSignature, error) {
	if s.Disk == nil || admission == nil || source.Size < 0 || s.MaxFile < 1 || source.Size > s.MaxFile || s.MaxStored < 1 || len(slots) != 3 || r.State != "approved" || r.SourceID != source.ID {
		return nil, nil, ErrInput
	}
	for _, g := range []string{"admin", "read", "write", "intake_manage", "check_run", "check_release"} {
		if err := t.Require(g); err != nil {
			return nil, nil, err
		}
	}
	guard := func() error {
		if err := s.Disk.CheckIdentity(); err != nil {
			return err
		}
		if err := admission(); err != nil {
			return err
		}
		return t.Reauthorize(ctx)
	}
	if err := guard(); err != nil {
		return nil, nil, err
	}
	original, err := s.Disk.VerifiedContext(ctx, Name(t.Scope.Tenant, t.Scope.Partner, source.ID), source.Size, source.SHA256)
	if err != nil {
		return nil, nil, err
	}
	defer original.Close()
	var signature *os.File
	if reuse != nil {
		if reuse.FileID != source.ID || reuse.StorageID != s.Disk.Identity() || reuse.DataSHA256 != source.SHA256 {
			return nil, nil, ErrIntegrity
		}
		signature, err = s.Disk.VerifiedContext(ctx, Name(t.Scope.Tenant, t.Scope.Partner, reuse.ObjectID), reuse.Size, reuse.SHA256)
		if err != nil {
			return nil, nil, err
		}
		defer signature.Close()
	}
	for _, slot := range slots {
		if !store.ValidID(slot.FileID) || slot.FileID == source.ID || ((reuse != nil) != store.ValidID(slot.SignatureID)) {
			return nil, nil, ErrInput
		}
		if _, err = t.File(ctx, slot.FileID); err == nil {
			return nil, nil, store.ErrState
		} else if !errors.Is(err, store.ErrNotFound) {
			return nil, nil, err
		}
		name := Name(t.Scope.Tenant, t.Scope.Partner, slot.FileID)
		exists, partial, e := s.Disk.recheckObject(ctx, name, source.Size, source.SHA256)
		if e != nil {
			return nil, nil, e
		}
		if partial {
			continue
		}
		sigExists := false
		if reuse != nil {
			var p bool
			sigExists, p, e = s.Disk.recheckObject(ctx, Name(t.Scope.Tenant, t.Scope.Partner, slot.SignatureID), reuse.Size, reuse.SHA256)
			if e != nil {
				return nil, nil, e
			}
			if p {
				continue
			}
			if sigExists && !exists {
				return nil, nil, ErrIntegrity
			}
		}
		additional := int64(0)
		if !exists {
			additional += source.Size
		}
		if reuse != nil && !sigExists {
			additional += reuse.Size
		}
		if err = s.Disk.Capacity(additional, s.MaxStored); err != nil {
			return nil, nil, err
		}
		file := &store.File{ID: slot.FileID, Size: source.Size, SHA256: source.SHA256}
		if err = t.ConfigureIntakeFile(ctx, file); err != nil {
			return nil, nil, err
		}
		if !exists {
			if _, err = original.Seek(0, io.SeekStart); err != nil {
				return nil, nil, err
			}
			if err = s.Disk.stage(name, recheckReader{ctx, original, guard}, file.Size, file.SHA256, true); err != nil {
				return nil, nil, err
			}
		}
		if reuse != nil && !sigExists {
			if _, err = signature.Seek(0, io.SeekStart); err != nil {
				return nil, nil, err
			}
			if err = s.Disk.stage(Name(t.Scope.Tenant, t.Scope.Partner, slot.SignatureID), recheckReader{ctx, signature, guard}, reuse.Size, reuse.SHA256, true); err != nil {
				return nil, nil, err
			}
		}
		if err = t.AcceptRecheckedFile(ctx, r, file, s.Disk.Identity()); err != nil {
			return nil, nil, err
		}
		var binding *store.PathCommand
		if target != nil {
			copy := *target
			copy.FileID = file.ID
			binding = &copy
		}
		held, err := t.BindIntake(ctx, file, s.Disk.Identity(), binding)
		if err != nil {
			return nil, nil, err
		}
		if !held {
			return nil, nil, store.ErrState
		}
		var attached *store.FileSignature
		if reuse != nil {
			policyHash, controlled := store.IntakePolicyHash(file.Policy)
			if !controlled {
				return nil, nil, store.ErrState
			}
			attached = &store.FileSignature{FileID: file.ID, ObjectID: slot.SignatureID, StorageID: s.Disk.Identity(), Size: reuse.Size, SHA256: reuse.SHA256, DataSHA256: file.SHA256, PolicyHash: policyHash, Key: reuse.Key}
			if err = t.SaveFileSignature(ctx, attached); err != nil {
				return nil, nil, err
			}
		}
		return file, attached, guard()
	}
	return nil, nil, store.ErrLimit
}
