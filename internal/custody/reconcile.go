package custody

import (
	"context"
	"errors"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

type ReconciliationEntry struct {
	Reference string `json:"reference"`
	State     string `json:"state"`
	Size      int64  `json:"size_bytes"`
}
type Reconciliation struct {
	Consistent        bool                  `json:"consistent"`
	Counts            map[string]int        `json:"counts"`
	Entries           []ReconciliationEntry `json:"entries"`
	Truncated         bool                  `json:"truncated"`
	VerifiedBytes     int64                 `json:"verified_bytes"`
	HashedBytes       int64                 `json:"hashed_bytes"`
	VerificationLimit int64                 `json:"verification_limit_bytes"`
	Mutations         string                `json:"mutations"`
}
type diskEntry struct {
	name, reference string
	size            int64
	safe            bool
}

func (d *Disk) inventory(tenant, partner string) ([]diskEntry, error) {
	if !store.ValidID(tenant) || !store.ValidID(partner) {
		return nil, store.ErrUnauthorized
	}
	f, err := d.root.Open(".")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	prefix := tenant + "_" + partner + "_"
	result := make([]diskEntry, 0)
	total := 0
	for {
		entries, err := f.ReadDir(128)
		if err != nil && err != io.EOF {
			return nil, err
		}
		for _, entry := range entries {
			total++
			if total > 10000 {
				return nil, ErrCapacity
			}
			if !strings.HasPrefix(entry.Name(), prefix) {
				continue
			}
			ref := secure.Digest([]byte(entry.Name()))
			if !validName(entry.Name()) {
				result = append(result, diskEntry{reference: ref})
				continue
			}
			info, err := entry.Info()
			if err != nil {
				return nil, err
			}
			result = append(result, diskEntry{name: entry.Name(), reference: strings.TrimPrefix(entry.Name(), prefix), size: info.Size(), safe: info.Mode().IsRegular()})
		}
		if err == io.EOF {
			return result, nil
		}
	}
}

// Reconcile observes one scope while the same database lock excludes staging.
// It never deletes, adopts or publishes bytes, including objects without metadata.
func (s *Service) Reconcile(ctx context.Context, scope store.Scope) (*Reconciliation, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.DB.Begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if err = t.Require("inspect"); err != nil {
		return nil, err
	}
	if t.Root != "/" {
		return nil, store.ErrForbidden
	}
	if _, err = t.Tx.Exec(ctx, `SELECT pg_advisory_xact_lock(721815034)`); err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	if err = s.Disk.CheckIdentity(); err != nil {
		return nil, err
	}
	rows, err := t.Tx.Query(ctx, `SELECT file_id::text,size_bytes,sha256,'file' FROM files UNION ALL SELECT object_id::text,size_bytes,sha256,'checkpoint' FROM upload_chunks UNION ALL SELECT object_id::text,size_bytes,sha256,'signature' FROM file_signatures UNION ALL SELECT object_id::text,size_bytes,sha256,'ciphertext' FROM delivery_ciphertexts ORDER BY 1 LIMIT 10001`)
	if err != nil {
		return nil, err
	}
	files := make(map[string]store.File)
	classes := make(map[string]string)
	for rows.Next() {
		var f store.File
		var class string
		if err = rows.Scan(&f.ID, &f.Size, &f.SHA256, &class); err != nil {
			rows.Close()
			return nil, err
		}
		if _, duplicate := files[f.ID]; duplicate {
			rows.Close()
			return nil, store.ErrState
		}
		files[f.ID] = f
		classes[f.ID] = class
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if len(files) > 10000 {
		return nil, ErrCapacity
	}
	objects, err := s.Disk.inventory(scope.Tenant, scope.Partner)
	if err != nil {
		return nil, err
	}
	limit := s.ReconcileMaxBytes
	if limit == 0 {
		limit = 64 << 20
	}
	if limit > s.MaxStored {
		limit = s.MaxStored
	}
	if limit < 1 {
		return nil, ErrInput
	}
	report := &Reconciliation{Consistent: true, Counts: make(map[string]int), Entries: make([]ReconciliationEntry, 0), VerificationLimit: limit, Mutations: "none; observation only"}
	add := func(reference, state string, size int64) {
		report.Counts[state]++
		if state != "verified" && state != "verified_checkpoint" && state != "verified_signature" && state != "verified_ciphertext" {
			report.Consistent = false
		}
		if len(report.Entries) < 200 {
			report.Entries = append(report.Entries, ReconciliationEntry{Reference: reference, State: state, Size: size})
		} else {
			report.Truncated = true
		}
	}
	sort.Slice(objects, func(i, j int) bool { return objects[i].reference < objects[j].reference })
	for _, object := range objects {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		f, known := files[object.reference]
		verified, corrupt, missingState := "verified", "integrity_mismatch", "missing_bytes"
		if classes[object.reference] == "checkpoint" {
			verified, corrupt, missingState = "verified_checkpoint", "checkpoint_integrity_mismatch", "missing_checkpoint_bytes"
		}
		if classes[object.reference] == "signature" {
			verified, corrupt, missingState = "verified_signature", "signature_integrity_mismatch", "missing_signature_bytes"
		}
		if classes[object.reference] == "ciphertext" {
			verified, corrupt, missingState = "verified_ciphertext", "ciphertext_integrity_mismatch", "missing_ciphertext_bytes"
		}
		delete(files, object.reference)
		if !object.safe {
			add(object.reference, "unsafe_entry", object.size)
			continue
		}
		if !known {
			add(object.reference, "unreferenced_bytes", object.size)
			continue
		}
		if object.size != f.Size {
			add(object.reference, corrupt, object.size)
			continue
		}
		if f.Size > limit-report.HashedBytes {
			add(f.ID, "not_checked_budget", f.Size)
			continue
		}
		report.HashedBytes += f.Size
		stream, verifyErr := s.Disk.VerifiedContext(ctx, object.name, f.Size, f.SHA256)
		if verifyErr == nil {
			stream.Close()
			report.VerifiedBytes += f.Size
			add(f.ID, verified, f.Size)
		} else if errors.Is(verifyErr, ErrIntegrity) {
			add(f.ID, corrupt, f.Size)
		} else if os.IsNotExist(verifyErr) {
			add(f.ID, missingState, f.Size)
		} else {
			return nil, verifyErr
		}
	}
	missing := make([]string, 0, len(files))
	for id := range files {
		missing = append(missing, id)
	}
	sort.Strings(missing)
	for _, id := range missing {
		state := "missing_bytes"
		if classes[id] == "checkpoint" {
			state = "missing_checkpoint_bytes"
		}
		if classes[id] == "signature" {
			state = "missing_signature_bytes"
		}
		if classes[id] == "ciphertext" {
			state = "missing_ciphertext_bytes"
		}
		add(id, state, files[id].Size)
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	if err = t.Tx.Commit(ctx); err != nil {
		return nil, err
	}
	return report, nil
}
