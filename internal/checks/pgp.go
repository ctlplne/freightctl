package checks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

type PGPKeyRequest struct {
	ID              string `json:"key_id,omitempty"`
	ExpectedVersion int    `json:"expected_version"`
	Fingerprint     string `json:"fingerprint"`
	PublicKey       []byte `json:"public_key"`
}
type PGPKeyView struct {
	ID          string     `json:"id"`
	Version     int        `json:"version"`
	Hash        string     `json:"definition_hash"`
	State       string     `json:"state"`
	Revision    int64      `json:"revision"`
	Fingerprint string     `json:"fingerprint"`
	Algorithm   string     `json:"algorithm"`
	KeyVersion  int        `json:"key_version"`
	Created     time.Time  `json:"created_at"`
	ValidUntil  *time.Time `json:"valid_until,omitempty"`
}

func keyView(row *store.PGPKey, definition *secure.PGPPublicKey) *PGPKeyView {
	return &PGPKeyView{ID: row.ID, Version: row.Version, Hash: row.Hash, State: row.State, Revision: row.Revision, Fingerprint: definition.Fingerprint, Algorithm: definition.Algorithm, KeyVersion: definition.Version, Created: definition.Created, ValidUntil: row.ValidUntil}
}
func decodeKey(row *store.PGPKey) (*secure.PGPPublicKey, error) {
	var definition secure.PGPPublicKey
	if json.Unmarshal(row.Definition, &definition) != nil || definition.Schema != 1 {
		return nil, store.ErrState
	}
	_, hash, err := canonical(definition)
	if err != nil || hash != row.Hash {
		return nil, store.ErrState
	}
	return &definition, nil
}
func (s *Service) RegisterPGPKey(ctx context.Context, scope store.Scope, key string, r PGPKeyRequest) (*Result, error) {
	if !keyPattern.MatchString(key) || r.ExpectedVersion < 0 || (r.ID != "" && (!store.ValidID(r.ID) || r.ExpectedVersion < 1)) || (r.ID == "" && r.ExpectedVersion != 0) {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.begin(ctx, scope, "admin", "pgp_manage")
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if t.Root != "/" {
		return nil, store.ErrForbidden
	}
	now, err := t.DatabaseTime(ctx)
	if err != nil {
		return nil, err
	}
	definition, err := secure.ParsePGPPublicKey(ctx, r.PublicKey, r.Fingerprint, now)
	if err != nil {
		return nil, ErrInput
	}
	data, hash, err := canonical(definition)
	if err != nil {
		return nil, err
	}
	_, meaning, _ := canonical(struct {
		Kind, ID, Hash  string
		ExpectedVersion int
	}{"register_pgp_key", r.ID, hash, r.ExpectedVersion})
	prior, err := t.CheckReplay(ctx, key, meaning)
	if err != nil {
		return nil, err
	}
	if prior != nil {
		return &Result{Resource: prior, Replayed: true}, t.Tx.Commit(ctx)
	}
	id := r.ID
	if id == "" {
		id = secure.NewID()
	}
	version, err := t.PGPKeyVersion(ctx, id)
	if err != nil {
		return nil, err
	}
	if version != r.ExpectedVersion {
		return nil, store.ErrRevision
	}
	row := &store.PGPKey{Configuration: store.Configuration{ID: id, Version: version + 1, Definition: data, Hash: hash, State: "active", Revision: 1}, ValidUntil: definition.ValidUntil}
	if err = t.SavePGPKey(ctx, row, 0); err != nil {
		return nil, err
	}
	return finish(ctx, t, key, meaning, id, keyView(row, definition))
}
func (s *Service) PGPKey(ctx context.Context, scope store.Scope, id string, version int) (*PGPKeyView, error) {
	t, err := s.begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if !t.Has("read") && !t.Has("write") && !t.Has("pgp_manage") {
		return nil, store.ErrForbidden
	}
	row, err := t.PGPKey(ctx, id, version, false)
	if err != nil {
		return nil, err
	}
	definition, err := decodeKey(row)
	if err != nil {
		return nil, err
	}
	return keyView(row, definition), t.Tx.Commit(ctx)
}
func (s *Service) RevokePGPKey(ctx context.Context, scope store.Scope, id string, version int, key string, d workflow.Decision) (*Result, error) {
	if !keyPattern.MatchString(key) || !hashPattern.MatchString(d.Hash) || d.Revision < 1 {
		return nil, ErrInput
	}
	t, err := s.begin(ctx, scope, "admin", "pgp_manage")
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if t.Root != "/" {
		return nil, store.ErrForbidden
	}
	_, meaning, _ := canonical(struct {
		Kind, ID string
		Version  int
		Decision workflow.Decision
	}{"revoke_pgp_key", id, version, d})
	prior, err := t.CheckReplay(ctx, key, meaning)
	if err != nil {
		return nil, err
	}
	row, err := t.PGPKey(ctx, id, version, true)
	if err != nil {
		return nil, err
	}
	if prior != nil {
		return &Result{Resource: prior, Replayed: true}, t.Tx.Commit(ctx)
	}
	if row.Hash != d.Hash || row.Revision != d.Revision {
		return nil, store.ErrRevision
	}
	if row.State != "active" {
		return nil, store.ErrState
	}
	definition, err := decodeKey(row)
	if err != nil {
		return nil, err
	}
	previous := row.Revision
	row.Revision++
	row.State = "revoked"
	if err = t.SavePGPKey(ctx, row, previous); err != nil {
		return nil, err
	}
	return finish(ctx, t, key, meaning, id, keyView(row, definition))
}
func keyCurrent(ctx context.Context, t *store.Transaction, p *SignaturePolicy) (*secure.PGPPublicKey, time.Time, error) {
	now, err := t.DatabaseTime(ctx)
	if err != nil {
		return nil, now, err
	}
	row, err := t.PGPKey(ctx, p.Key.ID, p.Key.Version, false)
	if err != nil {
		return nil, now, err
	}
	if row.State != "active" || row.Hash != p.Key.Hash || (row.ValidUntil != nil && !now.Before(*row.ValidUntil)) {
		return nil, now, store.ErrState
	}
	definition, err := decodeKey(row)
	if err != nil {
		return nil, now, err
	}
	checked, err := secure.ParsePGPPublicKey(ctx, definition.Packets, definition.Fingerprint, now)
	if err != nil || checked.Algorithm != definition.Algorithm || checked.Version != definition.Version || !checked.Created.Equal(definition.Created) {
		return nil, now, store.ErrState
	}
	return definition, now, nil
}
func (s *Service) AttachSignature(ctx context.Context, scope store.Scope, id, key, dataHash, policyHash string, revision int64, wire []byte) (*Result, error) {
	if !keyPattern.MatchString(key) || !hashPattern.MatchString(dataHash) || !hashPattern.MatchString(policyHash) || revision < 1 || secure.InspectPGPSignature(wire) != nil {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	t, err := s.begin(ctx, scope, "write")
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	_, meaning, _ := canonical(struct {
		Kind, ID, Data, Policy, Signature string
		Revision                          int64
	}{"attach_signature", id, dataHash, policyHash, secure.Digest(wire), revision})
	prior, err := t.CheckReplay(ctx, key, meaning)
	if err != nil {
		return nil, err
	}
	c, err := t.FileCheck(ctx, id, true)
	if err != nil {
		return nil, err
	}
	b, p, err := s.current(ctx, t, c)
	if err != nil {
		return nil, err
	}
	if prior != nil {
		return &Result{Resource: prior, Replayed: true}, t.Tx.Commit(ctx)
	}
	policy, err := decodePolicy(p)
	if err != nil {
		return nil, err
	}
	if policy.Signature == nil || c.State != "held" || c.Attempts != 0 {
		return nil, store.ErrState
	}
	if c.Revision != revision || b.File.SHA256 != dataHash || c.PolicyHash != policyHash {
		return nil, store.ErrRevision
	}
	existing, err := t.FileSignature(ctx, id)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	if existing != nil {
		if existing.SHA256 != secure.Digest(wire) || existing.Size != int64(len(wire)) {
			return nil, store.ErrConflict
		}
		return finish(ctx, t, key, meaning, id, existing)
	}
	if _, err = t.Tx.Exec(ctx, `SELECT pg_advisory_xact_lock(721815034)`); err != nil {
		return nil, err
	}
	if err = s.Custody.Disk.Capacity(int64(len(wire)), s.Custody.MaxStored); err != nil {
		return nil, err
	}
	artifact := &store.FileSignature{FileID: id, ObjectID: secure.NewID(), StorageID: b.StorageID, Size: int64(len(wire)), SHA256: secure.Digest(wire), DataSHA256: dataHash, PolicyHash: policyHash, Key: policy.Signature.Key}
	if err = s.Custody.Disk.Stage(custody.Name(scope.Tenant, scope.Partner, artifact.ObjectID), bytes.NewReader(wire), artifact.Size, artifact.SHA256); err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	if err = t.SaveFileSignature(ctx, artifact); err != nil {
		return nil, err
	}
	return finish(ctx, t, key, meaning, id, artifact)
}

func (s *Service) SignatureContent(ctx context.Context, scope store.Scope, id string) (*store.FileSignature, *os.File, error) {
	t, err := s.begin(ctx, scope, "read")
	if err != nil {
		return nil, nil, err
	}
	defer t.Tx.Rollback(ctx)
	c, err := t.FileCheck(ctx, id, false)
	if err != nil {
		return nil, nil, err
	}
	b, _, err := s.current(ctx, t, c)
	if err != nil {
		return nil, nil, err
	}
	artifact, err := t.FileSignature(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	if artifact.StorageID != b.StorageID || artifact.DataSHA256 != b.File.SHA256 || artifact.PolicyHash != c.PolicyHash {
		return nil, nil, store.ErrState
	}
	data, err := s.Custody.Disk.VerifiedContext(ctx, custody.Name(scope.Tenant, scope.Partner, artifact.ObjectID), artifact.Size, artifact.SHA256)
	if err != nil {
		return nil, nil, err
	}
	if err = t.Reauthorize(ctx); err == nil {
		err = t.Tx.Commit(ctx)
	}
	if err != nil {
		data.Close()
		return nil, nil, err
	}
	return artifact, data, nil
}
func (s *Service) verifySignature(ctx context.Context, scope store.Scope, c *store.FileCheck, b *store.CheckBinding, p Policy, grant string) (*SignatureProof, error) {
	if p.Signature == nil {
		return nil, nil
	}
	t, err := s.begin(ctx, scope, "read", grant)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	artifact, err := t.FileSignature(ctx, c.FileID)
	if err != nil {
		return nil, err
	}
	key, now, err := keyCurrent(ctx, t, p.Signature)
	if err != nil {
		return nil, err
	}
	if artifact.Key != p.Signature.Key || artifact.StorageID != b.StorageID || artifact.DataSHA256 != b.File.SHA256 || artifact.PolicyHash != c.PolicyHash {
		return nil, store.ErrState
	}
	if err = t.Tx.Commit(ctx); err != nil {
		return nil, err
	}
	signature, err := s.Custody.Disk.VerifiedContext(ctx, custody.Name(scope.Tenant, scope.Partner, artifact.ObjectID), artifact.Size, artifact.SHA256)
	if err != nil {
		return nil, err
	}
	wire, err := io.ReadAll(io.LimitReader(signature, secure.MaxPGPWire+1))
	_ = signature.Close()
	if err != nil || len(wire) > secure.MaxPGPWire {
		return nil, secure.ErrPGPInput
	}
	defer secure.Clear(wire)
	source, err := s.Custody.Disk.VerifiedContext(ctx, custody.Name(scope.Tenant, scope.Partner, b.File.ID), b.File.Size, b.File.SHA256)
	if err != nil {
		return nil, err
	}
	defer source.Close()
	verified, err := secure.VerifyPGPDetached(ctx, *key, wire, source, b.File.Size, b.File.SHA256, now, p.Signature.MaxAgeSeconds)
	if err != nil {
		return nil, err
	}
	return &SignatureProof{Key: p.Signature.Key, ObjectID: artifact.ObjectID, SHA256: artifact.SHA256, Verification: verified}, nil
}
