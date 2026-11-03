// Package delivery implements explicit, locally approved transfer intents.
// Workflow scheduling and receiver business acknowledgments are separate work.
package delivery

import (
	"context"
	"encoding/json"
	"errors"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/vpath"
)

var ErrInput = errors.New("invalid delivery request")
var keyPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
var namePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type Request struct {
	FileID         string          `json:"file_id"`
	Address        string          `json:"address"`
	User           string          `json:"user"`
	Directory      string          `json:"directory"`
	Filename       string          `json:"filename"`
	HostPublicFile string          `json:"host_public_file"`
	KeyFile        string          `json:"key_file"`
	KeyPublicFile  string          `json:"key_public_file"`
	FTPS           *FTPSDefinition `json:"ftps,omitempty"`
}
type Definition struct {
	Schema         int                          `json:"schema_version"`
	Source         store.File                   `json:"source"`
	Destination    secure.SSHDestination        `json:"destination"`
	Directory      string                       `json:"directory"`
	Filename       string                       `json:"filename"`
	StorageID      string                       `json:"storage_id"`
	Root           string                       `json:"namespace_root"`
	Authority      int64                        `json:"authority_revision"`
	Binding        *store.ExecutionBinding      `json:"workflow_binding,omitempty"`
	Encryption     *store.EncryptionPolicy      `json:"encryption,omitempty"`
	DispatchPolicy *store.ApprovalPolicyBinding `json:"dispatch_approval_policy,omitempty"`
	Transfer       *store.DeliveryCiphertext    `json:"-"`
	FTPS           *FTPSDefinition              `json:"ftps,omitempty"`
}
type Result struct {
	Delivery *store.Delivery `json:"delivery"`
	Replayed bool            `json:"replayed"`
}
type Service struct{ Custody *custody.Service }

func require(t *store.Transaction, management bool) error {
	if t.Root != "/" {
		return store.ErrForbidden
	}
	for _, p := range []string{"read", "deliver"} {
		if err := t.Require(p); err != nil {
			return err
		}
	}
	if management {
		for _, p := range []string{"admin", "connections_manage"} {
			if err := t.Require(p); err != nil {
				return err
			}
		}
	}
	return nil
}
func (s *Service) Create(ctx context.Context, scope store.Scope, key string, r Request) (*Result, error) {
	if !keyPattern.MatchString(key) || !store.ValidID(r.FileID) || !namePattern.MatchString(r.Filename) {
		return nil, ErrInput
	}
	directory, err := vpath.Canonical(r.Directory)
	if err != nil || directory != r.Directory || vpath.ControlPath(directory) {
		return nil, ErrInput
	}
	destination, ftps, err := requestDestination(r)
	if err != nil {
		return nil, err
	}
	t, err := s.Custody.DB.Begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if err = require(t, true); err != nil {
		return nil, err
	}
	if err = t.FileAccessible(ctx, r.FileID); err != nil {
		return nil, err
	}
	file, err := t.File(ctx, r.FileID)
	if err != nil {
		return nil, err
	}
	if file.Size > s.Custody.MaxFile {
		return nil, store.ErrLimit
	}
	if s.Custody.Disk == nil {
		return nil, custody.ErrStorageIdentity
	}
	if err = s.Custody.Disk.CheckIdentity(); err != nil {
		return nil, err
	}
	definition := Definition{Schema: 1, Source: *file, Destination: destination, Directory: directory, Filename: r.Filename, StorageID: s.Custody.Disk.Identity(), Root: t.Root, Authority: t.AuthorityRevision}
	if ftps != nil {
		definition.Schema, definition.FTPS = 2, ftps
	}
	encoded, err := json.Marshal(definition)
	if err != nil {
		return nil, err
	}
	hash := secure.Digest(encoded)
	prior, err := t.DeliveryReplay(ctx, key, hash)
	if err != nil {
		return nil, err
	}
	if prior != nil {
		return &Result{prior, true}, t.Tx.Commit(ctx)
	}
	meaning := hash
	if err = BindDispatchPolicy(ctx, t, &definition); err != nil {
		return nil, err
	}
	encoded, hash, err = dispatchDigest(definition)
	if err != nil {
		return nil, err
	}
	if err = t.DeliveryAdmission(ctx, 1); err != nil {
		return nil, err
	}
	now, err := t.DatabaseTime(ctx)
	if err != nil {
		return nil, err
	}
	d := &store.Delivery{ID: secure.NewID(), FileID: file.ID, Definition: encoded, DefinitionHash: hash, State: "draft", Revision: 1, NextAt: now, Observation: json.RawMessage(`{}`)}
	if err = t.SaveDelivery(ctx, d, 0); err != nil {
		return nil, err
	}
	if err = t.DeliveryReceipt(ctx, key, meaning, d); err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return &Result{d, false}, t.Tx.Commit(ctx)
}
func (s *Service) begin(ctx context.Context, scope store.Scope, id string, lock bool) (*store.Transaction, *store.Delivery, *Definition, error) {
	t, err := s.Custody.DB.Begin(ctx, scope)
	if err != nil {
		return nil, nil, nil, err
	}
	fail := func(err error) (*store.Transaction, *store.Delivery, *Definition, error) {
		t.Tx.Rollback(ctx)
		return nil, nil, nil, err
	}
	if err = require(t, false); err != nil {
		return fail(err)
	}
	d, err := t.Delivery(ctx, id, lock)
	if err != nil {
		return fail(err)
	}
	var spec Definition
	if err = json.Unmarshal(d.Definition, &spec); err != nil || !validProtocolDefinition(&spec) || spec.Source.ID != d.FileID {
		return fail(store.ErrState)
	}
	// JSONB reorders keys: the hash identifies the original typed canonical definition.
	encoded, err := json.Marshal(spec)
	if err != nil || secure.Digest(encoded) != d.DefinitionHash {
		return fail(store.ErrState)
	}
	if spec.Root != t.Root || spec.Authority != t.AuthorityRevision {
		return fail(store.ErrUnauthorized)
	}
	if err = t.FileAccessible(ctx, d.FileID); err != nil {
		return fail(err)
	}
	file, err := t.File(ctx, d.FileID)
	if err != nil {
		return fail(err)
	}
	if *file != spec.Source {
		return fail(store.ErrState)
	}
	return t, d, &spec, nil
}

func requestDestination(r Request) (secure.SSHDestination, *FTPSDefinition, error) {
	if r.FTPS != nil {
		if r.Address != "" || r.User != "" || r.HostPublicFile != "" || r.KeyFile != "" || r.KeyPublicFile != "" || !validFTPSDefinition(r.FTPS, r.Directory) {
			return secure.SSHDestination{}, nil, ErrInput
		}
		copy := *r.FTPS
		return secure.SSHDestination{}, &copy, nil
	}
	keyFile, err := filepath.Abs(r.KeyFile)
	if err != nil {
		return secure.SSHDestination{}, nil, ErrInput
	}
	host, err := secure.ReadSSHPublic(r.HostPublicFile)
	if err != nil {
		return secure.SSHDestination{}, nil, err
	}
	public, err := secure.ReadSSHPublic(r.KeyPublicFile)
	if err != nil {
		return secure.SSHDestination{}, nil, err
	}
	d := secure.SSHDestination{Address: r.Address, User: r.User, Host: host, KeyFile: keyFile, KeyFingerprint: public.Fingerprint}
	return d, nil, secure.ValidateSSHDestination(d)
}
func (s *Service) Status(ctx context.Context, scope store.Scope, id string) (*store.Delivery, error) {
	t, d, _, err := s.begin(ctx, scope, id, false)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	return d, t.Tx.Commit(ctx)
}
func (s *Service) Command(ctx context.Context, scope store.Scope, id, key, action, hash string, revision int64) (*Result, error) {
	if !keyPattern.MatchString(key) || (action != "approve" && action != "cancel") {
		return nil, ErrInput
	}
	// Lock receipt before the intent in every command to keep lock ordering stable.
	t, err := s.Custody.DB.Begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if err = require(t, true); err != nil {
		return nil, err
	}
	meaning := secure.Digest([]byte(action + ":" + id + ":" + hash + ":" + strconv.FormatInt(revision, 10)))
	prior, err := t.DeliveryReplay(ctx, key, meaning)
	if err != nil {
		return nil, err
	}
	if prior != nil { // Recheck frozen authority even when returning the original receipt.
		var spec Definition
		if json.Unmarshal(prior.Definition, &spec) != nil || spec.Authority != t.AuthorityRevision || spec.Root != t.Root {
			return nil, store.ErrUnauthorized
		}
		if err = t.FileAccessible(ctx, prior.FileID); err != nil {
			return nil, err
		}
		return &Result{prior, true}, t.Tx.Commit(ctx)
	}
	d, err := t.Delivery(ctx, id, true)
	if err != nil {
		return nil, err
	}
	var spec Definition
	if json.Unmarshal(d.Definition, &spec) != nil || spec.Authority != t.AuthorityRevision || spec.Root != t.Root {
		return nil, store.ErrUnauthorized
	}
	if err = t.FileAccessible(ctx, d.FileID); err != nil {
		return nil, err
	}
	if d.Revision != revision || d.DefinitionHash != hash {
		return nil, store.ErrRevision
	}
	if action == "approve" {
		if d.State != "draft" {
			return nil, store.ErrState
		}
		d.State = "queued"
	} else {
		if d.State != "draft" && d.State != "queued" && d.State != "retry" && d.State != "ambiguous" {
			return nil, store.ErrState
		}
		d.State = "cancelled"
	}
	previous := d.Revision
	d.Revision++
	if err = t.SaveDelivery(ctx, d, previous); err != nil {
		return nil, err
	}
	if err = t.DeliveryReceipt(ctx, key, meaning, d); err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return &Result{d, false}, t.Tx.Commit(ctx)
}

func (s *Service) storage(spec *Definition) error {
	if s.Custody.Disk == nil || s.Custody.Disk.Identity() != spec.StorageID {
		return custody.ErrStorageIdentity
	}
	return s.Custody.Disk.CheckIdentity()
}
func clearLease(d *store.Delivery) { d.LeaseOwner = ""; d.LeaseUntil = nil }
func observation(code string) json.RawMessage {
	b, _ := json.Marshal(map[string]string{"code": code})
	return b
}
func (s *Service) Claim(ctx context.Context, scope store.Scope, id, owner string) (*store.Delivery, *Definition, error) {
	if !store.ValidID(owner) {
		return nil, nil, ErrInput
	}
	t, d, spec, err := s.begin(ctx, scope, id, true)
	if err != nil {
		return nil, nil, err
	}
	defer t.Tx.Rollback(ctx)
	if spec.Encryption != nil {
		if _, err = t.EncryptionKey(ctx, *spec.Encryption); err != nil {
			return nil, nil, err
		}
	}
	if err = t.CheckExecutionBinding(ctx, spec.Binding); err != nil {
		return nil, nil, err
	}
	if err = t.CheckOutboundDispatch(ctx, id); err != nil {
		return nil, nil, err
	}
	if err = s.storage(spec); err != nil {
		return nil, nil, err
	}
	now, err := t.DatabaseTime(ctx)
	if err != nil {
		return nil, nil, err
	}
	if d.State == "publishing" && d.LeaseUntil != nil && !d.LeaseUntil.After(now) {
		prior := d.Revision
		d.Revision++
		d.State = "ambiguous"
		clearLease(d)
		d.Observation = observation("worker_lost_during_publication")
		if err = t.SaveDelivery(ctx, d, prior); err != nil {
			return nil, nil, err
		}
		return d, spec, t.Tx.Commit(ctx)
	}
	if d.State != "queued" && d.State != "retry" && !(d.State == "staging" && d.LeaseUntil != nil && !d.LeaseUntil.After(now)) {
		return nil, nil, store.ErrState
	}
	if d.NextAt.After(now) {
		return nil, nil, store.ErrState
	}
	previous := d.Revision
	d.Revision++
	if d.Attempts >= 8 {
		d.State = "blocked"
		clearLease(d)
		d.Observation = observation("attempt_budget_exhausted")
	} else {
		until := now.Add(30 * time.Second)
		d.State = "staging"
		d.Fence++
		d.Attempts++
		d.LeaseOwner = owner
		d.LeaseUntil = &until
		d.Observation = observation("claimed")
	}
	if err = t.SaveDelivery(ctx, d, previous); err != nil {
		return nil, nil, err
	}
	return d, spec, t.Tx.Commit(ctx)
}
func (s *Service) transition(ctx context.Context, scope store.Scope, id, owner string, fence int64, next string, obs json.RawMessage) (*store.Delivery, error) {
	t, d, spec, err := s.begin(ctx, scope, id, true)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if spec.Encryption != nil && next != "blocked" && next != "retry" {
		if _, err = t.EncryptionKey(ctx, *spec.Encryption); err != nil {
			return nil, err
		}
	}
	if next == "blocked" || next == "retry" || next == "ambiguous" {
		err = t.CheckExecutionObservationBinding(ctx, spec.Binding)
	} else {
		err = t.CheckExecutionBinding(ctx, spec.Binding)
	}
	if err != nil {
		return nil, err
	}
	if next != "blocked" && next != "retry" && next != "ambiguous" {
		if err = t.CheckOutboundDispatch(ctx, id); err != nil {
			return nil, err
		}
	}
	if err = s.storage(spec); err != nil {
		return nil, err
	}
	now, err := t.DatabaseTime(ctx)
	if err != nil {
		return nil, err
	}
	if d.LeaseOwner != owner || d.Fence != fence || d.LeaseUntil == nil || !d.LeaseUntil.After(now) {
		return nil, store.ErrRevision
	}
	previous := d.Revision
	d.Revision++
	switch next {
	case "renew":
		until := now.Add(30 * time.Second)
		d.LeaseUntil = &until
	case "publishing":
		if d.State != "staging" {
			return nil, store.ErrState
		}
		d.State = next
	case "succeeded", "ambiguous":
		if d.State != "publishing" {
			return nil, store.ErrState
		}
		d.State = next
		clearLease(d)
	case "retry", "blocked":
		if d.State != "staging" {
			return nil, store.ErrState
		}
		d.State = next
		clearLease(d)
		d.NextAt = now.Add(time.Duration(1<<min(d.Attempts, 6)) * time.Second)
	default:
		return nil, store.ErrState
	}
	if obs != nil {
		d.Observation = obs
	}
	if err = t.SaveDelivery(ctx, d, previous); err != nil {
		return nil, err
	}
	return d, t.Tx.Commit(ctx)
}
func (s *Service) checkLease(ctx context.Context, scope store.Scope, id, owner string, fence int64) error {
	t, d, spec, err := s.begin(ctx, scope, id, false)
	if err != nil {
		return err
	}
	defer t.Tx.Rollback(ctx)
	if spec.Encryption != nil {
		if _, err = t.EncryptionKey(ctx, *spec.Encryption); err != nil {
			return err
		}
	}
	if err = t.CheckExecutionBinding(ctx, spec.Binding); err != nil {
		return err
	}
	if err = t.CheckOutboundDispatch(ctx, id); err != nil {
		return err
	}
	now, err := t.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if d.LeaseOwner != owner || d.Fence != fence || d.LeaseUntil == nil || !d.LeaseUntil.After(now) || (d.State != "staging" && d.State != "publishing") {
		return store.ErrRevision
	}
	if err = s.storage(spec); err != nil {
		return err
	}
	return t.Tx.Commit(ctx)
}
func finalPath(d *store.Delivery, spec *Definition) string {
	return path.Join(spec.Directory, d.ID+"-"+spec.Filename)
}
