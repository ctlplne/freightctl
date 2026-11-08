package workflow

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"reflect"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/delivery"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/vpath"
)

type Service struct {
	Custody   *custody.Service
	Processor ProcessingPort
}
type ConnectionDefinition struct {
	Schema      int                             `json:"schema_version"`
	Destination secure.SSHDestination           `json:"destination"`
	Directory   string                          `json:"directory"`
	FTPS        *delivery.FTPSDefinition        `json:"ftps,omitempty"`
	Local       *delivery.LocalCollectionSource `json:"local,omitempty"`
	DAV         *delivery.DAVCollectionSource   `json:"dav,omitempty"`
}
type ConnectionRequest struct {
	ID              string                          `json:"connection_id,omitempty"`
	ExpectedVersion int                             `json:"expected_version"`
	Address         string                          `json:"address"`
	User            string                          `json:"user"`
	Directory       string                          `json:"directory"`
	HostPublicFile  string                          `json:"host_public_file"`
	KeyFile         string                          `json:"key_file"`
	KeyPublicFile   string                          `json:"key_public_file"`
	FTPS            *delivery.FTPSDefinition        `json:"ftps,omitempty"`
	Local           *delivery.LocalCollectionSource `json:"local,omitempty"`
	DAV             *delivery.DAVCollectionSource   `json:"dav,omitempty"`
}
type ConnectionView struct {
	ID              string               `json:"id"`
	Version         int                  `json:"version"`
	Hash            string               `json:"definition_hash"`
	State           string               `json:"state"`
	Revision        int64                `json:"revision"`
	Address         string               `json:"address"`
	User            string               `json:"user"`
	Directory       string               `json:"directory"`
	HostFingerprint string               `json:"host_fingerprint"`
	KeyFingerprint  string               `json:"key_fingerprint"`
	Protocol        string               `json:"protocol,omitempty"`
	FTPS            *FTPSConnectionView  `json:"ftps,omitempty"`
	Local           *LocalConnectionView `json:"local,omitempty"`
	DAV             *DAVConnectionView   `json:"dav,omitempty"`
}

type DAVConnectionView struct {
	Profile               string `json:"profile"`
	ServerName            string `json:"server_name"`
	CASHA256              string `json:"ca_sha256"`
	CAReferenceHash       string `json:"ca_reference_sha256"`
	TokenReferenceHash    string `json:"token_reference_sha256,omitempty"`
	ReadOnly              bool   `json:"read_only"`
	Authentication        string `json:"authentication,omitempty"`
	PasswordReferenceHash string `json:"password_reference_sha256,omitempty"`
}

type LocalConnectionView struct {
	Profile           string `json:"profile"`
	RootReferenceHash string `json:"root_reference_sha256"`
	ConfigurationHash string `json:"configuration_sha256"`
	RootFingerprint   string `json:"root_fingerprint"`
	ReadOnly          bool   `json:"read_only"`
}

type FTPSConnectionView struct {
	Mode                  string                     `json:"mode"`
	ServerName            string                     `json:"server_name"`
	CASHA256              string                     `json:"ca_sha256"`
	CAReferenceHash       string                     `json:"ca_reference_sha256"`
	PasswordReferenceHash string                     `json:"password_reference_sha256"`
	StagingDirectory      string                     `json:"staging_directory"`
	ReceiverContract      store.FTPSReceiverContract `json:"receiver_contract"`
}

func connectionDefinition(c *store.Configuration) (*ConnectionDefinition, error) {
	var d ConnectionDefinition
	// Stored SSH public identities use the library's historical Wire/Fingerprint
	// keys. Request Decode's lowercase-key policy is not their storage format.
	// JSONB removes duplicate keys; strict decoding plus the canonical checksum
	// below still rejects unknown, changed or trailing stored fields.
	decoder := json.NewDecoder(bytes.NewReader(c.Definition))
	decoder.DisallowUnknownFields()
	var trailing any
	if len(c.Definition) > 32<<10 || decoder.Decode(&d) != nil || decoder.Decode(&trailing) != io.EOF {
		return nil, store.ErrState
	}
	_, hash, err := digest(d)
	canonical, pathErr := vpath.Canonical(d.Directory)
	if err != nil || hash != c.Hash || pathErr != nil || canonical != d.Directory || vpath.ControlPath(canonical) {
		return nil, store.ErrState
	}
	if d.Schema == 1 && d.DAV == nil && d.FTPS == nil && d.Local == nil && secure.ValidateSSHDestination(d.Destination) == nil {
		return &d, nil
	}
	if d.Schema == 2 && d.DAV == nil && d.Local == nil && reflect.DeepEqual(d.Destination, secure.SSHDestination{}) && d.FTPS.Valid(d.Directory) {
		return &d, nil
	}
	if d.Schema == 3 && d.DAV == nil && d.FTPS == nil && reflect.DeepEqual(d.Destination, secure.SSHDestination{}) && d.Directory == "/" && d.Local.Valid() {
		return &d, nil
	}
	if d.Schema == 4 && d.FTPS == nil && d.Local == nil && reflect.DeepEqual(d.Destination, secure.SSHDestination{}) && d.DAV.Valid() {
		return &d, nil
	}
	return nil, store.ErrState
}

func ftpsConnectionView(f *delivery.FTPSDefinition) *FTPSConnectionView {
	return &FTPSConnectionView{Mode: f.Destination.Mode, ServerName: f.Destination.ServerName, CASHA256: f.Destination.CASHA256, CAReferenceHash: secure.Digest([]byte(f.Destination.CAFile)), PasswordReferenceHash: secure.Digest([]byte(f.Destination.PasswordFile)), StagingDirectory: f.StagingDirectory, ReceiverContract: f.ReceiverContract}
}

func (s *Service) begin(ctx context.Context, scope store.Scope, grants ...string) (*store.Transaction, error) {
	t, err := s.Custody.DB.Begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	if t.Root != "/" {
		t.Tx.Rollback(ctx)
		return nil, store.ErrForbidden
	}
	for _, grant := range grants {
		if err = t.Require(grant); err != nil {
			t.Tx.Rollback(ctx)
			return nil, err
		}
	}
	return t, nil
}
func viewConnection(c *store.Configuration) (ConnectionView, error) {
	d, err := connectionDefinition(c)
	if err != nil {
		return ConnectionView{}, store.ErrState
	}
	if d.FTPS != nil {
		return ConnectionView{ID: c.ID, Version: c.Version, Hash: c.Hash, State: c.State, Revision: c.Revision, Address: d.FTPS.Destination.Address, User: d.FTPS.Destination.User, Directory: d.Directory, Protocol: "ftps", FTPS: ftpsConnectionView(d.FTPS)}, nil
	}
	if d.Local != nil {
		return ConnectionView{ID: c.ID, Version: c.Version, Hash: c.Hash, State: c.State, Revision: c.Revision, Directory: "/", Protocol: "local", Local: &LocalConnectionView{Profile: delivery.LocalCollectionProfile, RootReferenceHash: secure.Digest([]byte(d.Local.Reference)), ConfigurationHash: d.Local.SHA256, RootFingerprint: d.Local.RootFingerprint, ReadOnly: true}}, nil
	}
	if d.DAV != nil {
		peer := d.DAV.Destination
		proof := &DAVConnectionView{Profile: "freightctl-webdav-collection-source-v1", ServerName: peer.ServerName, CASHA256: peer.CASHA256, CAReferenceHash: secure.Digest([]byte(peer.CAFile)), ReadOnly: true}
		if peer.Authentication == "basic" {
			proof.Profile, proof.Authentication = "freightctl-webdav-basic-collection-source-v1", "basic"
			proof.PasswordReferenceHash = secure.Digest([]byte(peer.PasswordFile))
		} else {
			proof.TokenReferenceHash = secure.Digest([]byte(peer.TokenFile))
		}
		return ConnectionView{ID: c.ID, Version: c.Version, Hash: c.Hash, State: c.State, Revision: c.Revision, Address: peer.Address, User: peer.User, Directory: d.Directory, Protocol: "webdav", DAV: proof}, nil
	}
	return ConnectionView{ID: c.ID, Version: c.Version, Hash: c.Hash, State: c.State, Revision: c.Revision, Address: d.Destination.Address, User: d.Destination.User, Directory: d.Directory, HostFingerprint: d.Destination.Host.Fingerprint, KeyFingerprint: d.Destination.KeyFingerprint}, nil
}
func digest(v any) (json.RawMessage, string, error) {
	b, err := json.Marshal(v)
	return b, secure.Digest(b), err
}
func result(t *store.Transaction, ctx context.Context, key, meaning, id string, value any) (*Result, error) {
	// All workflow controls use the existing stored-receipt path. A separate
	// first-response Go encoding can differ from PostgreSQL JSONB on replay.
	return scheduleResult(t, ctx, key, meaning, id, value)
}
func replay(t *store.Transaction, ctx context.Context, key, meaning string) (*Result, error) {
	data, err := t.WorkflowReplay(ctx, key, meaning)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, nil
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return &Result{Resource: data, Replayed: true}, t.Tx.Commit(ctx)
}

// RegisterConnection is a local management operation. It is deliberately absent
// from HTTP: callers of that surface can only use existing registered references.
func (s *Service) RegisterConnection(ctx context.Context, scope store.Scope, key string, r ConnectionRequest) (*Result, error) {
	if !keyPattern.MatchString(key) || r.ExpectedVersion < 0 || (r.ID != "" && (!store.ValidID(r.ID) || r.ExpectedVersion < 1)) || (r.ID == "" && r.ExpectedVersion != 0) {
		return nil, ErrInput
	}
	t, err := s.begin(ctx, scope, "admin", "connections_manage")
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	directory, err := vpath.Canonical(r.Directory)
	if err != nil || directory != r.Directory || vpath.ControlPath(directory) {
		return nil, ErrInput
	}
	definition := ConnectionDefinition{Schema: 2, Directory: directory, FTPS: r.FTPS}
	if r.DAV != nil {
		if r.FTPS != nil || r.Local != nil || r.Address != "" || r.User != "" || r.HostPublicFile != "" || r.KeyFile != "" || r.KeyPublicFile != "" || !r.DAV.Valid() {
			return nil, ErrInput
		}
		dav := *r.DAV
		definition = ConnectionDefinition{Schema: 4, Directory: directory, DAV: &dav}
	} else if r.Local != nil {
		if t.Root != "/" || directory != "/" || r.FTPS != nil || r.Address != "" || r.User != "" || r.HostPublicFile != "" || r.KeyFile != "" || r.KeyPublicFile != "" || !r.Local.Valid() {
			return nil, ErrInput
		}
		local := *r.Local
		peer, err := delivery.OpenConfiguredLocalCollectionPeer(ctx, &local, func() error { return t.Reauthorize(ctx) })
		if err != nil {
			return nil, err
		}
		if err = peer.Close(); err != nil {
			return nil, err
		}
		definition = ConnectionDefinition{Schema: 3, Directory: "/", Local: &local}
	} else if r.FTPS != nil {
		if r.Address != "" || r.User != "" || r.HostPublicFile != "" || r.KeyFile != "" || r.KeyPublicFile != "" || !r.FTPS.Valid(directory) {
			return nil, ErrInput
		}
	} else {
		keyFile, err := filepath.Abs(r.KeyFile)
		if err != nil {
			return nil, ErrInput
		}
		host, err := secure.ReadSSHPublic(r.HostPublicFile)
		if err != nil {
			return nil, err
		}
		public, err := secure.ReadSSHPublic(r.KeyPublicFile)
		if err != nil {
			return nil, err
		}
		definition = ConnectionDefinition{Schema: 1, Destination: secure.SSHDestination{Address: r.Address, User: r.User, Host: host, KeyFile: keyFile, KeyFingerprint: public.Fingerprint}, Directory: directory}
		if err = secure.ValidateSSHDestination(definition.Destination); err != nil {
			return nil, err
		}
	}
	data, hash, err := digest(definition)
	if err != nil {
		return nil, err
	}
	_, meaning, _ := digest(struct {
		Kind, ID, Hash string
		Expected       int
	}{"register_connection", r.ID, hash, r.ExpectedVersion})
	if prior, err := replay(t, ctx, key, meaning); err != nil || prior != nil {
		return prior, err
	}
	id := r.ID
	if id == "" {
		id = secure.NewID()
	}
	current, err := t.ConfigurationVersion(ctx, true, id)
	if err != nil {
		return nil, err
	}
	if current != r.ExpectedVersion {
		return nil, store.ErrRevision
	}
	c := &store.Configuration{ID: id, Version: current + 1, Definition: data, Hash: hash, State: "active", Revision: 1}
	if err = t.SaveConfiguration(ctx, true, c, 0); err != nil {
		return nil, err
	}
	view, err := viewConnection(c)
	if err != nil {
		return nil, err
	}
	return result(t, ctx, key, meaning, id, view)
}
func (s *Service) Connection(ctx context.Context, scope store.Scope, id string, version int) (*ConnectionView, error) {
	t, err := s.begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if !t.Has("connections_manage") && !t.Has("workflow_manage") && !t.Has("workflow_approve") && !t.Has("workflow_execute") {
		return nil, store.ErrForbidden
	}
	c, err := t.Configuration(ctx, true, id, version, false)
	if err != nil {
		return nil, err
	}
	view, err := viewConnection(c)
	if err != nil {
		return nil, err
	}
	return &view, t.Tx.Commit(ctx)
}
func (s *Service) RevokeConnection(ctx context.Context, scope store.Scope, id string, version int, key string, decision Decision) (*Result, error) {
	if !keyPattern.MatchString(key) || !hashPattern.MatchString(decision.Hash) || decision.Revision < 1 {
		return nil, ErrInput
	}
	t, err := s.begin(ctx, scope, "admin", "connections_manage")
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	_, meaning, _ := digest(struct {
		Kind, ID string
		Version  int
		Decision Decision
	}{"revoke_connection", id, version, decision})
	if prior, err := replay(t, ctx, key, meaning); err != nil || prior != nil {
		return prior, err
	}
	c, err := t.Configuration(ctx, true, id, version, true)
	if err != nil {
		return nil, err
	}
	if c.Revision != decision.Revision || c.Hash != decision.Hash {
		return nil, store.ErrRevision
	}
	if c.State != "active" {
		return nil, store.ErrState
	}
	previous := c.Revision
	c.State = "revoked"
	c.Revision++
	if err = t.SaveConfiguration(ctx, true, c, previous); err != nil {
		return nil, err
	}
	view, err := viewConnection(c)
	if err != nil {
		return nil, err
	}
	return result(t, ctx, key, meaning, id, view)
}
func connections(ctx context.Context, t *store.Transaction, d Definition) ([]ConnectionView, error) {
	if d.Schema == 3 {
		if d.Processing == nil {
			return nil, ErrInput
		}
		p, err := t.ProcessingPolicy(ctx, store.OnboardingReference{ID: d.Processing.OutputPolicy.ID, Version: d.Processing.OutputPolicy.Version, Hash: d.Processing.OutputPolicy.Hash})
		if err != nil {
			return nil, err
		}
		if p == nil || (p.State != "active" && p.State != "output_active") || d.Processing.OutputPolicy != (Reference{ID: p.ID, Version: p.Version, Hash: p.Hash}) {
			return nil, store.ErrRevision
		}
	}
	if d.Source != nil {
		if _, _, err := collectionConnection(ctx, t, d.Source); err != nil {
			return nil, err
		}
	}
	views := make([]ConnectionView, 0, len(d.Steps))
	for _, step := range d.Steps {
		c, err := t.Configuration(ctx, true, step.Connection.ID, step.Connection.Version, false)
		if err != nil {
			return nil, err
		}
		if c.Hash != step.Connection.Hash {
			return nil, store.ErrRevision
		}
		if c.State != "active" {
			return nil, store.ErrState
		}
		definition, err := connectionDefinition(c)
		if err != nil {
			return nil, err
		}
		if definition.Local != nil || definition.DAV != nil || (step.Kind == "ftps.deliver") != (definition.FTPS != nil) {
			return nil, ErrInput
		}
		if step.Encryption != nil {
			if _, err = t.EncryptionKey(ctx, *step.Encryption); err != nil {
				return nil, err
			}
		}
		v, err := viewConnection(c)
		if err != nil {
			return nil, err
		}
		views = append(views, v)
	}
	return views, nil
}
func (s *Service) Draft(ctx context.Context, scope store.Scope, key string, r DraftRequest) (*Result, error) {
	if !keyPattern.MatchString(key) || r.ExpectedVersion < 0 || (r.ID != "" && (!store.ValidID(r.ID) || r.ExpectedVersion < 1)) || (r.ID == "" && r.ExpectedVersion != 0) {
		return nil, ErrInput
	}
	d, err := Normalize(r.Definition)
	if err != nil {
		return nil, err
	}
	r.Definition = d
	t, err := s.beginWorkflow(ctx, scope, "workflow_manage")
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if err = workflowDefinitionScope(t, d); err != nil {
		return nil, err
	}
	if _, err = connections(ctx, t, d); err != nil {
		return nil, err
	}
	_, meaning, _ := digest(struct {
		Kind    string
		Request DraftRequest
	}{"draft_workflow", r})
	if prior, err := replay(t, ctx, key, meaning); err != nil || prior != nil {
		return prior, err
	}
	c, err := StageDraft(ctx, t, r)
	if err != nil {
		return nil, err
	}
	return result(t, ctx, key, meaning, c.ID, c)
}

// StageDraft participates in its caller's transaction. Model adoption receives
// only draft creation, with exactly the same normalization and permission gates.
// It never approves a definition, creates a run or executes an external effect.
func StageDraft(ctx context.Context, t *store.Transaction, r DraftRequest) (*store.Configuration, error) {
	if t.Root != "/" && r.Definition.Schema != 3 {
		return nil, store.ErrForbidden
	}
	if err := t.Require("workflow_manage"); err != nil {
		return nil, err
	}
	if r.ExpectedVersion < 0 || (r.ID != "" && (!store.ValidID(r.ID) || r.ExpectedVersion < 1)) || (r.ID == "" && r.ExpectedVersion != 0) {
		return nil, ErrInput
	}
	d, err := Normalize(r.Definition)
	if err != nil {
		return nil, err
	}
	if _, err = connections(ctx, t, d); err != nil {
		return nil, err
	}
	data, hash, err := digest(d)
	if err != nil {
		return nil, err
	}
	id := r.ID
	if id == "" {
		id = secure.NewID()
	}
	current, err := t.ConfigurationVersion(ctx, false, id)
	if err != nil {
		return nil, err
	}
	if current != r.ExpectedVersion {
		return nil, store.ErrRevision
	}
	c := &store.Configuration{ID: id, Version: current + 1, Definition: data, Hash: hash, State: "draft", Revision: 1}
	if err = t.SaveConfiguration(ctx, false, c, 0); err != nil {
		return nil, err
	}
	return c, nil
}
func (s *Service) Configuration(ctx context.Context, scope store.Scope, id string, version int) (*store.Configuration, error) {
	t, err := s.beginWorkflow(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if !t.Has("workflow_manage") && !t.Has("workflow_approve") && !t.Has("workflow_execute") {
		return nil, store.ErrForbidden
	}
	c, err := t.Configuration(ctx, false, id, version, false)
	if err != nil {
		return nil, err
	}
	if err = workflowConfigurationScope(t, c); err != nil {
		return nil, err
	}
	return c, t.Tx.Commit(ctx)
}
func (s *Service) Decide(ctx context.Context, scope store.Scope, id string, version int, key, action string, decision Decision) (*Result, error) {
	if !keyPattern.MatchString(key) || !hashPattern.MatchString(decision.Hash) || decision.Revision < 1 || (action != "approve" && action != "revoke") {
		return nil, ErrInput
	}
	t, err := s.beginWorkflow(ctx, scope, "workflow_approve")
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	current, err := t.Configuration(ctx, false, id, version, false)
	if err != nil {
		return nil, err
	}
	if err = workflowConfigurationScope(t, current); err != nil {
		return nil, err
	}
	_, meaning, _ := digest(struct {
		Kind, ID string
		Version  int
		Decision Decision
	}{action + "_workflow", id, version, decision})
	if prior, err := replay(t, ctx, key, meaning); err != nil || prior != nil {
		return prior, err
	}
	c, err := t.Configuration(ctx, false, id, version, true)
	if err != nil {
		return nil, err
	}
	if c.Revision != decision.Revision || c.Hash != decision.Hash {
		return nil, store.ErrRevision
	}
	previous := c.Revision
	if action == "approve" {
		if c.State != "draft" {
			return nil, store.ErrState
		}
		var d Definition
		if err = Decode(c.Definition, &d); err != nil {
			return nil, err
		}
		if _, err = connections(ctx, t, d); err != nil {
			return nil, err
		}
		c.State = "approved"
		c.ApprovalAuthority = t.AuthorityRevision
	} else {
		if c.State != "approved" {
			return nil, store.ErrState
		}
		c.State = "revoked"
	}
	c.Revision++
	if err = t.SaveConfiguration(ctx, false, c, previous); err != nil {
		return nil, err
	}
	return result(t, ctx, key, meaning, id, c)
}

type Effect struct {
	StepID                string                  `json:"step_id"`
	Connection            Reference               `json:"connection"`
	Address               string                  `json:"address"`
	Directory             string                  `json:"directory"`
	FinalNamePattern      string                  `json:"final_name_pattern"`
	HostFingerprint       string                  `json:"host_fingerprint"`
	Encryption            *store.EncryptionPolicy `json:"encryption,omitempty"`
	RecipientFingerprint  string                  `json:"recipient_fingerprint,omitempty"`
	EncryptionFingerprint string                  `json:"encryption_fingerprint,omitempty"`
	Protocol              string                  `json:"protocol,omitempty"`
	User                  string                  `json:"user,omitempty"`
	FTPS                  *FTPSConnectionView     `json:"ftps,omitempty"`
}
type Preview struct {
	Definition       Definition        `json:"definition"`
	Hash             string            `json:"definition_hash"`
	Source           *store.File       `json:"source,omitempty"`
	Effects          []Effect          `json:"effects"`
	ExternalContact  bool              `json:"external_contact"`
	ApprovalRequired bool              `json:"approval_required"`
	Collection       *CollectionEffect `json:"collection,omitempty"`
	Processing       json.RawMessage   `json:"processing,omitempty"`
}

func (s *Service) Validate(ctx context.Context, scope store.Scope, r PreviewRequest) (*Preview, error) {
	d, err := Normalize(r.Definition)
	if err != nil {
		return nil, err
	}
	t, err := s.beginWorkflow(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if err = workflowDefinitionScope(t, d); err != nil {
		return nil, err
	}
	if !t.Has("workflow_manage") && !t.Has("workflow_approve") && !t.Has("workflow_execute") {
		return nil, store.ErrForbidden
	}
	effects, err := workflowEffects(ctx, t, &d)
	if err != nil {
		return nil, err
	}
	_, hash, err := digest(d)
	if err != nil {
		return nil, err
	}
	preview := &Preview{Definition: d, Hash: hash, ApprovalRequired: true, Effects: effects}
	if d.Source != nil {
		if r.FileID != "" {
			return nil, ErrInput
		}
		_, v, err := collectionConnection(ctx, t, d.Source)
		if err != nil {
			return nil, err
		}
		preview.Collection = &CollectionEffect{Kind: d.Source.Kind, Connection: *v, Source: *d.Source}
	}
	if r.FileID != "" {
		if !store.ValidID(r.FileID) {
			return nil, ErrInput
		}
		if err = t.Require("read"); err != nil {
			return nil, err
		}
		if d.Schema == 3 {
			if s.Processor == nil {
				return nil, store.ErrState
			}
			if err = t.NamespaceLock(ctx); err != nil {
				return nil, err
			}
			preview.Processing, err = s.Processor.ValidateProcessing(ctx, t, *d.Processing, r.FileID)
			if err != nil {
				return nil, err
			}
		} else if err = t.FileAccessible(ctx, r.FileID); err != nil {
			return nil, err
		}
		preview.Source, err = t.File(ctx, r.FileID)
		if err != nil {
			return nil, err
		}
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return preview, t.Tx.Commit(ctx)
}
