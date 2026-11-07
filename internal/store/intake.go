package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/ctlplne/freightctl/internal/vpath"
	"github.com/jackc/pgx/v5"
)

type CheckBinding struct {
	File           File         `json:"file"`
	StorageID      string       `json:"storage_id"`
	Root           string       `json:"namespace_root"`
	Authority      int64        `json:"authority_revision"`
	ParentID       string       `json:"parent_id"`
	ParentRevision int64        `json:"parent_revision"`
	Target         *PathCommand `json:"target"`
}
type FileCheck struct {
	FileID        string          `json:"file_id"`
	PolicyID      string          `json:"policy_id"`
	PolicyVersion int             `json:"policy_version"`
	PolicyHash    string          `json:"policy_hash"`
	Binding       json.RawMessage `json:"binding"`
	State         string          `json:"state"`
	Revision      int64           `json:"revision"`
	Attempts      int             `json:"attempts"`
	WorkerID      string          `json:"worker_id"`
	LeaseUntil    *time.Time      `json:"lease_until"`
	Report        json.RawMessage `json:"report"`
	ReportHash    string          `json:"report_hash"`
	Code          string          `json:"code"`
}

func (t *Transaction) IntakePolicy(ctx context.Context, exclusive bool) (*Configuration, error) {
	lock := "pg_advisory_xact_lock_shared"
	suffix := " FOR SHARE"
	if exclusive {
		lock = "pg_advisory_xact_lock"
		suffix = " FOR UPDATE"
	}
	if _, err := t.Tx.Exec(ctx, `SELECT `+lock+`(hashtextextended($1,0))`, t.Scope.Tenant+":"+t.Scope.Partner+":intake-policy"); err != nil {
		return nil, err
	}
	p := &Configuration{}
	err := t.Tx.QueryRow(ctx, `SELECT policy_id::text,version,definition,definition_hash,state,revision FROM intake_policies WHERE state IN ('active','retired','revoked') ORDER BY version DESC LIMIT 1`+suffix).Scan(&p.ID, &p.Version, &p.Definition, &p.Hash, &p.State, &p.Revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return p, err
}
func (t *Transaction) SaveIntakePolicy(ctx context.Context, p *Configuration, previous int64) error {
	event, err := t.Append(ctx, "IntakePolicyChanged", p.ID, p)
	if err != nil {
		return err
	}
	if previous == 0 {
		_, err = t.Tx.Exec(ctx, `INSERT INTO intake_policies VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, t.Scope.Tenant, t.Scope.Partner, t.Actor, p.ID, p.Version, p.Definition, p.Hash, p.State, p.Revision, event)
		return err
	}
	tag, err := t.Tx.Exec(ctx, `UPDATE intake_policies SET state=$1,revision=$2,changed_event_id=$3 WHERE policy_id=$4 AND version=$5 AND revision=$6`, p.State, p.Revision, event, p.ID, p.Version, previous)
	if err == nil && tag.RowsAffected() != 1 {
		return ErrRevision
	}
	return err
}

// ConfigureIntakeFile executes before staging. A configured/revoked policy can
// never fall back silently to the historical integrity-only development profile.
func (t *Transaction) ConfigureIntakeFile(ctx context.Context, f *File) error {
	p, err := t.IntakePolicy(ctx, false)
	if err != nil {
		return err
	}
	if p == nil {
		f.Policy = "integrity-only-v1"
		return nil
	}
	if p.State != "active" {
		return ErrState
	}
	return t.configurePolicyFile(ctx, f, p)
}

func (t *Transaction) configurePolicyFile(ctx context.Context, f *File, p *Configuration) error {
	var err error
	if _, err = t.Tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, t.Scope.Tenant+":"+t.Scope.Partner+":"+t.Actor+":check-admission"); err != nil {
		return err
	}
	var count int
	if err = t.Tx.QueryRow(ctx, `SELECT count(*) FROM file_checks WHERE actor_id=$1 AND state<>'released'`, t.Actor).Scan(&count); err != nil {
		return err
	}
	if count >= 128 {
		return ErrLimit
	}
	f.Policy, err = IntakeFilePolicy(p)
	return err
}
func (t *Transaction) BindIntake(ctx context.Context, f *File, storageID string, target *PathCommand) (bool, error) {
	p, err := t.IntakePolicy(ctx, false)
	if err != nil {
		return false, err
	}
	if p == nil {
		if f.Policy != "integrity-only-v1" {
			return false, ErrState
		}
		return false, nil
	}
	expected, formatErr := IntakeFilePolicy(p)
	if p.State != "active" || formatErr != nil || f.Policy != expected || !ValidID(storageID) {
		return false, ErrState
	}
	return t.bindPolicyFile(ctx, f, storageID, target, p)
}

func (t *Transaction) bindPolicyFile(ctx context.Context, f *File, storageID string, target *PathCommand, p *Configuration) (bool, error) {
	b := CheckBinding{File: *f, StorageID: storageID, Root: t.Root, Authority: t.AuthorityRevision, Target: target}
	if target != nil {
		actual, err := vpath.Resolve(t.Root, target.Path)
		if err != nil {
			return false, err
		}
		parent, err := t.Entry(ctx, vpath.Parent(actual))
		if err != nil {
			return false, err
		}
		b.ParentID = parent.ID
		b.ParentRevision = parent.Revision
	}
	data, err := json.Marshal(b)
	if err != nil {
		return false, err
	}
	c := &FileCheck{FileID: f.ID, PolicyID: p.ID, PolicyVersion: p.Version, PolicyHash: p.Hash, Binding: data, State: "held", Revision: 1, Report: json.RawMessage(`{}`), Code: "awaiting_checks"}
	return true, t.SaveFileCheck(ctx, c, 0)
}
func (t *Transaction) FileCheck(ctx context.Context, id string, lock bool) (*FileCheck, error) {
	if !ValidID(id) {
		return nil, ErrNotFound
	}
	q := `SELECT file_id::text,policy_id::text,policy_version,policy_hash,binding,state,revision,attempts,coalesce(worker_id::text,''),lease_until,report,report_hash,code FROM file_checks WHERE file_id=$1 AND actor_id=$2`
	if lock {
		q += ` FOR UPDATE`
	}
	c := &FileCheck{}
	err := t.Tx.QueryRow(ctx, q, id, t.Actor).Scan(&c.FileID, &c.PolicyID, &c.PolicyVersion, &c.PolicyHash, &c.Binding, &c.State, &c.Revision, &c.Attempts, &c.WorkerID, &c.LeaseUntil, &c.Report, &c.ReportHash, &c.Code)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return c, err
}
func (t *Transaction) SaveFileCheck(ctx context.Context, c *FileCheck, previous int64) error {
	event, err := t.Append(ctx, "FileCheckChanged", c.FileID, c)
	if err != nil {
		return err
	}
	if previous == 0 {
		_, err = t.Tx.Exec(ctx, `INSERT INTO file_checks VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,nullif($12,'')::uuid,$13,$14,$15,$16,$17)`, t.Scope.Tenant, t.Scope.Partner, t.Actor, c.FileID, c.PolicyID, c.PolicyVersion, c.PolicyHash, c.Binding, c.State, c.Revision, c.Attempts, c.WorkerID, c.LeaseUntil, c.Report, c.ReportHash, c.Code, event)
		return err
	}
	tag, err := t.Tx.Exec(ctx, `UPDATE file_checks SET state=$1,revision=$2,attempts=$3,worker_id=nullif($4,'')::uuid,lease_until=$5,report=$6,report_hash=$7,code=$8,changed_event_id=$9 WHERE file_id=$10 AND actor_id=$11 AND revision=$12`, c.State, c.Revision, c.Attempts, c.WorkerID, c.LeaseUntil, c.Report, c.ReportHash, c.Code, event, c.FileID, t.Actor, previous)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrRevision
	}
	if c.State == "released" {
		key, signatureHash, until, parseErr := releaseSignatureFields(c.Report)
		if parseErr != nil {
			return parseErr
		}
		scanner, scanUntil, parseErr := releaseScannerFields(c.Report)
		if parseErr != nil {
			return parseErr
		}
		_, err = t.Tx.Exec(ctx, `INSERT INTO file_releases(tenant_id,partner_id,file_id,actor_id,policy_id,policy_version,policy_hash,report_hash,released_event_id,pgp_key_id,pgp_key_version,pgp_key_hash,signature_sha256,signature_expires_at,scanner_id,scanner_version,scanner_hash,scan_expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,nullif($10,'')::uuid,nullif($11,0),nullif($12,''),nullif($13,''),$14,nullif($15,'')::uuid,nullif($16,0),nullif($17,''),$18)`, t.Scope.Tenant, t.Scope.Partner, c.FileID, t.Actor, c.PolicyID, c.PolicyVersion, c.PolicyHash, c.ReportHash, event, key.ID, key.Version, key.Hash, signatureHash, until, scanner.ID, scanner.Version, scanner.Hash, scanUntil)
	}
	return err
}
func (t *Transaction) FileAvailable(ctx context.Context, id string) error {
	if _, err := t.File(ctx, id); err != nil {
		return err
	}
	var available bool
	err := t.Tx.QueryRow(ctx, `SELECT freightctl_file_available($1,$2,$3)`, t.Scope.Tenant, t.Scope.Partner, id).Scan(&available)
	if err != nil {
		return err
	}
	if !available {
		return ErrState
	}
	return t.releasedScannerConfigurationCurrent(ctx, id)
}
func (t *Transaction) CheckBindingCurrent(ctx context.Context, c *FileCheck, storageID string) (*CheckBinding, error) {
	var b CheckBinding
	if json.Unmarshal(c.Binding, &b) != nil {
		return nil, ErrState
	}
	if b.Root != t.Root || b.Authority != t.AuthorityRevision {
		return nil, ErrUnauthorized
	}
	if b.StorageID != storageID {
		return nil, ErrState
	}
	f, err := t.File(ctx, c.FileID)
	if err != nil {
		return nil, err
	}
	if *f != b.File {
		return nil, ErrState
	}
	p, err := t.FileCheckPolicy(ctx, c)
	if err != nil {
		return nil, err
	}
	if p == nil || p.ID != c.PolicyID || p.Version != c.PolicyVersion || p.Hash != c.PolicyHash || (p.State != "active" && p.State != "output_active") {
		return nil, ErrRevision
	}
	if b.Target != nil {
		actual, err := vpath.Resolve(t.Root, b.Target.Path)
		if err != nil {
			return nil, err
		}
		if err = t.ParentWritable(ctx, actual); err != nil {
			return nil, err
		}
		parent, err := t.Entry(ctx, vpath.Parent(actual))
		if err != nil {
			return nil, err
		}
		if parent.ID != b.ParentID || parent.Revision != b.ParentRevision {
			return nil, ErrRevision
		}
		old, err := t.Entry(ctx, actual)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return nil, err
		}
		// After release, the target itself is expected to reference these exact bytes.
		if c.State == "released" {
			if old == nil || old.FileID != c.FileID {
				return nil, ErrRevision
			}
		} else if b.Target.ExpectedRevision == nil {
			if old != nil {
				return nil, ErrRevision
			}
		} else if old == nil || old.Kind != "file" || old.Revision != *b.Target.ExpectedRevision {
			return nil, ErrRevision
		}
	}
	return &b, t.Reauthorize(ctx)
}
func (t *Transaction) FileReceiptAccessible(ctx context.Context, id string) error {
	c, err := t.FileCheck(ctx, id, false)
	if errors.Is(err, ErrNotFound) {
		return t.FileAccessibleMode(ctx, id, 2)
	}
	if err != nil {
		return err
	}
	var b CheckBinding
	if json.Unmarshal(c.Binding, &b) != nil {
		return ErrState
	}
	if b.Root != t.Root || b.Authority != t.AuthorityRevision {
		return ErrUnauthorized
	}
	if b.Target != nil {
		actual, err := vpath.Resolve(t.Root, b.Target.Path)
		if err != nil {
			return err
		}
		return t.ParentWritable(ctx, actual)
	}
	return nil
}
func (t *Transaction) CheckReplay(ctx context.Context, key, meaning string) (json.RawMessage, error) {
	if _, err := t.Tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, t.Scope.Tenant+":"+t.Scope.Partner+":"+t.Actor+":check-receipt:"+key); err != nil {
		return nil, err
	}
	var hash string
	var data json.RawMessage
	err := t.Tx.QueryRow(ctx, `SELECT request_hash,result FROM check_receipts WHERE request_key=$1 AND actor_id=$2`, key, t.Actor).Scan(&hash, &data)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if hash != meaning {
		return nil, ErrConflict
	}
	return data, nil
}
func (t *Transaction) CheckReceipt(ctx context.Context, key, meaning, id string, result any) error {
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}
	event, err := t.Append(ctx, "CheckCommandCompleted", id, map[string]any{"request_key": key, "request_hash": meaning, "result": json.RawMessage(data)})
	if err != nil {
		return err
	}
	_, err = t.Tx.Exec(ctx, `INSERT INTO check_receipts VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, t.Scope.Tenant, t.Scope.Partner, t.Actor, key, meaning, id, data, event)
	return err
}

// CheckSlot separates deterministic parsing from delivery and inference. A
// retained session owns one of two non-waiting slots across all processes.
func (s *Store) CheckSlot(ctx context.Context) (func() error, func(), error) {
	conn, err := s.Pool.Acquire(ctx)
	if err != nil {
		return nil, nil, err
	}
	slot := -1
	for i := 0; i < 2; i++ {
		var ok bool
		if err = conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(721815037,$1)`, i).Scan(&ok); err != nil {
			break
		}
		if ok {
			slot = i
			break
		}
	}
	if err != nil || slot < 0 {
		conn.Release()
		if err != nil {
			return nil, nil, err
		}
		return nil, nil, ErrLimit
	}
	return func() error { return conn.Conn().Ping(ctx) }, func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if _, err := conn.Exec(cleanup, `SELECT pg_advisory_unlock(721815037,$1)`, slot); err != nil {
			_ = conn.Conn().Close(cleanup)
		}
		conn.Release()
	}, nil
}
