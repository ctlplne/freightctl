package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/jackc/pgx/v5"
)

var ErrDispatchApproval = errors.New("current outbound dispatch approval required")

type OutboundDispatchPolicy struct {
	ApprovalPolicyBinding
	Author  string `json:"author_id,omitempty"`
	EventID string `json:"event_id,omitempty"`
}
type OutboundDispatchEffect struct {
	Protocol             string              `json:"protocol"`
	Address              string              `json:"address"`
	User                 string              `json:"user"`
	Directory            string              `json:"directory"`
	Filename             string              `json:"filename"`
	FinalPath            string              `json:"final_path"`
	HostFingerprint      string              `json:"host_fingerprint"`
	KeyFingerprint       string              `json:"key_fingerprint"`
	KeyReferenceHash     string              `json:"key_reference_sha256"`
	Encryption           *EncryptionPolicy   `json:"encryption,omitempty"`
	RecipientFingerprint string              `json:"recipient_fingerprint"`
	Workflow             *ExecutionBinding   `json:"workflow_binding,omitempty"`
	FTPS                 *OutboundFTPSEffect `json:"ftps,omitempty"`
	DAV                  *OutboundDAVEffect  `json:"dav,omitempty"`
}

// FTPSReceiverContract records an explicitly approved receiver promise. The
// digest identifies the operator's contract document; it is not proof that a
// receiver enforces the promise. FTP itself cannot enforce consumer visibility
// or deduplication and its rename can replace an existing name.
type FTPSReceiverContract struct {
	Schema            int    `json:"schema_version"`
	DocumentSHA256    string `json:"document_sha256"`
	StagingVisibility string `json:"staging_visibility"`
	Rename            string `json:"rename"`
	Duplicates        string `json:"duplicates"`
	Receipt           string `json:"receipt"`
}

type OutboundFTPSEffect struct {
	Mode                  string               `json:"mode"`
	ServerName            string               `json:"server_name"`
	CASHA256              string               `json:"ca_sha256"`
	CAReferenceHash       string               `json:"ca_reference_sha256"`
	PasswordReferenceHash string               `json:"password_reference_sha256"`
	StagingPath           string               `json:"staging_path"`
	ReceiverContract      FTPSReceiverContract `json:"receiver_contract"`
}

// A receiver contract identifies an explicit operator promise,not proof that
// the server hides stage bytes or deduplicates downstream business effects.
type DAVReceiverContract struct {
	Schema            int    `json:"schema_version"`
	DocumentSHA256    string `json:"document_sha256"`
	StagingVisibility string `json:"staging_visibility"`
	Put               string `json:"put"`
	Move              string `json:"move"`
	Duplicates        string `json:"duplicates"`
	Receipt           string `json:"receipt"`
}

type OutboundDAVEffect struct {
	Profile               string              `json:"profile"`
	Authentication        string              `json:"authentication"`
	ServerName            string              `json:"server_name"`
	CASHA256              string              `json:"ca_sha256"`
	CAReferenceHash       string              `json:"ca_reference_sha256"`
	TokenReferenceHash    string              `json:"token_reference_sha256,omitempty"`
	PasswordReferenceHash string              `json:"password_reference_sha256,omitempty"`
	StagingPath           string              `json:"staging_path"`
	ReceiverContract      DAVReceiverContract `json:"receiver_contract"`
}
type OutboundDispatchDefinition struct {
	Schema            int                    `json:"schema_version"`
	Author            string                 `json:"author_id"`
	Authority         int64                  `json:"authority_revision"`
	Reviewer          string                 `json:"reviewer_id"`
	ReviewerAuthority int64                  `json:"reviewer_authority_revision"`
	Policy            ApprovalPolicyBinding  `json:"policy"`
	DeliveryID        string                 `json:"delivery_id"`
	DeliveryRevision  int64                  `json:"delivery_revision"`
	DeliveryHash      string                 `json:"delivery_hash"`
	Source            File                   `json:"source"`
	StorageID         string                 `json:"storage_id"`
	Root              string                 `json:"namespace_root"`
	Effect            OutboundDispatchEffect `json:"effect"`
	AttemptLimit      int                    `json:"attempt_limit"`
}
type OutboundDispatchSummary struct {
	ID         string    `json:"id"`
	Author     string    `json:"author_id"`
	Reviewer   string    `json:"reviewer_id"`
	DeliveryID string    `json:"delivery_id"`
	Hash       string    `json:"definition_hash"`
	State      string    `json:"state"`
	Revision   int64     `json:"revision"`
	CreatedAt  time.Time `json:"created_at"`
	EventID    string    `json:"changed_event_id"`
}
type OutboundDispatchReview struct {
	OutboundDispatchSummary
	Definition OutboundDispatchDefinition `json:"definition"`
}
type OutboundDispatchPage struct {
	Reviews []OutboundDispatchSummary `json:"reviews"`
	Next    string                    `json:"next,omitempty"`
}

func (t *Transaction) OutboundDispatchPolicy(ctx context.Context) (*OutboundDispatchPolicy, error) {
	if _, err := t.Tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0))`, t.Scope.Tenant+":"+t.Scope.Partner+":outbound-dispatch-policy"); err != nil {
		return nil, err
	}
	p := &OutboundDispatchPolicy{ApprovalPolicyBinding: ApprovalPolicyBinding{Mode: "author"}}
	err := t.Tx.QueryRow(ctx, `SELECT revision,mode,actor_id::text,event_id::text FROM outbound_dispatch_policies WHERE tenant_id=$1 AND partner_id=$2 ORDER BY revision DESC LIMIT 1`, t.Scope.Tenant, t.Scope.Partner).Scan(&p.Revision, &p.Mode, &p.Author, &p.EventID)
	if errors.Is(err, pgx.ErrNoRows) {
		return p, nil
	}
	return p, err
}
func (t *Transaction) SaveOutboundDispatchPolicy(ctx context.Context, p *OutboundDispatchPolicy) error {
	e, err := t.Append(ctx, "OutboundDispatchPolicyChanged", t.Scope.Partner, p)
	if err != nil {
		return err
	}
	p.EventID = e
	_, err = t.Tx.Exec(ctx, `INSERT INTO outbound_dispatch_policies VALUES($1,$2,$3,$4,$5,$6)`, t.Scope.Tenant, t.Scope.Partner, p.Revision, p.Mode, t.Actor, e)
	return err
}
func (t *Transaction) OutboundDispatchReviewer(ctx context.Context, id string) (int64, error) {
	var rev int64
	err := t.Tx.QueryRow(ctx, `SELECT authority_revision FROM credentials WHERE tenant_id=$1 AND partner_id=$2 AND actor_id=$3 AND namespace_root='/' AND permissions @> ARRAY['inspect','workflow_approve']::text[] AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>clock_timestamp())`, t.Scope.Tenant, t.Scope.Partner, id).Scan(&rev)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrNotFound
	}
	return rev, err
}
func (t *Transaction) CheckOutboundDispatch(ctx context.Context, id string) error {
	var current bool
	err := t.Tx.QueryRow(ctx, `SELECT freightctl_outbound_dispatch_current($1,$2,$3,$4)`, t.Scope.Tenant, t.Scope.Partner, t.Actor, id).Scan(&current)
	if err == nil && !current {
		return ErrDispatchApproval
	}
	return err
}
func (t *Transaction) OutboundDispatchReview(ctx context.Context, id string, lock bool) (*OutboundDispatchReview, error) {
	if !ValidID(id) {
		return nil, ErrNotFound
	}
	q := `SELECT review_id::text,actor_id::text,reviewer_id::text,delivery_id::text,definition_hash,state,revision,created_at,changed_event_id::text,definition FROM outbound_dispatch_reviews WHERE tenant_id=$1 AND partner_id=$2 AND review_id=$3 AND (actor_id=$4 OR reviewer_id=$4)`
	if lock {
		q += ` FOR UPDATE`
	}
	var r OutboundDispatchReview
	var data []byte
	err := t.Tx.QueryRow(ctx, q, t.Scope.Tenant, t.Scope.Partner, id, t.Actor).Scan(&r.ID, &r.Author, &r.Reviewer, &r.DeliveryID, &r.Hash, &r.State, &r.Revision, &r.CreatedAt, &r.EventID, &data)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if json.Unmarshal(data, &r.Definition) != nil {
		return nil, ErrIsolation
	}
	b, err := json.Marshal(r.Definition)
	if err != nil || secure.Digest(b) != r.Hash || r.Definition.Author != r.Author || r.Definition.Reviewer != r.Reviewer || r.Definition.DeliveryID != r.DeliveryID || !validOutboundDispatchProtocol(r.Definition.Schema, r.Definition.Effect) {
		return nil, ErrIsolation
	}
	r.CreatedAt = r.CreatedAt.UTC()
	return &r, nil
}

func validOutboundDispatchProtocol(schema int, effect OutboundDispatchEffect) bool {
	if schema == 3 {
		return effect.Protocol == "webdav" && effect.DAV != nil && effect.FTPS == nil && effect.Encryption == nil && effect.Workflow == nil
	}
	if schema == 1 {
		return effect.Protocol == "sftp" && effect.FTPS == nil && effect.DAV == nil
	}
	return schema == 2 && effect.Protocol == "ftps" && effect.FTPS != nil && effect.DAV == nil
}
func (t *Transaction) SaveOutboundDispatchReview(ctx context.Context, r *OutboundDispatchReview, previous int64) error {
	e, err := t.Append(ctx, "OutboundDispatchReviewChanged", r.ID, r)
	if err != nil {
		return err
	}
	r.EventID = e
	if previous == 0 {
		d, err := json.Marshal(r.Definition)
		if err != nil {
			return err
		}
		_, err = t.Tx.Exec(ctx, `INSERT INTO outbound_dispatch_reviews VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, t.Scope.Tenant, t.Scope.Partner, r.Author, r.ID, r.Reviewer, r.DeliveryID, d, r.Hash, r.State, r.Revision, r.CreatedAt, e, r.Definition.Policy.Revision)
		return err
	}
	tag, err := t.Tx.Exec(ctx, `UPDATE outbound_dispatch_reviews SET state=$1,revision=$2,changed_event_id=$3 WHERE tenant_id=$4 AND partner_id=$5 AND review_id=$6 AND revision=$7`, r.State, r.Revision, e, t.Scope.Tenant, t.Scope.Partner, r.ID, previous)
	if err == nil && tag.RowsAffected() != 1 {
		return ErrRevision
	}
	return err
}
func (t *Transaction) OutboundDispatchReviews(ctx context.Context, after string, limit int) (*OutboundDispatchPage, error) {
	if (after != "" && !ValidID(after)) || limit < 1 || limit > 100 {
		return nil, ErrLimit
	}
	rows, err := t.Tx.Query(ctx, `SELECT review_id::text,actor_id::text,reviewer_id::text,delivery_id::text,definition_hash,state,revision,created_at,changed_event_id::text FROM outbound_dispatch_reviews WHERE tenant_id=$1 AND partner_id=$2 AND (actor_id=$3 OR reviewer_id=$3) AND ($4='' OR review_id>nullif($4,'')::uuid) ORDER BY review_id LIMIT $5`, t.Scope.Tenant, t.Scope.Partner, t.Actor, after, limit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	page := &OutboundDispatchPage{Reviews: []OutboundDispatchSummary{}}
	for rows.Next() {
		var r OutboundDispatchSummary
		if err = rows.Scan(&r.ID, &r.Author, &r.Reviewer, &r.DeliveryID, &r.Hash, &r.State, &r.Revision, &r.CreatedAt, &r.EventID); err != nil {
			return nil, err
		}
		r.CreatedAt = r.CreatedAt.UTC()
		page.Reviews = append(page.Reviews, r)
	}
	if len(page.Reviews) > limit {
		page.Next = page.Reviews[limit-1].ID
		page.Reviews = page.Reviews[:limit]
	}
	return page, rows.Err()
}
