package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

var ErrCollection = errors.New("current collection authority, exact input and live execution lease required")

type CollectionJob struct {
	ID              string          `json:"id"`
	WorkflowID      string          `json:"workflow_id"`
	WorkflowVersion int             `json:"workflow_version"`
	WorkflowHash    string          `json:"workflow_hash"`
	Definition      json.RawMessage `json:"definition"`
	Hash            string          `json:"definition_hash"`
	State           string          `json:"state"`
	Captured        bool            `json:"captured"`
	Revision        int64           `json:"revision"`
	Fence           int64           `json:"fence"`
	Attempts        int             `json:"attempts"`
	Owner           string          `json:"lease_owner"`
	Until           *time.Time      `json:"lease_until"`
	Next            time.Time       `json:"next_at"`
	Created         time.Time       `json:"created_at"`
	Deadline        time.Time       `json:"deadline_at"`
	Manifest        json.RawMessage `json:"manifest"`
	ManifestHash    *string         `json:"manifest_hash"`
	Reason          string          `json:"reason"`
}
type CollectionBatch struct {
	ID             string          `json:"id"`
	JobID          string          `json:"job_id"`
	WorkflowID     string          `json:"workflow_id"`
	SourceIdentity string          `json:"source_identity"`
	ProducerID     string          `json:"producer_batch_id"`
	Hash           string          `json:"manifest_hash"`
	Manifest       json.RawMessage `json:"manifest"`
}
type CollectionInput struct {
	ID             string  `json:"id"`
	JobID          string  `json:"first_job_id"`
	WorkflowID     string  `json:"workflow_id"`
	SourceIdentity string  `json:"source_identity"`
	Identity       string  `json:"input_identity"`
	Name           string  `json:"source_name"`
	Size           int64   `json:"size_bytes"`
	SHA256         string  `json:"sha256"`
	Target         string  `json:"target_path"`
	ObjectID       string  `json:"object_id"`
	State          string  `json:"state"`
	Revision       int64   `json:"revision"`
	Fence          int64   `json:"capture_fence"`
	Owner          string  `json:"capture_owner"`
	FileID         *string `json:"file_id"`
	RunID          *string `json:"run_id"`
}
type CollectionPage struct {
	Jobs []CollectionJob `json:"jobs"`
	Next string          `json:"next,omitempty"`
}

const collectionJobColumns = `id::text,workflow_id::text,workflow_version,workflow_hash,definition,definition_hash,state,revision,fence,attempts,coalesce(lease_owner::text,''),lease_until,next_at,created_at,deadline_at,manifest,manifest_hash,reason,captured`
const collectionInputColumns = `i.id::text,i.first_job_id::text,i.workflow_id::text,i.source_identity,i.input_identity,i.source_name,i.size_bytes,i.sha256,i.target_path,i.object_id::text,i.state,i.revision,i.capture_fence,i.capture_owner::text,i.file_id::text,i.run_id::text`

type collectionScanner interface{ Scan(...any) error }

func scanCollectionJob(row collectionScanner) (*CollectionJob, error) {
	j := &CollectionJob{}
	e := row.Scan(&j.ID, &j.WorkflowID, &j.WorkflowVersion, &j.WorkflowHash, &j.Definition, &j.Hash, &j.State, &j.Revision, &j.Fence, &j.Attempts, &j.Owner, &j.Until, &j.Next, &j.Created, &j.Deadline, &j.Manifest, &j.ManifestHash, &j.Reason, &j.Captured)
	if errors.Is(e, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if e != nil {
		return nil, e
	}
	j.Next = j.Next.UTC()
	j.Created = j.Created.UTC()
	j.Deadline = j.Deadline.UTC()
	if j.Until != nil {
		until := j.Until.UTC()
		j.Until = &until
	}
	return j, nil
}
func scanCollectionInput(row collectionScanner) (*CollectionInput, error) {
	i := &CollectionInput{}
	e := row.Scan(&i.ID, &i.JobID, &i.WorkflowID, &i.SourceIdentity, &i.Identity, &i.Name, &i.Size, &i.SHA256, &i.Target, &i.ObjectID, &i.State, &i.Revision, &i.Fence, &i.Owner, &i.FileID, &i.RunID)
	if errors.Is(e, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return i, e
}
func (t *Transaction) CollectionLock(ctx context.Context, exclusive bool) error {
	name := "pg_advisory_xact_lock_shared"
	if exclusive {
		name = "pg_advisory_xact_lock"
	}
	_, e := t.Tx.Exec(ctx, `SELECT `+name+`(hashtextextended($1,0))`, t.Scope.Tenant+":"+t.Scope.Partner+":workflow-collections")
	return e
}
func (s *Store) CollectionWorkerSlot(ctx context.Context) (func() error, func(), error) {
	return s.encryptionLock(ctx, 721815043, true)
}
func (t *Transaction) CollectionDefinitionCurrent(ctx context.Context, definition json.RawMessage) error {
	var ok bool
	e := t.Tx.QueryRow(ctx, `SELECT freightctl_collection_definition_current($1,$2,$3,$4)`, t.Scope.Tenant, t.Scope.Partner, t.Actor, definition).Scan(&ok)
	if e == nil && !ok {
		return ErrCollection
	}
	return e
}
func (t *Transaction) CheckCollectionBinding(ctx context.Context, run string) error {
	var ok bool
	e := t.Tx.QueryRow(ctx, `SELECT freightctl_collected_run_current($1,$2,$3,$4)`, t.Scope.Tenant, t.Scope.Partner, t.Actor, run).Scan(&ok)
	if e == nil && !ok {
		return ErrCollection
	}
	return e
}
func (t *Transaction) CollectionBindingStatus(ctx context.Context, run string) error {
	var ok bool
	e := t.Tx.QueryRow(ctx, `SELECT freightctl_collected_run_status($1,$2,$3,$4)`, t.Scope.Tenant, t.Scope.Partner, t.Actor, run).Scan(&ok)
	if e == nil && !ok {
		return ErrCollection
	}
	return e
}
func (t *Transaction) Collection(ctx context.Context, id string, lock bool) (*CollectionJob, error) {
	if !ValidID(id) {
		return nil, ErrNotFound
	}
	q := `SELECT ` + collectionJobColumns + ` FROM workflow_collection_jobs WHERE id=$1 AND actor_id=$2`
	if lock {
		q += ` FOR UPDATE`
	}
	return scanCollectionJob(t.Tx.QueryRow(ctx, q, id, t.Actor))
}
func (t *Transaction) SaveCollection(ctx context.Context, j *CollectionJob, previous int64) error {
	event, e := t.Append(ctx, "WorkflowCollectionChanged", j.ID, j)
	if e != nil {
		return e
	}
	if previous == 0 {
		_, e = t.Tx.Exec(ctx, `INSERT INTO workflow_collection_jobs(tenant_id,partner_id,actor_id,id,workflow_id,workflow_version,workflow_hash,definition,definition_hash,state,revision,fence,attempts,lease_owner,lease_until,next_at,created_at,deadline_at,manifest,manifest_hash,reason,changed_event_id,captured) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,nullif($14,'')::uuid,$15,$16,$17,$18,$19,$20,$21,$22,$23)`, t.Scope.Tenant, t.Scope.Partner, t.Actor, j.ID, j.WorkflowID, j.WorkflowVersion, j.WorkflowHash, j.Definition, j.Hash, j.State, j.Revision, j.Fence, j.Attempts, j.Owner, j.Until, j.Next, j.Created, j.Deadline, j.Manifest, j.ManifestHash, j.Reason, event, j.Captured)
		return e
	}
	tag, e := t.Tx.Exec(ctx, `UPDATE workflow_collection_jobs SET state=$1,revision=$2,fence=$3,attempts=$4,lease_owner=nullif($5,'')::uuid,lease_until=$6,next_at=$7,manifest=$8,manifest_hash=$9,reason=$10,changed_event_id=$11,captured=$15 WHERE id=$12 AND actor_id=$13 AND revision=$14`, j.State, j.Revision, j.Fence, j.Attempts, j.Owner, j.Until, j.Next, j.Manifest, j.ManifestHash, j.Reason, event, j.ID, t.Actor, previous, j.Captured)
	if e == nil && tag.RowsAffected() != 1 {
		return ErrRevision
	}
	return e
}
func (t *Transaction) Collections(ctx context.Context, after string, limit int) (*CollectionPage, error) {
	if limit < 1 || limit > 100 || (after != "" && !ValidID(after)) {
		return nil, ErrLimit
	}
	rows, e := t.Tx.Query(ctx, `SELECT `+collectionJobColumns+` FROM workflow_collection_jobs WHERE actor_id=$1 AND ($2='' OR id>nullif($2,'')::uuid) ORDER BY id LIMIT $3`, t.Actor, after, limit+1)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	p := &CollectionPage{Jobs: []CollectionJob{}}
	for rows.Next() {
		j, e := scanCollectionJob(rows)
		if e != nil {
			return nil, e
		}
		p.Jobs = append(p.Jobs, *j)
	}
	if e = rows.Err(); e != nil {
		return nil, e
	}
	if len(p.Jobs) > limit {
		p.Jobs = p.Jobs[:limit]
		p.Next = p.Jobs[limit-1].ID
	}
	return p, nil
}
func (t *Transaction) CollectionAdmission(ctx context.Context, workflow string) error {
	var n int
	e := t.Tx.QueryRow(ctx, `SELECT count(*) FROM workflow_collection_jobs WHERE actor_id=$1 AND state IN ('queued','reading','retry')`, t.Actor).Scan(&n)
	if e != nil {
		return e
	}
	if n >= 128 {
		return ErrLimit
	}
	var exists bool
	e = t.Tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM workflow_collection_jobs WHERE actor_id=$1 AND workflow_id=$2 AND state IN ('queued','reading','retry'))`, t.Actor, workflow).Scan(&exists)
	if e == nil && exists {
		return ErrCollection
	}
	return e
}
func (t *Transaction) CollectionBatch(ctx context.Context, workflow, source, producer string) (*CollectionBatch, error) {
	b := &CollectionBatch{}
	e := t.Tx.QueryRow(ctx, `SELECT id::text,job_id::text,workflow_id::text,source_identity,producer_batch_id::text,manifest_hash,manifest FROM workflow_collection_batches WHERE actor_id=$1 AND workflow_id=$2 AND source_identity=$3 AND producer_batch_id=$4`, t.Actor, workflow, source, producer).Scan(&b.ID, &b.JobID, &b.WorkflowID, &b.SourceIdentity, &b.ProducerID, &b.Hash, &b.Manifest)
	if errors.Is(e, pgx.ErrNoRows) {
		return nil, nil
	}
	return b, e
}
func (t *Transaction) SaveCollectionBatch(ctx context.Context, b *CollectionBatch) error {
	event, e := t.Append(ctx, "WorkflowCollectionBatch", b.ID, b)
	if e != nil {
		return e
	}
	_, e = t.Tx.Exec(ctx, `INSERT INTO workflow_collection_batches VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, t.Scope.Tenant, t.Scope.Partner, t.Actor, b.ID, b.JobID, b.WorkflowID, b.SourceIdentity, b.ProducerID, b.Hash, b.Manifest, event)
	return e
}
func (t *Transaction) CollectionInput(ctx context.Context, id string, lock bool) (*CollectionInput, error) {
	if !ValidID(id) {
		return nil, ErrNotFound
	}
	q := `SELECT ` + collectionInputColumns + ` FROM workflow_collection_inputs i WHERE i.actor_id=$1 AND i.id=$2`
	if lock {
		q += ` FOR UPDATE OF i`
	}
	return scanCollectionInput(t.Tx.QueryRow(ctx, q, t.Actor, id))
}
func (t *Transaction) CollectionInputIdentity(ctx context.Context, workflow, identity string) (*CollectionInput, error) {
	i, e := scanCollectionInput(t.Tx.QueryRow(ctx, `SELECT `+collectionInputColumns+` FROM workflow_collection_inputs i WHERE i.actor_id=$1 AND i.workflow_id=$2 AND i.input_identity=$3`, t.Actor, workflow, identity))
	if errors.Is(e, ErrNotFound) {
		return nil, nil
	}
	return i, e
}
func (t *Transaction) CollectionInputs(ctx context.Context, j *CollectionJob) ([]CollectionInput, error) {
	if j.Manifest == nil {
		return []CollectionInput{}, nil
	}
	rows, e := t.Tx.Query(ctx, `SELECT `+collectionInputColumns+` FROM jsonb_array_elements($1::jsonb->'files') WITH ORDINALITY q(value,ordinal) JOIN workflow_collection_inputs i ON i.source_identity=$2 AND i.workflow_id=$3 AND i.actor_id=$4 AND (i.source_name,i.size_bytes,i.sha256)=(q.value->>'name',(q.value->>'size_bytes')::bigint,q.value->>'sha256') ORDER BY q.ordinal`, j.Manifest, stringFromJSON(j.Definition, "source_identity"), j.WorkflowID, t.Actor)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []CollectionInput{}
	for rows.Next() {
		i, e := scanCollectionInput(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, *i)
	}
	return out, rows.Err()
}
func stringFromJSON(data json.RawMessage, key string) string {
	var d map[string]json.RawMessage
	var s string
	if json.Unmarshal(data, &d) == nil {
		_ = json.Unmarshal(d[key], &s)
	}
	return s
}
func (t *Transaction) SaveCollectionInput(ctx context.Context, i *CollectionInput, previous int64) error {
	event, e := t.Append(ctx, "WorkflowCollectionInput", i.ID, i)
	if e != nil {
		return e
	}
	if previous == 0 {
		_, e = t.Tx.Exec(ctx, `INSERT INTO workflow_collection_inputs VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)`, t.Scope.Tenant, t.Scope.Partner, t.Actor, i.ID, i.JobID, i.WorkflowID, i.SourceIdentity, i.Identity, i.Name, i.Size, i.SHA256, i.Target, i.ObjectID, i.State, i.Revision, i.Fence, i.Owner, i.FileID, i.RunID, event)
		return e
	}
	tag, e := t.Tx.Exec(ctx, `UPDATE workflow_collection_inputs SET object_id=$1,state=$2,revision=$3,capture_fence=$4,capture_owner=$5,file_id=$6,run_id=$7,changed_event_id=$8 WHERE id=$9 AND actor_id=$10 AND revision=$11`, i.ObjectID, i.State, i.Revision, i.Fence, i.Owner, i.FileID, i.RunID, event, i.ID, t.Actor, previous)
	if e == nil && tag.RowsAffected() != 1 {
		return ErrRevision
	}
	return e
}
