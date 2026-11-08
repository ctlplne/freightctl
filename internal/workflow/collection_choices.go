package workflow

import (
	"context"
	"time"

	"github.com/ctlplne/freightctl/internal/store"
)

type CollectionConnectionPage struct {
	Connections []ConnectionView `json:"connections"`
	Next        string           `json:"next,omitempty"`
}

func (s *Service) CollectionConnections(ctx context.Context, scope store.Scope, after string, limit int) (*CollectionConnectionPage, error) {
	if (after != "" && !store.ValidID(after)) || limit < 1 || limit > 100 {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, e := s.collectionRead(ctx, scope)
	if e != nil {
		return nil, e
	}
	defer t.Tx.Rollback(ctx)
	rows, e := t.Tx.Query(ctx, `SELECT c.connection_id::text,c.version,c.definition,c.definition_hash,c.state,c.revision FROM connection_revisions c WHERE c.actor_id=$1 AND c.state='active' AND ($2='' OR c.connection_id>nullif($2,'')::uuid) AND c.version=(SELECT max(v.version) FROM connection_revisions v WHERE v.actor_id=$1 AND v.connection_id=c.connection_id AND v.state='active') ORDER BY c.connection_id LIMIT $3`, t.Actor, after, limit+1)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	p := &CollectionConnectionPage{Connections: []ConnectionView{}}
	for rows.Next() {
		c := &store.Configuration{}
		if e = rows.Scan(&c.ID, &c.Version, &c.Definition, &c.Hash, &c.State, &c.Revision); e != nil {
			return nil, e
		}
		v, e := viewConnection(c)
		if e != nil {
			return nil, e
		}
		p.Connections = append(p.Connections, v)
	}
	if e = rows.Err(); e != nil {
		return nil, e
	}
	if len(p.Connections) > limit {
		p.Connections = p.Connections[:limit]
		p.Next = p.Connections[limit-1].ID
	}
	return p, t.Tx.Commit(ctx)
}
func (s *Service) CollectionWorkflows(ctx context.Context, scope store.Scope, after string, limit int) (*SchedulableWorkflowPage, error) {
	if (after != "" && !store.ValidID(after)) || limit < 1 || limit > 100 {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, e := s.collectionRead(ctx, scope)
	if e != nil {
		return nil, e
	}
	defer t.Tx.Rollback(ctx)
	rows, e := t.Tx.Query(ctx, `SELECT w.workflow_id::text,w.version,w.definition_hash,w.definition->>'name' FROM workflow_revisions w WHERE w.actor_id=$1 AND w.definition->'source'->>'kind' IN ('sftp.collect','ftps.collect','local.collect','webdav.collect') AND ($2='' OR w.workflow_id>nullif($2,'')::uuid) AND w.version=(SELECT max(v.version) FROM workflow_revisions v WHERE v.actor_id=$1 AND v.workflow_id=w.workflow_id) ORDER BY w.workflow_id LIMIT $3`, t.Actor, after, limit+1)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	p := &SchedulableWorkflowPage{Workflows: []SchedulableWorkflow{}}
	for rows.Next() {
		var w SchedulableWorkflow
		if e = rows.Scan(&w.ID, &w.Version, &w.Hash, &w.Name); e != nil {
			return nil, e
		}
		p.Workflows = append(p.Workflows, w)
	}
	if e = rows.Err(); e != nil {
		return nil, e
	}
	if len(p.Workflows) > limit {
		p.Workflows = p.Workflows[:limit]
		p.Next = p.Workflows[limit-1].ID
	}
	return p, t.Tx.Commit(ctx)
}
