package workflow

import (
	"context"
	"encoding/json"
	"time"

	"github.com/ctlplne/freightctl/internal/store"
)

type ConnectionProvisionRecipientPage struct {
	Recipients []store.ConnectionProvisionRecipient `json:"recipients"`
	Next       string                               `json:"next,omitempty"`
}

type ConnectionProvisionAssignmentPage struct {
	Assignments []ConnectionProvisionReceipt `json:"assignments"`
	Next        string                       `json:"next,omitempty"`
}

// Provisioning choices expose either the operator's own sources and journal
// decisions or the minimal current recipient identity needed for the command.
// The assignment journal does not read the recipient's connection catalog.
func (s *Service) ConnectionProvisionChoices(ctx context.Context, scope store.Scope, kind, after string, limit int) (any, error) {
	if (after != "" && !store.ValidID(after)) || limit < 1 || limit > 100 {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.begin(ctx, scope, "admin", "connections_manage")
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if err = t.ConnectionAuthorityFence(ctx); err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	var page any
	switch kind {
	case "sources":
		page, err = listActiveConnections(ctx, t, after, limit, true)
	case "recipients":
		var rows []store.ConnectionProvisionRecipient
		rows, err = t.ConnectionProvisionRecipients(ctx, after, limit+1)
		p := ConnectionProvisionRecipientPage{Recipients: rows}
		if len(rows) > limit {
			p.Recipients, p.Next = rows[:limit], rows[limit-1].ID
		}
		page = p
	case "assignments":
		page, err = listConnectionProvisionAssignments(ctx, t, after, limit)
	default:
		return nil, ErrInput
	}
	if err != nil {
		return nil, err
	}
	return page, t.Tx.Commit(ctx)
}

func listConnectionProvisionAssignments(ctx context.Context, t *store.Transaction, after string, limit int) (*ConnectionProvisionAssignmentPage, error) {
	rows, err := t.Tx.Query(ctx, `SELECT DISTINCT ON(resource_id) resource_id::text,event_id::text,payload->'provision' FROM events
		WHERE (tenant_id,partner_id,actor_id)=($1,$2,$3) AND kind='OperatorConnectionChanged'
		AND ($4='' OR resource_id>nullif($4,'')::uuid)
		ORDER BY resource_id,payload->'provision'->>'revision' DESC LIMIT $5`, t.Scope.Tenant, t.Scope.Partner, t.Actor, after, limit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	page := &ConnectionProvisionAssignmentPage{Assignments: []ConnectionProvisionReceipt{}}
	for rows.Next() {
		var resource, event string
		var raw []byte
		if err = rows.Scan(&resource, &event, &raw); err != nil {
			return nil, err
		}
		var receipt ConnectionProvisionReceipt
		if json.Unmarshal(raw, &receipt) != nil || receipt.Profile != operatorConnectionProfile ||
			receipt.EventID != "" || receipt.Connection.ID != resource || receipt.Operator != t.Actor {
			return nil, store.ErrIsolation
		}
		receipt.EventID = event
		page.Assignments = append(page.Assignments, receipt)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if len(page.Assignments) > limit {
		page.Assignments = page.Assignments[:limit]
		page.Next = page.Assignments[limit-1].Connection.ID
	}
	return page, nil
}
