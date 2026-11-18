package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

const operatorConnectionProfile = "operator-provisioned-connection-v1"

type ConnectionProvisionCommand struct {
	Operation          string     `json:"operation"`
	Recipient          string     `json:"recipient_actor_id,omitempty"`
	RecipientAuthority int64      `json:"recipient_authority_revision,omitempty"`
	Source             *Reference `json:"source,omitempty"`
	Connection         *Reference `json:"connection,omitempty"`
	ProvisionEvent     string     `json:"provision_event_id,omitempty"`
}

type ConnectionProvisionReceipt struct {
	Profile            string    `json:"profile"`
	Operation          string    `json:"operation"`
	Operator           string    `json:"operator_actor_id"`
	OperatorAuthority  int64     `json:"operator_authority_revision"`
	Recipient          string    `json:"recipient_actor_id"`
	RecipientAuthority int64     `json:"recipient_authority_revision"`
	Source             Reference `json:"source"`
	Connection         Reference `json:"connection"`
	State              string    `json:"state"`
	Revision           int64     `json:"revision"`
	ProvisionEvent     string    `json:"provision_event_id,omitempty"`
	EventID            string    `json:"event_id,omitempty"`
}

func (c ConnectionProvisionCommand) valid() bool {
	exact := func(r *Reference) bool {
		return r != nil && store.ValidID(r.ID) && r.Version > 0 && r.Version <= 2147483647 && hashPattern.MatchString(r.Hash)
	}
	switch c.Operation {
	case "provision":
		return exact(c.Source) && store.ValidID(c.Recipient) && c.RecipientAuthority > 0 && c.Connection == nil && c.ProvisionEvent == ""
	case "revoke":
		return exact(c.Connection) && c.Connection.Version == 1 && store.ValidID(c.ProvisionEvent) && c.Source == nil && c.Recipient == "" && c.RecipientAuthority == 0
	default:
		return false
	}
}

// ProvisionConnection records an operator decision and projects a new ordinary
// SFTP registration for a named existing actor. It never authenticates as that
// actor or changes anyone's credential. Only the projection trigger can write
// the other actor's row, in the same transaction as the original receipt.
func (s *Service) ProvisionConnection(ctx context.Context, scope store.Scope, key string, c ConnectionProvisionCommand) (*Result, error) {
	if !keyPattern.MatchString(key) || !c.valid() {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.begin(ctx, scope, "admin", "connections_manage")
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	_, meaning, err := digest(struct {
		Profile string                     `json:"profile"`
		Command ConnectionProvisionCommand `json:"command"`
	}{operatorConnectionProfile, c})
	if err != nil {
		return nil, err
	}
	if prior, err := replay(t, ctx, key, meaning); err != nil || prior != nil {
		return prior, err
	}
	if err = t.ConnectionAuthorityFence(ctx); err != nil {
		return nil, provisionError(err)
	}
	var recorded ConnectionProvisionReceipt
	if c.Operation == "provision" {
		if c.Recipient == t.Actor {
			return nil, ErrInput
		}
		source, err := t.Configuration(ctx, true, c.Source.ID, c.Source.Version, false)
		if err != nil {
			return nil, err
		}
		if source.Hash != c.Source.Hash {
			return nil, store.ErrRevision
		}
		d, err := connectionDefinition(source)
		if err != nil || source.State != "active" || d.Schema != 1 {
			return nil, store.ErrState
		}
		if err = t.CheckConnectionProvisionRecipient(ctx, c.Recipient, c.RecipientAuthority); err != nil {
			return nil, err
		}
		recorded = ConnectionProvisionReceipt{
			Profile: operatorConnectionProfile, Operation: c.Operation, Operator: t.Actor,
			Recipient: c.Recipient, RecipientAuthority: c.RecipientAuthority, Source: *c.Source,
			Connection: Reference{ID: secure.NewID(), Version: 1, Hash: source.Hash}, State: "active", Revision: 1,
		}
	} else {
		original, err := t.OwnConnectionProvision(ctx, c.ProvisionEvent, c.Connection.ID)
		if err != nil {
			return nil, err
		}
		if json.Unmarshal(original, &recorded) != nil || recorded.Profile != operatorConnectionProfile ||
			recorded.Operator != t.Actor || recorded.Operation != "provision" || recorded.State != "active" || recorded.Revision != 1 {
			return nil, store.ErrIsolation
		}
		if recorded.Connection != *c.Connection {
			return nil, store.ErrRevision
		}
		recorded.Operation, recorded.State, recorded.Revision = c.Operation, "revoked", 2
		recorded.ProvisionEvent = c.ProvisionEvent
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	recorded.OperatorAuthority = t.AuthorityRevision
	recorded.EventID, err = t.Append(ctx, "OperatorConnectionChanged", recorded.Connection.ID, map[string]any{
		"request_key": key, "request_hash": meaning, "provision": recorded,
	})
	if err != nil {
		return nil, provisionError(err)
	}
	out, err := result(t, ctx, key, meaning, recorded.Connection.ID, recorded)
	return out, provisionError(err)
}

func provisionError(err error) error {
	var sql interface{ SQLState() string }
	if errors.As(err, &sql) {
		switch sql.SQLState() {
		case "42501":
			return store.ErrForbidden
		case "40001":
			return store.ErrRevision
		case "55000":
			return store.ErrState
		case "23514":
			return store.ErrIsolation
		}
	}
	return err
}
