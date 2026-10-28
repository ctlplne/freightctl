package store

import (
	"context"

	secure "github.com/ctlplne/freightctl/internal/crypto"
)

type Identity struct {
	Tenant            string   `json:"tenant_id"`
	Partner           string   `json:"partner_id"`
	Actor             string   `json:"actor_id"`
	Permissions       []string `json:"permissions"`
	AuthorityRevision int64    `json:"authority_revision"`
	RootPolicyDigest  string   `json:"root_policy_digest"`
	SSHUsername       string   `json:"ssh_username"`
}

func (s *Store) Identity(ctx context.Context, scope Scope) (*Identity, error) {
	t, err := s.Begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	result := &Identity{Tenant: scope.Tenant, Partner: scope.Partner, Actor: t.Actor, Permissions: t.Permissions, AuthorityRevision: t.AuthorityRevision, RootPolicyDigest: secure.Digest([]byte(t.Root)), SSHUsername: scope.Tenant + "." + scope.Partner + "." + t.Actor}
	if err = t.Tx.Commit(ctx); err != nil {
		return nil, err
	}
	return result, nil
}
