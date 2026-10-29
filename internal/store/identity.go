package store

import (
	"context"

	secure "github.com/ctlplne/freightctl/internal/crypto"
)

type Identity struct {
	Tenant               string   `json:"tenant_id"`
	Partner              string   `json:"partner_id"`
	Actor                string   `json:"actor_id"`
	Permissions          []string `json:"permissions"`
	AuthorityRevision    int64    `json:"authority_revision"`
	RootPolicyDigest     string   `json:"root_policy_digest"`
	SSHUsername          string   `json:"ssh_username"`
	TenantAdministration bool     `json:"tenant_administration"`
}

func (s *Store) Identity(ctx context.Context, scope Scope) (*Identity, error) {
	t, err := s.Begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	result, err := transactionIdentity(ctx, t)
	if err != nil {
		return nil, err
	}
	if err = t.Tx.Commit(ctx); err != nil {
		return nil, err
	}
	return result, nil
}

func transactionIdentity(ctx context.Context, t *Transaction) (*Identity, error) {
	r := &Identity{Tenant: t.Scope.Tenant, Partner: t.Scope.Partner, Actor: t.Actor, Permissions: t.Permissions, AuthorityRevision: t.AuthorityRevision, RootPolicyDigest: secure.Digest([]byte(t.Root)), SSHUsername: t.Scope.Tenant + "." + t.Scope.Partner + "." + t.Actor}
	if err := t.Tx.QueryRow(ctx, `SELECT freightctl_tenant_manager($1)`, t.Scope.Tenant).Scan(&r.TenantAdministration); err != nil {
		return nil, err
	}
	return r, nil
}
