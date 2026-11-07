package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/vpath"
	"github.com/jackc/pgx/v5"
)

// ValidNamespaceRequestKey uses the existing mutation-key grammar.
func ValidNamespaceRequestKey(key string) bool { return operationKey.MatchString(key) }

// Keep the original command meaning byte-for-byte,including mount authority,
// canonical paths,omitted default options and microsecond UTC timestamps.
func (t *Transaction) pathCommandMeaning(command PathCommand) (PathCommand, string, string, error) {
	virtual, err := vpath.Canonical(command.Path)
	if err != nil {
		return command, "", "", err
	}
	command.Path = virtual
	if vpath.ControlPath(virtual) || vpath.ControlPath(command.Target) {
		return command, "", "", ErrForbidden
	}
	if virtual == "/" {
		return command, "", "", ErrForbidden
	}
	actual, err := vpath.Resolve(t.Root, virtual)
	if err != nil {
		return command, "", "", err
	}
	if command.Target != "" {
		target, err := vpath.Canonical(command.Target)
		if err != nil {
			return command, "", "", err
		}
		command.Target = target
		if command.Operation == "copy" && command.Target == virtual {
			return command, "", "", ErrForbidden
		}
	}
	if command.Mode != nil && *command.Mode > 0777 {
		return command, "", "", ErrState
	}
	if command.Modified != nil {
		normalized := command.Modified.UTC().Truncate(time.Microsecond)
		command.Modified = &normalized
	}
	meaningBytes, err := json.Marshal(struct {
		Root      string
		Authority int64
		Command   PathCommand
	}{t.Root, t.AuthorityRevision, command})
	if err != nil {
		return command, "", "", err
	}
	meaning := secure.Digest(meaningBytes)
	return command, actual, meaning, nil
}

// PathCommandReceipt describes the old committed transaction,never current
// namespace,byte availability,delivery,forwarding or execution authority.
type PathCommandReceipt struct {
	Profile          string     `json:"profile"`
	Observation      string     `json:"observation"`
	RequestKey       string     `json:"request_key"`
	RequestHash      string     `json:"request_hash"`
	CompletedEventID string     `json:"completed_event_id"`
	Result           PathResult `json:"result"`
}

func (t *Transaction) ReadPathCommandReceipt(ctx context.Context, key string, command PathCommand) (*PathCommandReceipt, error) {
	if !ValidNamespaceRequestKey(key) {
		return nil, ErrState
	}
	permissions := []string{"read", "list"}
	switch command.Operation {
	case "mkdir", "publish", "copy", "copy_tree", "copy_dir":
		permissions = append(permissions, "write")
	case "rename", "remove", "rmdir", "setstat", "move_tree", "remove_tree":
		permissions = append(permissions, "manage_paths")
	case "properties":
		permissions = append(permissions, "write", "manage_paths")
	default:
		return nil, ErrState
	}
	if command.Operation == "copy" && command.Replace {
		permissions = append(permissions, "manage_paths")
	}
	for _, permission := range permissions {
		if err := t.Require(permission); err != nil {
			return nil, err
		}
	}
	_, _, meaning, err := t.pathCommandMeaning(command)
	if err != nil {
		return nil, err
	}
	var raw []byte
	receipt := &PathCommandReceipt{Profile: "namespace-command-receipt-v1", Observation: "original-commit-not-current-state", RequestKey: key, RequestHash: meaning}
	// Actor RLS and the exact original request meaning bind tenant,partner,
	// identity,mount,authority revision and every supplied command option.
	err = t.Tx.QueryRow(ctx, `SELECT result,completed_event_id::text FROM namespace_commands WHERE actor_id=$1 AND request_key=$2 AND request_hash=$3`, t.Actor, key, meaning).Scan(&raw, &receipt.CompletedEventID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(raw, &receipt.Result); err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return receipt, nil
}
