package api

import (
	"context"
	"encoding/json"

	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func (s *Server) mcpNamespaceReceipt(ctx context.Context, scope store.Scope, args mcpToolArguments) (any, error) {
	if !store.ValidNamespaceRequestKey(args.Key) || len(args.Command) > 16<<10 {
		return nil, store.ErrExchangeInput
	}
	var fields map[string]json.RawMessage
	if workflow.Decode(args.Command, &fields) != nil {
		return nil, store.ErrExchangeInput
	}
	// Property mutations contain content. This metadata-only agent profile
	// never acquires or discloses those original XML values as tool context.
	if _, present := fields["property_changes"]; present {
		return nil, store.ErrExchangeInput
	}
	var command store.PathCommand
	if workflow.Decode(args.Command, &command) != nil {
		return nil, store.ErrExchangeInput
	}
	switch command.Operation {
	case "mkdir", "publish", "copy", "rename", "remove", "rmdir", "setstat", "move_tree", "remove_tree", "copy_tree", "copy_dir":
	default:
		return nil, store.ErrExchangeInput
	}
	return s.Service.ReadPathCommandReceipt(ctx, scope, args.Key, command)
}
