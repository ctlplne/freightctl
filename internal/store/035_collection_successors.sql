-- A collection keeps its original input assignment. Resolve completed handoff
-- leaves by input without scanning an actor's entire handoff history.
CREATE INDEX collection_handoff_input ON workflow_collection_handoffs
 (tenant_id,partner_id,actor_id,input_id) WHERE state='completed';
