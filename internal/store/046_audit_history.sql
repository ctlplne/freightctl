-- Root audit_read search reads metadata only and keeps every scope/RLS guard.
-- Keyset indexes avoid sorting a full tenant history for common exact filters.
CREATE INDEX events_actor_history ON events(tenant_id,partner_id,actor_id,happened_at,event_id);
CREATE INDEX events_resource_history ON events(tenant_id,partner_id,resource_id,happened_at,event_id);
CREATE INDEX events_kind_history ON events(tenant_id,partner_id,kind,happened_at,event_id);
