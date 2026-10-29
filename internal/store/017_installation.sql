-- First-run enrollment is an explicit local database-administrator operation.
-- The serving role receives no new write authority.
CREATE TABLE installation_enrollments (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 tenant_id uuid NOT NULL, partner_id uuid NOT NULL, actor_id uuid NOT NULL,
 request_key uuid NOT NULL,
 request_hash text NOT NULL CHECK(request_hash ~ '^[0-9a-f]{64}$'),
 definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object' AND octet_length(definition::text)<=8192),
 result jsonb NOT NULL CHECK(jsonb_typeof(result)='object' AND octet_length(result::text)<=8192),
 event_id uuid NOT NULL,
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,event_id) REFERENCES events(tenant_id,partner_id,event_id)
);
ALTER TABLE installation_enrollments ENABLE ROW LEVEL SECURITY;
ALTER TABLE installation_enrollments FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON installation_enrollments USING(
 tenant_id=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND
 partner_id=nullif(current_setting('freightctl.partner_id',true),'')::uuid AND
 actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid);
REVOKE ALL ON installation_enrollments FROM PUBLIC;
GRANT SELECT ON installation_enrollments TO freightctl_runtime;

CREATE FUNCTION freightctl_installation_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE e events;c credentials;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'installation enrollment is immutable' USING ERRCODE='23514';END IF;
 SELECT * INTO e FROM events WHERE (tenant_id,partner_id,event_id)=(NEW.tenant_id,NEW.partner_id,NEW.event_id);
 SELECT * INTO c FROM credentials WHERE (tenant_id,partner_id,actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id);
 IF e.kind IS DISTINCT FROM 'InstallationInitialized' OR e.actor_id IS DISTINCT FROM NEW.actor_id OR e.resource_id IS DISTINCT FROM NEW.request_key OR
 e.payload->'request' IS DISTINCT FROM NEW.definition OR e.payload->'result' IS DISTINCT FROM NEW.result OR e.payload->>'request_hash' IS DISTINCT FROM NEW.request_hash OR
 NEW.definition->>'tenant_id' IS DISTINCT FROM NEW.tenant_id::text OR NEW.definition->>'partner_id' IS DISTINCT FROM NEW.partner_id::text OR NEW.definition->>'admin_id' IS DISTINCT FROM NEW.actor_id::text OR
 NEW.definition->>'request_key' IS DISTINCT FROM NEW.request_key::text OR NEW.definition->>'credential_sha256' IS DISTINCT FROM c.token_hash OR NEW.definition->>'admin_label' IS DISTINCT FROM c.account_label OR
 NEW.definition->'permissions' IS DISTINCT FROM to_jsonb(c.permissions) OR c.namespace_root IS DISTINCT FROM '/' OR c.revoked_at IS NOT NULL OR c.expires_at IS NOT NULL OR
 NEW.result->>'tenant_id' IS DISTINCT FROM NEW.tenant_id::text OR NEW.result->>'partner_id' IS DISTINCT FROM NEW.partner_id::text OR NEW.result->>'actor_id' IS DISTINCT FROM NEW.actor_id::text OR NEW.result->>'event_id' IS DISTINCT FROM NEW.event_id::text THEN
 RAISE EXCEPTION 'installation enrollment requires exact identity, event and receipt' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER installation_guard BEFORE INSERT OR UPDATE OR DELETE ON installation_enrollments FOR EACH ROW EXECUTE FUNCTION freightctl_installation_guard();
