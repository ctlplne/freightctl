-- Preserve the key/result meaning of v1 records by appending a checkpoint.
-- Original events stay immutable. This is a migration snapshot, not retroactive proof.
INSERT INTO events(tenant_id,partner_id,event_id,actor_id,kind,resource_id,payload)
SELECT f.tenant_id,f.partner_id,gen_random_uuid(),e.actor_id,
       'FileIdempotencyCheckpointed',f.file_id,
       jsonb_build_object('schema_version',2,'keys',jsonb_agg(jsonb_build_object('key',i.request_key,'request_hash',i.request_hash) ORDER BY i.request_key))
FROM files f
JOIN events e ON (e.tenant_id,e.partner_id,e.event_id)=(f.tenant_id,f.partner_id,f.accepted_event_id)
JOIN idempotency i ON (i.tenant_id,i.partner_id,i.file_id)=(f.tenant_id,f.partner_id,f.file_id)
WHERE NOT (e.payload ? 'request_key')
GROUP BY f.tenant_id,f.partner_id,f.file_id,e.actor_id;

CREATE FUNCTION freightctl_check_file_event() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM events e
        WHERE (e.tenant_id,e.partner_id,e.event_id)=(NEW.tenant_id,NEW.partner_id,NEW.accepted_event_id)
          AND e.kind='FileAccepted' AND e.resource_id=NEW.file_id
          AND e.payload->>'sha256'=NEW.sha256
          AND e.payload->>'size_bytes'=NEW.size_bytes::text
          AND e.payload->>'policy'=NEW.policy
    ) THEN
        RAISE EXCEPTION 'file projection requires its exact FileAccepted event' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER files_event_binding BEFORE INSERT ON files
FOR EACH ROW EXECUTE FUNCTION freightctl_check_file_event();

CREATE FUNCTION freightctl_check_idempotency_event() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM files f JOIN events e
          ON (e.tenant_id,e.partner_id,e.event_id)=(f.tenant_id,f.partner_id,f.accepted_event_id)
        WHERE (f.tenant_id,f.partner_id,f.file_id)=(NEW.tenant_id,NEW.partner_id,NEW.file_id)
          AND (
            (e.payload->>'request_key'=NEW.request_key AND e.payload->>'request_hash'=NEW.request_hash)
            OR EXISTS (
                SELECT 1 FROM events c, jsonb_array_elements(c.payload->'keys') k
                WHERE (c.tenant_id,c.partner_id,c.resource_id)=(NEW.tenant_id,NEW.partner_id,NEW.file_id)
                  AND c.kind='FileIdempotencyCheckpointed'
                  AND k->>'key'=NEW.request_key AND k->>'request_hash'=NEW.request_hash
            )
          )
    ) THEN
        RAISE EXCEPTION 'idempotency projection requires its journaled request meaning' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER idempotency_event_binding BEFORE INSERT ON idempotency
FOR EACH ROW EXECUTE FUNCTION freightctl_check_idempotency_event();
REVOKE ALL ON FUNCTION freightctl_check_file_event(),freightctl_check_idempotency_event() FROM PUBLIC;
