-- Reserve the protocol-control namespace without shadowing existing names.
ALTER TABLE namespace_entries ADD CONSTRAINT namespace_control_names_reserved
 CHECK (deleted OR path !~ '(^|/)[.]freightctl(/|$)');
ALTER TABLE credentials ADD CONSTRAINT credential_control_names_reserved
 CHECK(revoked_at IS NOT NULL OR namespace_root !~ '(^|/)[.]freightctl(/|$)');
CREATE TABLE upload_sessions (
 tenant_id uuid NOT NULL,
 partner_id uuid NOT NULL,
 upload_id uuid NOT NULL,
 actor_id uuid NOT NULL,
 namespace_root text NOT NULL CHECK(left(namespace_root,1)='/' AND octet_length(namespace_root)<=1024),
 authority_revision bigint NOT NULL CHECK(authority_revision>0),
 target jsonb NOT NULL CHECK(jsonb_typeof(target)='object' AND octet_length(target::text)<=8192),
 expected_size bigint NOT NULL CHECK(expected_size BETWEEN 0 AND 1073741824),
 expected_sha256 text NOT NULL CHECK(expected_sha256 ~ '^[0-9a-f]{64}$'),
 committed_offset bigint NOT NULL CHECK(committed_offset>=0 AND committed_offset<=expected_size),
 chunk_count integer NOT NULL CHECK(chunk_count BETWEEN 0 AND 4096),
 state text NOT NULL CHECK(state IN ('open','completed','aborted','rejected')),
 file_id uuid,
 revision bigint NOT NULL CHECK(revision>0),
 changed_event_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,upload_id),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,file_id) REFERENCES files(tenant_id,partner_id,file_id),
 FOREIGN KEY(tenant_id,partner_id,changed_event_id) REFERENCES events(tenant_id,partner_id,event_id),
 CHECK((state='completed')=(file_id IS NOT NULL)),
 CHECK(state<>'completed' OR committed_offset=expected_size)
);
CREATE INDEX upload_actor_state ON upload_sessions(tenant_id,partner_id,actor_id,state);
CREATE TABLE upload_chunks (
 tenant_id uuid NOT NULL,
 partner_id uuid NOT NULL,
 upload_id uuid NOT NULL,
 actor_id uuid NOT NULL,
 start_offset bigint NOT NULL CHECK(start_offset>=0),
 object_id uuid NOT NULL,
 size_bytes bigint NOT NULL CHECK(size_bytes BETWEEN 1 AND 8388608),
 sha256 text NOT NULL CHECK(sha256 ~ '^[0-9a-f]{64}$'),
 checkpoint_event_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,upload_id,start_offset),
 UNIQUE(tenant_id,partner_id,object_id),
 FOREIGN KEY(tenant_id,partner_id,upload_id) REFERENCES upload_sessions(tenant_id,partner_id,upload_id),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,checkpoint_event_id) REFERENCES events(tenant_id,partner_id,event_id)
);
CREATE TABLE upload_receipts (
 tenant_id uuid NOT NULL,
 partner_id uuid NOT NULL,
 actor_id uuid NOT NULL,
 request_key text NOT NULL CHECK(length(request_key) BETWEEN 1 AND 128),
 request_hash text NOT NULL CHECK(request_hash ~ '^[0-9a-f]{64}$'),
 upload_id uuid NOT NULL,
 result jsonb NOT NULL CHECK(octet_length(result::text)<=16384),
 completed_event_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,actor_id,request_key),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,upload_id) REFERENCES upload_sessions(tenant_id,partner_id,upload_id),
 FOREIGN KEY(tenant_id,partner_id,completed_event_id) REFERENCES events(tenant_id,partner_id,event_id)
);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['upload_sessions','upload_chunks','upload_receipts'] LOOP
  EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('CREATE POLICY scope ON %I USING (tenant_id=nullif(current_setting(''freightctl.tenant_id'',true),'''')::uuid AND partner_id=nullif(current_setting(''freightctl.partner_id'',true),'''')::uuid) WITH CHECK(tenant_id=nullif(current_setting(''freightctl.tenant_id'',true),'''')::uuid AND partner_id=nullif(current_setting(''freightctl.partner_id'',true),'''')::uuid)',t);
 END LOOP;
 FOREACH t IN ARRAY ARRAY['upload_sessions','upload_receipts'] LOOP
  EXECUTE format('CREATE POLICY identity_scope ON %I AS RESTRICTIVE USING(actor_id=nullif(current_setting(''freightctl.actor_id'',true),'''')::uuid) WITH CHECK(actor_id=nullif(current_setting(''freightctl.actor_id'',true),'''')::uuid)',t);
 END LOOP;
END $$;
CREATE POLICY chunk_identity ON upload_chunks AS RESTRICTIVE
 USING(actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid OR EXISTS(
  SELECT 1 FROM credentials c WHERE c.actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid AND c.revoked_at IS NULL AND c.namespace_root='/' AND 'inspect'=ANY(c.permissions)))
 WITH CHECK(actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid);
GRANT SELECT,INSERT,UPDATE ON upload_sessions TO freightctl_runtime;
GRANT SELECT,INSERT ON upload_chunks,upload_receipts TO freightctl_runtime;
CREATE FUNCTION freightctl_upload_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE kind text;
BEGIN
 SELECT e.kind INTO kind FROM events e WHERE (e.tenant_id,e.partner_id,e.event_id)=(NEW.tenant_id,NEW.partner_id,NEW.changed_event_id) AND e.actor_id=NEW.actor_id AND e.resource_id=NEW.upload_id;
 IF TG_OP='INSERT' AND (kind IS DISTINCT FROM 'UploadSessionCreated' OR NEW.state<>'open' OR NEW.revision<>1 OR NEW.committed_offset<>0 OR NEW.chunk_count<>0) THEN
  RAISE EXCEPTION 'upload requires its creation event' USING ERRCODE='23514';
 END IF;
 IF TG_OP='UPDATE' AND kind='UploadCheckpointed' AND NOT EXISTS(SELECT 1 FROM events e
  WHERE (e.tenant_id,e.partner_id,e.event_id)=(NEW.tenant_id,NEW.partner_id,NEW.changed_event_id)
  AND e.payload->>'chunk_offset'=OLD.committed_offset::text AND e.payload->>'chunk_size'=(NEW.committed_offset-OLD.committed_offset)::text) THEN
  RAISE EXCEPTION 'checkpoint must extend the exact contiguous prefix' USING ERRCODE='23514';
 END IF;
 IF TG_OP='UPDATE' AND (OLD.state<>'open' OR NEW.revision<>OLD.revision+1 OR
  (NEW.tenant_id,NEW.partner_id,NEW.upload_id) IS DISTINCT FROM (OLD.tenant_id,OLD.partner_id,OLD.upload_id) OR
  (NEW.actor_id,NEW.namespace_root,NEW.authority_revision,NEW.target,NEW.expected_size,NEW.expected_sha256) IS DISTINCT FROM (OLD.actor_id,OLD.namespace_root,OLD.authority_revision,OLD.target,OLD.expected_size,OLD.expected_sha256) OR
  kind NOT IN ('UploadCheckpointed','UploadCompleted','UploadAborted','UploadRejected') OR
  (kind='UploadCheckpointed' AND (NEW.state<>'open' OR NEW.committed_offset<=OLD.committed_offset OR NEW.chunk_count<>OLD.chunk_count+1)) OR
  (kind<>'UploadCheckpointed' AND (NEW.committed_offset<>OLD.committed_offset OR NEW.chunk_count<>OLD.chunk_count)) OR
  (kind='UploadCompleted' AND NEW.state<>'completed') OR (kind='UploadAborted' AND NEW.state<>'aborted') OR (kind='UploadRejected' AND NEW.state<>'rejected')) THEN
  RAISE EXCEPTION 'invalid upload transition' USING ERRCODE='23514';
 END IF;
 IF NEW.state='completed' AND NOT EXISTS(SELECT 1 FROM files f JOIN events e ON (e.tenant_id,e.partner_id,e.event_id)=(f.tenant_id,f.partner_id,f.accepted_event_id)
  WHERE (f.tenant_id,f.partner_id,f.file_id)=(NEW.tenant_id,NEW.partner_id,NEW.file_id) AND f.size_bytes=NEW.expected_size AND f.sha256=NEW.expected_sha256
  AND e.actor_id=NEW.actor_id AND e.payload->>'upload_session_id'=NEW.upload_id::text) THEN
  RAISE EXCEPTION 'completed upload requires its exact accepted revision' USING ERRCODE='23514';
 END IF;
 IF NOT EXISTS(SELECT 1 FROM events e WHERE (e.tenant_id,e.partner_id,e.event_id)=(NEW.tenant_id,NEW.partner_id,NEW.changed_event_id)
  AND e.actor_id=NEW.actor_id AND e.resource_id=NEW.upload_id
  AND e.payload->>'namespace_root'=NEW.namespace_root AND e.payload->>'authority_revision'=NEW.authority_revision::text
  AND e.payload->'target'=NEW.target AND e.payload->>'expected_size'=NEW.expected_size::text AND e.payload->>'expected_sha256'=NEW.expected_sha256
  AND e.payload->>'committed_offset'=NEW.committed_offset::text AND e.payload->>'chunk_count'=NEW.chunk_count::text
  AND e.payload->>'state'=NEW.state AND e.payload->>'file_id'=coalesce(NEW.file_id::text,'') AND e.payload->>'revision'=NEW.revision::text) THEN
  RAISE EXCEPTION 'upload projection requires its exact event' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER upload_guard BEFORE INSERT OR UPDATE ON upload_sessions FOR EACH ROW EXECUTE FUNCTION freightctl_upload_guard();
CREATE FUNCTION freightctl_upload_chunk_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM events e JOIN upload_sessions u ON (u.tenant_id,u.partner_id,u.upload_id)=(e.tenant_id,e.partner_id,e.resource_id)
  WHERE (e.tenant_id,e.partner_id,e.event_id)=(NEW.tenant_id,NEW.partner_id,NEW.checkpoint_event_id)
  AND e.kind='UploadCheckpointed' AND e.actor_id=NEW.actor_id AND u.actor_id=NEW.actor_id AND u.changed_event_id=e.event_id
  AND e.payload->>'chunk_object_id'=NEW.object_id::text AND e.payload->>'chunk_offset'=NEW.start_offset::text
  AND e.payload->>'chunk_size'=NEW.size_bytes::text AND e.payload->>'chunk_sha256'=NEW.sha256
  AND u.committed_offset=NEW.start_offset+NEW.size_bytes) THEN
  RAISE EXCEPTION 'chunk requires its exact checkpoint event and head' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER upload_chunk_guard BEFORE INSERT ON upload_chunks FOR EACH ROW EXECUTE FUNCTION freightctl_upload_chunk_guard();
CREATE FUNCTION freightctl_upload_receipt_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM events e WHERE (e.tenant_id,e.partner_id,e.event_id)=(NEW.tenant_id,NEW.partner_id,NEW.completed_event_id)
  AND e.actor_id=NEW.actor_id AND e.kind='UploadCommandCompleted' AND e.resource_id=NEW.upload_id
  AND e.payload->>'request_key'=NEW.request_key AND e.payload->>'request_hash'=NEW.request_hash AND e.payload->'result'=NEW.result) THEN
  RAISE EXCEPTION 'upload receipt requires its exact event' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER upload_receipt_guard BEFORE INSERT ON upload_receipts FOR EACH ROW EXECUTE FUNCTION freightctl_upload_receipt_guard();
REVOKE ALL ON FUNCTION freightctl_upload_guard(),freightctl_upload_chunk_guard(),freightctl_upload_receipt_guard() FROM PUBLIC;

CREATE FUNCTION freightctl_upload_checkpoint_exists() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM events e WHERE (e.tenant_id,e.partner_id,e.event_id)=(NEW.tenant_id,NEW.partner_id,NEW.changed_event_id) AND e.kind='UploadCheckpointed') AND
  NOT EXISTS(SELECT 1 FROM upload_chunks c WHERE (c.tenant_id,c.partner_id,c.upload_id,c.checkpoint_event_id)=(NEW.tenant_id,NEW.partner_id,NEW.upload_id,NEW.changed_event_id) AND c.start_offset+c.size_bytes=NEW.committed_offset) THEN
  RAISE EXCEPTION 'upload offset requires its immutable chunk record' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER upload_checkpoint_exists AFTER INSERT OR UPDATE ON upload_sessions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION freightctl_upload_checkpoint_exists();
REVOKE ALL ON FUNCTION freightctl_upload_checkpoint_exists() FROM PUBLIC;
