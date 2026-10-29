-- Existing experimental tickets remain explicitly unbound; do not infer a store.
ALTER TABLE upload_sessions ADD COLUMN storage_id text NOT NULL DEFAULT '' CHECK(storage_id='' OR storage_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$');
CREATE OR REPLACE FUNCTION freightctl_upload_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE kind text;
BEGIN
 SELECT e.kind INTO kind FROM events e WHERE (e.tenant_id,e.partner_id,e.event_id)=(NEW.tenant_id,NEW.partner_id,NEW.changed_event_id) AND e.actor_id=NEW.actor_id AND e.resource_id=NEW.upload_id;
 IF TG_OP='INSERT' AND (kind IS DISTINCT FROM 'UploadSessionCreated' OR NEW.state<>'open' OR NEW.revision<>1 OR NEW.committed_offset<>0 OR NEW.chunk_count<>0 OR NEW.storage_id='') THEN
  RAISE EXCEPTION 'upload requires its creation event' USING ERRCODE='23514';
 END IF;
 IF TG_OP='UPDATE' AND kind='UploadCheckpointed' AND NOT EXISTS(SELECT 1 FROM events e
  WHERE (e.tenant_id,e.partner_id,e.event_id)=(NEW.tenant_id,NEW.partner_id,NEW.changed_event_id)
  AND e.payload->>'chunk_offset'=OLD.committed_offset::text AND e.payload->>'chunk_size'=(NEW.committed_offset-OLD.committed_offset)::text) THEN
  RAISE EXCEPTION 'checkpoint must extend the exact contiguous prefix' USING ERRCODE='23514';
 END IF;
 IF TG_OP='UPDATE' AND (OLD.state<>'open' OR NEW.revision<>OLD.revision+1 OR
  (NEW.tenant_id,NEW.partner_id,NEW.upload_id) IS DISTINCT FROM (OLD.tenant_id,OLD.partner_id,OLD.upload_id) OR
  (NEW.actor_id,NEW.namespace_root,NEW.authority_revision,NEW.target,NEW.expected_size,NEW.expected_sha256,NEW.storage_id) IS DISTINCT FROM (OLD.actor_id,OLD.namespace_root,OLD.authority_revision,OLD.target,OLD.expected_size,OLD.expected_sha256,OLD.storage_id) OR
  kind NOT IN ('UploadCheckpointed','UploadCompleted','UploadAborted','UploadRejected') OR
  (kind='UploadCheckpointed' AND (NEW.state<>'open' OR NEW.committed_offset<=OLD.committed_offset OR NEW.chunk_count<>OLD.chunk_count+1)) OR
  (kind<>'UploadCheckpointed' AND (NEW.committed_offset<>OLD.committed_offset OR NEW.chunk_count<>OLD.chunk_count)) OR
  (kind='UploadCompleted' AND NEW.state<>'completed') OR (kind='UploadAborted' AND NEW.state<>'aborted') OR (kind='UploadRejected' AND NEW.state<>'rejected')) THEN
  RAISE EXCEPTION 'invalid upload transition' USING ERRCODE='23514';
 END IF;
 IF NEW.state='completed' AND NOT EXISTS(SELECT 1 FROM files f JOIN events e ON (e.tenant_id,e.partner_id,e.event_id)=(f.tenant_id,f.partner_id,f.accepted_event_id)
  WHERE (f.tenant_id,f.partner_id,f.file_id)=(NEW.tenant_id,NEW.partner_id,NEW.file_id) AND f.size_bytes=NEW.expected_size AND f.sha256=NEW.expected_sha256
  AND e.actor_id=NEW.actor_id AND e.payload->>'upload_session_id'=NEW.upload_id::text AND e.payload->>'storage_id'=NEW.storage_id) THEN
  RAISE EXCEPTION 'completed upload requires its exact accepted revision' USING ERRCODE='23514';
 END IF;
 IF NOT EXISTS(SELECT 1 FROM events e WHERE (e.tenant_id,e.partner_id,e.event_id)=(NEW.tenant_id,NEW.partner_id,NEW.changed_event_id)
  AND e.actor_id=NEW.actor_id AND e.resource_id=NEW.upload_id
  AND e.payload->>'storage_id'=NEW.storage_id AND e.payload->>'namespace_root'=NEW.namespace_root AND e.payload->>'authority_revision'=NEW.authority_revision::text
  AND e.payload->'target'=NEW.target AND e.payload->>'expected_size'=NEW.expected_size::text AND e.payload->>'expected_sha256'=NEW.expected_sha256
  AND e.payload->>'committed_offset'=NEW.committed_offset::text AND e.payload->>'chunk_count'=NEW.chunk_count::text
  AND e.payload->>'state'=NEW.state AND e.payload->>'file_id'=coalesce(NEW.file_id::text,'') AND e.payload->>'revision'=NEW.revision::text) THEN
  RAISE EXCEPTION 'upload projection requires its exact event' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
