-- Copy provenance stays in the immutable acceptance event. It creates no
-- traversal grant, inherited release or shared ownership of the source file.
CREATE FUNCTION freightctl_exchange_copy_acceptance_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE x artifact_exchanges;f files;c credentials;origin jsonb;expected jsonb;policy intake_policies;
BEGIN
 IF NEW.payload->'schema_version' IS DISTINCT FROM '4'::jsonb OR jsonb_typeof(NEW.payload->'exchange_copy') IS DISTINCT FROM 'object'
 OR jsonb_typeof(NEW.payload->'request_key') IS DISTINCT FROM 'string' OR (NEW.payload->>'request_key') !~ '^[A-Za-z0-9._:-]{1,128}$'
 OR jsonb_typeof(NEW.payload->'request_hash') IS DISTINCT FROM 'string' OR (NEW.payload->>'request_hash') !~ '^[0-9a-f]{64}$'
 OR jsonb_typeof(NEW.payload->'protocol_session_id') IS DISTINCT FROM 'string'
 OR NEW.actor_id IS DISTINCT FROM nullif(current_setting('freightctl.actor_id',true),'')::uuid THEN
  RAISE EXCEPTION 'received copy requires its typed acceptance and actor' USING ERRCODE='23514';
 END IF;
 origin:=NEW.payload->'exchange_copy';
 SELECT * INTO x FROM artifact_exchanges WHERE (tenant_id,partner_id,exchange_id::text,recipient_actor_id)=(NEW.tenant_id,NEW.partner_id,origin->>'exchange_id',NEW.actor_id);
 IF x.exchange_id IS NULL THEN RAISE EXCEPTION 'received copy requires its recipient view' USING ERRCODE='23514';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended(NEW.tenant_id::text||':'||NEW.partner_id::text||':artifact-exchange:'||x.exchange_id::text,0));
 PERFORM pg_advisory_xact_lock_shared(hashtextextended(NEW.tenant_id::text||':'||NEW.partner_id::text||':exchange-endpoint:'||x.endpoint_id::text,0));
 PERFORM pg_advisory_xact_lock_shared(hashtextextended(NEW.tenant_id::text||':'||NEW.partner_id::text||':namespace-v1',0));
 PERFORM pg_advisory_xact_lock_shared(hashtextextended(NEW.tenant_id::text||':'||NEW.partner_id::text||':intake-policy',0));
 SELECT * INTO c FROM credentials WHERE (tenant_id,partner_id,actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id);
 IF c.actor_id IS NULL OR c.revoked_at IS NOT NULL OR c.expires_at<=clock_timestamp() OR NOT c.permissions @> ARRAY['read','list','write']::text[]
 OR freightctl_artifact_exchange_principals_current(x) IS DISTINCT FROM true
 OR freightctl_artifact_exchange_policy_current(x.tenant_id,x.partner_id,x.file_id) IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'received copy requires current receive and write authority' USING ERRCODE='23514';
 END IF;
 IF origin IS DISTINCT FROM jsonb_build_object('exchange_id',x.exchange_id,'request_hash',x.request_hash,'artifact',x.request->'artifact')
 OR NEW.payload->'storage_id' IS DISTINCT FROM to_jsonb(x.storage_id::text) THEN
  RAISE EXCEPTION 'received copy source differs from exact immutable view' USING ERRCODE='23514';
 END IF;
 SELECT * INTO f FROM files WHERE (tenant_id,partner_id,file_id,accepted_event_id)=(NEW.tenant_id,NEW.partner_id,NEW.resource_id,NEW.event_id);
 IF f.file_id IS NULL OR f.file_id=x.file_id OR f.size_bytes::text IS DISTINCT FROM x.request->'artifact'->>'size_bytes'
 OR f.sha256 IS DISTINCT FROM x.request->'artifact'->>'sha256' THEN
  RAISE EXCEPTION 'received copy requires a separate exact accepted revision' USING ERRCODE='23514';
 END IF;
 SELECT * INTO policy FROM intake_policies WHERE (tenant_id,partner_id)=(NEW.tenant_id,NEW.partner_id) ORDER BY version DESC LIMIT 1;
 IF (policy.policy_id IS NULL AND f.policy<>'integrity-only-v1') OR (policy.policy_id IS NOT NULL AND (policy.state<>'active' OR f.policy IS DISTINCT FROM 'intake-csv-v1:'||policy.definition_hash)) THEN
  RAISE EXCEPTION 'received copy requires fresh current intake policy' USING ERRCODE='23514';
 END IF;
 expected:=jsonb_build_object('schema_version',4,'size_bytes',f.size_bytes,'sha256',f.sha256,'policy',f.policy,
  'request_key',NEW.payload->'request_key','request_hash',NEW.payload->'request_hash','protocol_session_id',NEW.payload->'protocol_session_id',
  'upload_session_id','','storage_id',x.storage_id,'exchange_copy',origin);
 IF NEW.payload IS DISTINCT FROM expected OR NOT EXISTS(SELECT 1 FROM idempotency i WHERE
  (i.tenant_id,i.partner_id,i.actor_id,i.file_id,i.request_key,i.request_hash)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,f.file_id,NEW.payload->>'request_key',NEW.payload->>'request_hash')) THEN
  RAISE EXCEPTION 'received copy requires exact transactional acceptance receipt' USING ERRCODE='23514';
 END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER exchange_copy_acceptance_complete AFTER INSERT ON events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
 WHEN(NEW.kind='FileAccepted' AND (NEW.payload ? 'exchange_copy' OR NEW.payload->'schema_version'='4'::jsonb)) EXECUTE FUNCTION freightctl_exchange_copy_acceptance_guard();
REVOKE ALL ON FUNCTION freightctl_exchange_copy_acceptance_guard() FROM PUBLIC;
