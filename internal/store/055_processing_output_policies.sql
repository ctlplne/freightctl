-- Producer-bound output contracts do not replace the default ingress policy.
-- Ordinary acceptance/check/publication guards remain active-policy-only until
-- an explicitly qualified generated-output profile is implemented.
ALTER TABLE intake_policies DROP CONSTRAINT intake_policies_state_check;
ALTER TABLE intake_policies ADD CONSTRAINT intake_policies_state_check CHECK(state IN ('active','retired','revoked','output_active','output_retired','output_revoked'));
ALTER TABLE intake_policies DROP CONSTRAINT intake_policies_tenant_id_partner_id_version_key;
CREATE UNIQUE INDEX intake_default_version ON intake_policies(tenant_id,partner_id,version) WHERE state IN ('active','retired','revoked');
CREATE UNIQUE INDEX processing_output_one_active ON intake_policies(tenant_id,partner_id,policy_id) WHERE state='output_active';
CREATE TABLE processing_output_policies(
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,actor_id uuid NOT NULL,policy_id uuid NOT NULL,policy_version integer NOT NULL,
 producer_id uuid NOT NULL,binding jsonb NOT NULL CHECK(jsonb_typeof(binding)='object' AND octet_length(binding::text)<=4096),
 binding_hash text NOT NULL CHECK(binding_hash ~ '^[0-9a-f]{64}$'),event_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,policy_id,policy_version),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,producer_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,policy_id,policy_version) REFERENCES intake_policies(tenant_id,partner_id,policy_id,version),
 FOREIGN KEY(tenant_id,partner_id,event_id) REFERENCES events(tenant_id,partner_id,event_id)
);
ALTER TABLE processing_output_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE processing_output_policies FORCE ROW LEVEL SECURITY;
CREATE FUNCTION freightctl_processing_output_admin(t uuid,p uuid) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT t=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND p=nullif(current_setting('freightctl.partner_id',true),'')::uuid
 AND EXISTS(SELECT 1 FROM credentials c WHERE (c.tenant_id,c.partner_id,c.actor_id)=(t,p,nullif(current_setting('freightctl.actor_id',true),'')::uuid)
 AND c.namespace_root='/' AND c.permissions @> ARRAY['admin','intake_manage']::text[] AND c.revoked_at IS NULL AND (c.expires_at IS NULL OR c.expires_at>clock_timestamp()))
$$;
CREATE FUNCTION freightctl_processing_output_producer_current(t uuid,p uuid,b jsonb) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT t=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND p=nullif(current_setting('freightctl.partner_id',true),'')::uuid
 AND b->'producer'->>'tenant_id'=t::text AND b->'producer'->>'partner_id'=p::text
 AND EXISTS(SELECT 1 FROM credentials c WHERE (c.tenant_id,c.partner_id,c.actor_id)=(t,p,nullif(current_setting('freightctl.actor_id',true),'')::uuid)
 AND c.actor_id::text=b->'producer'->>'actor_id' AND c.authority_revision::text=b->'producer'->>'authority_revision'
 AND encode(sha256(convert_to(c.namespace_root,'UTF8')),'hex')=b->'producer'->>'root_policy_digest'
 AND c.permissions @> ARRAY['read','write','check_run','workflow_execute']::text[] AND c.revoked_at IS NULL AND (c.expires_at IS NULL OR c.expires_at>clock_timestamp()))
$$;
CREATE POLICY scope ON processing_output_policies USING(freightctl_processing_output_admin(tenant_id,partner_id) OR freightctl_processing_output_producer_current(tenant_id,partner_id,binding))
 WITH CHECK(freightctl_processing_output_admin(tenant_id,partner_id) AND actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid);
REVOKE ALL ON processing_output_policies FROM PUBLIC;
GRANT SELECT,INSERT ON processing_output_policies TO freightctl_runtime;
CREATE FUNCTION freightctl_processing_output_reader(t uuid,p uuid,id uuid,v integer) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT freightctl_processing_output_admin(t,p) OR EXISTS(SELECT 1 FROM processing_output_policies b WHERE (b.tenant_id,b.partner_id,b.policy_id,b.policy_version)=(t,p,id,v) AND freightctl_processing_output_producer_current(t,p,b.binding))
$$;
CREATE POLICY output_contract_visibility ON intake_policies AS RESTRICTIVE
 USING(state IN ('active','retired','revoked') OR freightctl_processing_output_reader(tenant_id,partner_id,policy_id,version))
 WITH CHECK(state IN ('active','retired','revoked') OR freightctl_processing_output_reader(tenant_id,partner_id,policy_id,version));
REVOKE ALL ON FUNCTION freightctl_processing_output_admin(uuid,uuid),freightctl_processing_output_producer_current(uuid,uuid,jsonb),freightctl_processing_output_reader(uuid,uuid,uuid,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION freightctl_processing_output_admin(uuid,uuid),freightctl_processing_output_producer_current(uuid,uuid,jsonb),freightctl_processing_output_reader(uuid,uuid,uuid,integer) TO freightctl_runtime;

CREATE OR REPLACE FUNCTION freightctl_intake_policy_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE p jsonb; maximum integer;is_output boolean;
BEGIN
 SELECT payload INTO p FROM events WHERE (tenant_id,partner_id,event_id)=(NEW.tenant_id,NEW.partner_id,NEW.changed_event_id) AND actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid AND resource_id=NEW.policy_id AND kind='IntakePolicyChanged';
 IF p IS NULL OR p->>'id' IS DISTINCT FROM NEW.policy_id::text OR p->>'version' IS DISTINCT FROM NEW.version::text OR p->'definition' IS DISTINCT FROM NEW.definition OR p->>'definition_hash' IS DISTINCT FROM NEW.definition_hash OR p->>'state' IS DISTINCT FROM NEW.state OR p->>'revision' IS DISTINCT FROM NEW.revision::text THEN RAISE EXCEPTION 'intake policy requires its exact event' USING ERRCODE='23514';END IF;
 is_output:=NEW.state IN ('output_active','output_retired','output_revoked');
 IF TG_OP='UPDATE' THEN is_output:=is_output OR OLD.state IN ('output_active','output_retired','output_revoked');END IF;
 IF is_output THEN
  IF NOT freightctl_processing_output_admin(NEW.tenant_id,NEW.partner_id) THEN RAISE EXCEPTION 'processing output policy requires current root policy administrator' USING ERRCODE='42501';END IF;
  IF TG_OP='INSERT' THEN
   SELECT coalesce(max(version),0) INTO maximum FROM intake_policies WHERE tenant_id=NEW.tenant_id AND partner_id=NEW.partner_id AND policy_id=NEW.policy_id;
   IF NEW.version<>maximum+1 OR NEW.state<>'output_active' OR NEW.revision<>1 OR NEW.actor_id IS DISTINCT FROM nullif(current_setting('freightctl.actor_id',true),'')::uuid OR EXISTS(SELECT 1 FROM intake_policies i WHERE (i.tenant_id,i.partner_id,i.policy_id)=(NEW.tenant_id,NEW.partner_id,NEW.policy_id) AND i.state IN ('active','retired','revoked')) THEN RAISE EXCEPTION 'output policy starts as a separate versioned contract family' USING ERRCODE='23514';END IF;
  ELSIF (NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.policy_id,NEW.version,NEW.definition,NEW.definition_hash) IS DISTINCT FROM (OLD.tenant_id,OLD.partner_id,OLD.actor_id,OLD.policy_id,OLD.version,OLD.definition,OLD.definition_hash) OR NEW.revision<>OLD.revision+1 OR OLD.state<>'output_active' OR NEW.state NOT IN ('output_retired','output_revoked') THEN RAISE EXCEPTION 'output policy definition and scope are immutable' USING ERRCODE='23514';END IF;
 ELSE
  -- The legacy default lane retains its original transition and global version
  -- rules. Separate output rows never advance its version or change its head.
  IF TG_OP='INSERT' THEN
   SELECT coalesce(max(version),0) INTO maximum FROM intake_policies WHERE tenant_id=NEW.tenant_id AND partner_id=NEW.partner_id AND state IN ('active','retired','revoked');
   IF NEW.version<>maximum+1 OR NEW.state<>'active' OR NEW.revision<>1 OR EXISTS(SELECT 1 FROM intake_policies i WHERE (i.tenant_id,i.partner_id,i.policy_id)=(NEW.tenant_id,NEW.partner_id,NEW.policy_id) AND i.state IN ('output_active','output_retired','output_revoked')) THEN RAISE EXCEPTION 'invalid intake policy creation' USING ERRCODE='23514';END IF;
  ELSE
   IF (NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.policy_id,NEW.version,NEW.definition,NEW.definition_hash) IS DISTINCT FROM (OLD.tenant_id,OLD.partner_id,OLD.actor_id,OLD.policy_id,OLD.version,OLD.definition,OLD.definition_hash) OR NEW.revision<>OLD.revision+1 OR OLD.state<>'active' OR NEW.state NOT IN ('retired','revoked') THEN RAISE EXCEPTION 'intake policy definition is immutable' USING ERRCODE='23514';END IF;
  END IF;
 END IF;
 RETURN NEW;
END $$;

CREATE FUNCTION freightctl_processing_output_binding_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE e jsonb;b jsonb;i intake_policies;producer credentials;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'processing output producer bindings are immutable' USING ERRCODE='23514';END IF;
 b:=NEW.binding;
 SELECT payload INTO e FROM events WHERE (tenant_id,partner_id,event_id,actor_id,resource_id,kind)=(NEW.tenant_id,NEW.partner_id,NEW.event_id,NEW.actor_id,NEW.policy_id,'ProcessingOutputPolicyBound');
 IF e IS NULL OR e->'binding' IS DISTINCT FROM b OR e->>'binding_hash' IS DISTINCT FROM NEW.binding_hash OR NOT freightctl_processing_output_admin(NEW.tenant_id,NEW.partner_id) OR NEW.actor_id IS DISTINCT FROM nullif(current_setting('freightctl.actor_id',true),'')::uuid THEN RAISE EXCEPTION 'output binding requires exact administrator journal record' USING ERRCODE='42501';END IF;
 IF ARRAY(SELECT jsonb_object_keys(b) ORDER BY 1) IS DISTINCT FROM ARRAY['policy_hash','policy_id','policy_version','producer','profile','publisher_id']::text[] OR b->>'profile' IS DISTINCT FROM 'producer-processing-output-policy-v1' OR b->>'policy_id' IS DISTINCT FROM NEW.policy_id::text OR b->>'policy_version' IS DISTINCT FROM NEW.policy_version::text OR b->>'publisher_id' IS DISTINCT FROM NEW.actor_id::text OR b->'producer'->>'actor_id' IS DISTINCT FROM NEW.producer_id::text OR b->'producer'->>'tenant_id' IS DISTINCT FROM NEW.tenant_id::text OR b->'producer'->>'partner_id' IS DISTINCT FROM NEW.partner_id::text THEN RAISE EXCEPTION 'invalid exact output contract producer binding' USING ERRCODE='23514';END IF;
 IF jsonb_typeof(b->'producer') IS DISTINCT FROM 'object' OR ARRAY(SELECT jsonb_object_keys(b->'producer') ORDER BY 1) IS DISTINCT FROM ARRAY['actor_id','authority_revision','partner_id','root_policy_digest','tenant_id']::text[] THEN RAISE EXCEPTION 'invalid producer snapshot shape' USING ERRCODE='23514';END IF;
 SELECT * INTO i FROM intake_policies WHERE (tenant_id,partner_id,policy_id,version)=(NEW.tenant_id,NEW.partner_id,NEW.policy_id,NEW.policy_version);
 SELECT * INTO producer FROM credentials WHERE (tenant_id,partner_id,actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.producer_id) FOR SHARE;
 IF i.policy_id IS NULL OR i.state<>'output_active' OR i.revision<>1 OR i.actor_id<>NEW.actor_id OR i.definition_hash IS DISTINCT FROM b->>'policy_hash' OR producer.actor_id IS NULL OR producer.authority_revision::text IS DISTINCT FROM b->'producer'->>'authority_revision' OR encode(sha256(convert_to(producer.namespace_root,'UTF8')),'hex') IS DISTINCT FROM b->'producer'->>'root_policy_digest' OR NOT producer.permissions @> ARRAY['read','write','check_run','workflow_execute']::text[] OR producer.revoked_at IS NOT NULL OR producer.expires_at<=clock_timestamp() THEN RAISE EXCEPTION 'output binding requires current exact contract and producer authority' USING ERRCODE='42501';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER processing_output_binding_guard BEFORE INSERT OR UPDATE OR DELETE ON processing_output_policies FOR EACH ROW EXECUTE FUNCTION freightctl_processing_output_binding_guard();

CREATE FUNCTION freightctl_processing_output_complete() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_TABLE_NAME='events' THEN
  IF NEW.kind='ProcessingOutputPolicyBound' AND NOT EXISTS(SELECT 1 FROM processing_output_policies b WHERE (b.tenant_id,b.partner_id,b.policy_id,b.event_id)=(NEW.tenant_id,NEW.partner_id,NEW.resource_id,NEW.event_id)) THEN RAISE EXCEPTION 'output binding event requires exact projection' USING ERRCODE='23514';END IF;
  IF NEW.kind='IntakePolicyChanged' AND NEW.payload->>'state' IN ('output_active','output_retired','output_revoked') AND NOT EXISTS(SELECT 1 FROM intake_policies i WHERE (i.tenant_id,i.partner_id,i.policy_id,i.version,i.changed_event_id)=(NEW.tenant_id,NEW.partner_id,NEW.resource_id,(NEW.payload->>'version')::integer,NEW.event_id)) THEN RAISE EXCEPTION 'output policy event requires exact projection' USING ERRCODE='23514';END IF;
 ELSE
  IF NEW.state IN ('output_active','output_retired','output_revoked') AND NOT EXISTS(SELECT 1 FROM processing_output_policies b WHERE (b.tenant_id,b.partner_id,b.actor_id,b.policy_id,b.policy_version)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.policy_id,NEW.version) AND b.binding->>'policy_hash'=NEW.definition_hash) THEN RAISE EXCEPTION 'output policy and producer binding must commit together' USING ERRCODE='23514';END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER processing_output_event_complete AFTER INSERT ON events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN(NEW.kind IN ('ProcessingOutputPolicyBound','IntakePolicyChanged')) EXECUTE FUNCTION freightctl_processing_output_complete();
CREATE CONSTRAINT TRIGGER processing_output_policy_complete AFTER INSERT OR UPDATE ON intake_policies DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION freightctl_processing_output_complete();
REVOKE ALL ON FUNCTION freightctl_processing_output_binding_guard(),freightctl_processing_output_complete() FROM PUBLIC;

-- Preserve the legacy default lane in every database selection. Only the
-- explicit state filter changes; custody, authority, lease and format checks
-- from these latest guards are retained verbatim.

CREATE OR REPLACE FUNCTION freightctl_file_check_required() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.policy='integrity-only-v1' AND EXISTS(SELECT 1 FROM intake_policies i WHERE (i.tenant_id,i.partner_id)=(NEW.tenant_id,NEW.partner_id) AND i.state IN ('active','retired','revoked')) THEN RAISE EXCEPTION 'new acceptance cannot bypass a configured intake policy' USING ERRCODE='23514';END IF;
 IF freightctl_controlled_policy_hash(NEW.policy) IS NOT NULL AND NOT EXISTS(SELECT 1 FROM file_checks c WHERE (c.tenant_id,c.partner_id,c.file_id)=(NEW.tenant_id,NEW.partner_id,NEW.file_id) AND c.policy_hash=freightctl_controlled_policy_hash(NEW.policy)) THEN RAISE EXCEPTION 'controlled acceptance requires its bound check in the same transaction' USING ERRCODE='23514';END IF;RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION freightctl_artifact_exchange_policy_current(t uuid,p uuid,f uuid) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT EXISTS(SELECT 1 FROM files v LEFT JOIN LATERAL (SELECT state,definition_hash FROM intake_policies WHERE (tenant_id,partner_id)=(t,p) AND state IN ('active','retired','revoked') ORDER BY version DESC LIMIT 1) i ON true
 WHERE (v.tenant_id,v.partner_id,v.file_id)=(t,p,f) AND ((i.definition_hash IS NULL AND v.policy='integrity-only-v1') OR (i.state='active' AND v.policy=freightctl_intake_policy_prefix(i.definition)||i.definition_hash)))
 AND freightctl_file_available(t,p,f)
$$;

CREATE OR REPLACE FUNCTION freightctl_exchange_copy_acceptance_guard() RETURNS trigger LANGUAGE plpgsql AS $$
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
 SELECT * INTO policy FROM intake_policies WHERE (tenant_id,partner_id)=(NEW.tenant_id,NEW.partner_id) AND state IN ('active','retired','revoked') ORDER BY version DESC LIMIT 1;
 IF (policy.policy_id IS NULL AND f.policy<>'integrity-only-v1') OR (policy.policy_id IS NOT NULL AND (policy.state<>'active' OR f.policy IS DISTINCT FROM freightctl_intake_policy_prefix(policy.definition)||policy.definition_hash)) THEN
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

CREATE OR REPLACE FUNCTION freightctl_projection_current(t uuid,p uuid,a uuid,source uuid,plan jsonb) RETURNS void LANGUAGE plpgsql AS $$
DECLARE cr credentials; f files; c file_checks; prior_policy intake_policies; output_policy intake_policies;
 s jsonb; b jsonb; mapping jsonb; col jsonb; columns jsonb:='[]'::jsonb; shape jsonb;
 ref jsonb; proof jsonb; sig file_signatures; k pgp_keys; scan scanner_profiles;
 expiry timestamptz; signature_expiry timestamptz; scan_expiry timestamptz; expected_check jsonb;
BEGIN
 b:=plan->'context'; s:=b->'source';
 SELECT * INTO cr FROM credentials WHERE (tenant_id,partner_id,actor_id)=(t,p,a);
 IF cr.actor_id IS NULL OR a IS DISTINCT FROM nullif(current_setting('freightctl.actor_id',true),'')::uuid
 OR cr.revoked_at IS NOT NULL OR cr.expires_at<=clock_timestamp()
 OR b->>'namespace_root' IS DISTINCT FROM cr.namespace_root OR b->>'authority_revision' IS DISTINCT FROM cr.authority_revision::text
 OR freightctl_projection_actor_current(t,p,a,plan) IS DISTINCT FROM true
 OR b->>'storage_id' IS NULL THEN RAISE EXCEPTION 'projection requires exact current processing authority' USING ERRCODE='23514'; END IF;
 SELECT * INTO f FROM files WHERE (tenant_id,partner_id,file_id)=(t,p,source);
 SELECT * INTO c FROM file_checks WHERE (tenant_id,partner_id,file_id,actor_id)=(t,p,source,a);
 expected_check:=jsonb_build_object('policy_id',c.policy_id::text,'policy_version',c.policy_version,'policy_hash',c.policy_hash,'state',c.state,'revision',c.revision,'attempts',c.attempts,'code',c.code,'report_hash',c.report_hash,'binding',c.binding);
 IF f.file_id IS NULL OR c.file_id IS NULL OR c.state NOT IN ('passed','released') OR c.worker_id IS NOT NULL OR c.lease_until IS NOT NULL
 OR s->'check' IS DISTINCT FROM expected_check
 OR s->'file' IS DISTINCT FROM jsonb_build_object('id',f.file_id::text,'size_bytes',f.size_bytes,'sha256',f.sha256,'policy',f.policy,'accepted_event_id',f.accepted_event_id::text)
 OR c.binding->'file' IS DISTINCT FROM s->'file' OR c.binding->>'namespace_root' IS DISTINCT FROM cr.namespace_root
 OR c.binding->>'authority_revision' IS DISTINCT FROM cr.authority_revision::text OR c.binding->>'storage_id' IS DISTINCT FROM b->>'storage_id'
 OR NOT EXISTS(SELECT 1 FROM events WHERE (tenant_id,partner_id,event_id,actor_id,resource_id,kind)=(t,p,f.accepted_event_id,a,source,'FileAccepted'))
 THEN RAISE EXCEPTION 'projection requires exact owned successful source proof' USING ERRCODE='23514'; END IF;
 SELECT * INTO prior_policy FROM intake_policies WHERE (tenant_id,partner_id,policy_id,version,definition_hash)=(t,p,c.policy_id,c.policy_version,c.policy_hash);
 SELECT * INTO output_policy FROM intake_policies WHERE (tenant_id,partner_id)=(t,p) AND state IN ('active','retired','revoked') ORDER BY version DESC LIMIT 1;
 IF prior_policy.policy_id IS NULL OR prior_policy.state NOT IN ('active','retired') OR output_policy.policy_id IS NULL OR output_policy.state<>'active'
 OR plan->'source_policy' IS DISTINCT FROM jsonb_build_object('id',c.policy_id::text,'version',c.policy_version,'hash',c.policy_hash)
 OR b->'policy' IS DISTINCT FROM jsonb_build_object('id',output_policy.policy_id::text,'version',output_policy.version,'hash',output_policy.definition_hash)
 OR f.policy IS DISTINCT FROM freightctl_intake_policy_prefix(prior_policy.definition)||c.policy_hash
 OR c.report->>'file_id' IS DISTINCT FROM source::text OR c.report->>'sha256' IS DISTINCT FROM f.sha256
 OR c.report->>'bytes_read' IS DISTINCT FROM f.size_bytes::text OR c.report->>'policy_hash' IS DISTINCT FROM c.policy_hash
 OR c.report_hash !~ '^[0-9a-f]{64}$'
 OR c.report->>'code' IS DISTINCT FROM CASE prior_policy.definition->>'kind' WHEN 'csv' THEN 'valid_csv' WHEN 'json_records' THEN 'valid_json_records' WHEN 'fixed_width' THEN 'valid_fixed_width' WHEN 'xml_records' THEN 'valid_xml_records' WHEN 'xlsx_records' THEN 'valid_xlsx_records' END
 OR c.report->>'engine' IS DISTINCT FROM CASE prior_policy.definition->>'kind' WHEN 'csv' THEN 'freightctl-csv-v1' WHEN 'json_records' THEN 'freightctl-json-records-v1' WHEN 'fixed_width' THEN 'freightctl-fixed-width-v1' WHEN 'xml_records' THEN 'freightctl-xml-records-v1' WHEN 'xlsx_records' THEN 'freightctl-xlsx-records-v1' END
 THEN RAISE EXCEPTION 'projection source or output policy differs' USING ERRCODE='23514'; END IF;
 IF b->>'signature_mode' IS DISTINCT FROM CASE WHEN output_policy.definition ? 'signature' THEN 'require_new' ELSE 'not_required' END
 OR (prior_policy.definition ? 'scanner' AND NOT (output_policy.definition ? 'scanner'))
 OR (prior_policy.definition ? 'signature' AND NOT (output_policy.definition ? 'signature'))
 OR (coalesce((prior_policy.definition->'signature'->>'max_age_seconds')::bigint,0)>0 AND (coalesce((output_policy.definition->'signature'->>'max_age_seconds')::bigint,0)=0 OR (output_policy.definition->'signature'->>'max_age_seconds')::bigint>(prior_policy.definition->'signature'->>'max_age_seconds')::bigint))
 THEN RAISE EXCEPTION 'projection cannot inherit signatures or remove source controls' USING ERRCODE='23514'; END IF;
 SELECT * INTO sig FROM file_signatures WHERE (tenant_id,partner_id,file_id,actor_id)=(t,p,source,a);
 IF (sig.file_id IS NULL AND s ? 'signature') OR (sig.file_id IS NOT NULL AND s->'signature' IS DISTINCT FROM jsonb_build_object('file_id',sig.file_id::text,'object_id',sig.object_id::text,'storage_id',sig.storage_id::text,'size_bytes',sig.size_bytes,'sha256',sig.sha256,'data_sha256',sig.data_sha256,'policy_hash',sig.policy_hash,'key',jsonb_build_object('id',sig.key_id::text,'version',sig.key_version,'hash',sig.key_hash),'attached_event_id',sig.attached_event_id::text))
 THEN RAISE EXCEPTION 'projection requires the exact original attachment' USING ERRCODE='23514'; END IF;
 IF prior_policy.definition ? 'signature' THEN
  ref:=prior_policy.definition->'signature'->'key';proof:=c.report->'signature';
  SELECT * INTO k FROM pgp_keys WHERE (tenant_id,partner_id,key_id,version,definition_hash,state)=(t,p,(ref->>'id')::uuid,(ref->>'version')::integer,ref->>'hash','active');
  signature_expiry:=(proof->'verification'->>'valid_until')::timestamptz;
  IF k.key_id IS NULL OR k.valid_until<=clock_timestamp() OR sig.file_id IS NULL OR proof->'key' IS DISTINCT FROM ref
  OR proof->>'object_id' IS DISTINCT FROM sig.object_id::text OR proof->>'sha256' IS DISTINCT FROM sig.sha256
  OR sig.data_sha256 IS DISTINCT FROM f.sha256 OR sig.policy_hash IS DISTINCT FROM c.policy_hash OR sig.storage_id::text IS DISTINCT FROM b->>'storage_id'
  OR proof->'verification'->>'signature_sha256' IS DISTINCT FROM sig.sha256 OR proof->'verification'->>'primary_fingerprint' IS DISTINCT FROM k.definition->>'fingerprint'
  OR signature_expiry<=clock_timestamp() THEN RAISE EXCEPTION 'projection source signer or exact proof unavailable' USING ERRCODE='23514'; END IF;
 END IF;
 IF prior_policy.definition ? 'scanner' THEN
  ref:=prior_policy.definition->'scanner';proof:=c.report->'scanner';
  SELECT * INTO scan FROM scanner_profiles WHERE (tenant_id,partner_id,scanner_id,version,definition_hash,state)=(t,p,(ref->>'id')::uuid,(ref->>'version')::integer,ref->>'hash','active');
  scan_expiry:=(proof->>'valid_until')::timestamptz;
  IF scan.scanner_id IS NULL OR scan.valid_until<=clock_timestamp() OR proof->'profile' IS DISTINCT FROM ref
  OR proof->'result'->>'verdict' IS DISTINCT FROM 'clean' OR proof->'result'->>'backend' IS DISTINCT FROM 'clamd-instream-v1'
  OR proof->'result'->>'sha256' IS DISTINCT FROM f.sha256 OR proof->'result'->>'bytes_scanned' IS DISTINCT FROM f.size_bytes::text
  OR proof->'result'->>'configuration_sha256' IS DISTINCT FROM scan.definition->>'configuration_sha256'
  OR scan_expiry IS NULL OR scan_expiry<=clock_timestamp() OR scan_expiry>scan.valid_until
  THEN RAISE EXCEPTION 'projection source scan proof unavailable' USING ERRCODE='23514'; END IF;
 END IF;
 expiry:=least(signature_expiry,scan_expiry);
 IF (plan->>'source_proof_valid_until')::timestamptz IS DISTINCT FROM expiry THEN RAISE EXCEPTION 'projection source proof expiry differs' USING ERRCODE='23514'; END IF;
 IF b ? 'target' AND (b->'target'->'command'->>'operation' IS DISTINCT FROM 'publish'
 OR coalesce((b->'target'->'command'->>'replace')::boolean,false) OR b->'target'->'command' ? 'expected_revision'
 OR coalesce(b->'target'->>'entry_id','')<>'' OR coalesce((b->'target'->>'entry_revision')::bigint,0)<>0
 OR EXISTS(SELECT 1 FROM namespace_entries WHERE tenant_id=t AND partner_id=p AND path=CASE WHEN cr.namespace_root='/' THEN b->'target'->'command'->>'path' ELSE cr.namespace_root||(b->'target'->'command'->>'path') END AND NOT deleted))
 THEN RAISE EXCEPTION 'projection output must be create only' USING ERRCODE='23514'; END IF;
 IF plan->'projection'->>'schema_version' IS DISTINCT FROM '1' OR plan->'projection'->>'kind' IS DISTINCT FROM 'record_projection'
 OR plan->'projection'->>'engine' IS DISTINCT FROM 'freightctl-record-projection-v1' OR plan->'projection'->>'source_policy_hash' IS DISTINCT FROM c.policy_hash
 OR (plan->'projection'->>'output_kind') NOT IN ('csv','json_records')
 OR jsonb_typeof(plan->'projection'->'columns') IS DISTINCT FROM 'array' OR jsonb_array_length(plan->'projection'->'columns') NOT BETWEEN 1 AND 128
 THEN RAISE EXCEPTION 'projection rules are unqualified' USING ERRCODE='23514'; END IF;
 FOR mapping IN SELECT value FROM jsonb_array_elements(plan->'projection'->'columns') LOOP
  SELECT value INTO col FROM jsonb_array_elements(prior_policy.definition->'columns') WHERE value->>'name'=mapping->>'source';
  IF col IS NULL OR mapping->>'conversion' NOT IN ('identity','text','normalize_lf')
  OR (mapping->>'conversion'='normalize_lf' AND col->>'type'<>'text')
  OR mapping->>'missing' NOT IN ('preserve','empty','null','error') OR mapping->>'null' NOT IN ('preserve','empty','missing','error')
  OR mapping->>'empty' NOT IN ('preserve','missing','null','error') THEN RAISE EXCEPTION 'projection mapping is unqualified' USING ERRCODE='23514'; END IF;
  col:=(col-'width_bytes'-'padding')||jsonb_build_object('name',mapping->>'target','max_bytes',least((col->>'max_bytes')::integer,(plan->'projection'->>'max_record_bytes')::integer));
  IF mapping->>'conversion'='text' THEN col:=(col-'precision'-'scale')||jsonb_build_object('type','text'); END IF;
  columns:=columns||jsonb_build_array(col);
 END LOOP;
 shape:=jsonb_build_object('schema_version',CASE WHEN plan->'projection'->>'output_kind'='csv' THEN 1 ELSE 2 END,
 'kind',plan->'projection'->>'output_kind','columns',columns,'max_bytes',(plan->'projection'->>'max_bytes')::bigint,
 'max_rows',(plan->'projection'->>'max_rows')::bigint,'max_record_bytes',(plan->'projection'->>'max_record_bytes')::integer,
 'timeout_seconds',(plan->'projection'->>'timeout_seconds')::integer);
 IF shape IS DISTINCT FROM output_policy.definition-'signature'-'scanner' THEN RAISE EXCEPTION 'projection output data shape differs' USING ERRCODE='23514'; END IF;
END $$;

CREATE OR REPLACE FUNCTION freightctl_projection_acceptance_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r record_projections; e jsonb; policy intake_policies; proof jsonb;
BEGIN
 SELECT i.* INTO r FROM record_projections i JOIN record_projection_slots s USING(tenant_id,partner_id,projection_id) WHERE (s.tenant_id,s.partner_id,s.file_id)=(NEW.tenant_id,NEW.partner_id,NEW.file_id);
 SELECT payload INTO e FROM events WHERE (tenant_id,partner_id,event_id)=(NEW.tenant_id,NEW.partner_id,NEW.accepted_event_id);
 IF r.projection_id IS NULL THEN
  IF e ? 'record_projection' OR e->'schema_version'='5'::jsonb THEN RAISE EXCEPTION 'invented projection acceptance' USING ERRCODE='23514'; END IF;
  RETURN NEW;
 END IF;
 SELECT * INTO policy FROM intake_policies WHERE (tenant_id,partner_id)=(NEW.tenant_id,NEW.partner_id) AND state IN ('active','retired','revoked') ORDER BY version DESC LIMIT 1;
 proof:=e->'record_projection'->'report';
 IF r.state<>'running' OR r.lease_until<=clock_timestamp() OR r.actor_id IS DISTINCT FROM nullif(current_setting('freightctl.actor_id',true),'')::uuid
 OR e->'schema_version' IS DISTINCT FROM '5'::jsonb OR e->'record_projection'->>'id' IS DISTINCT FROM r.projection_id::text
 OR e->'record_projection'->>'definition_hash' IS DISTINCT FROM r.definition_hash OR e->'record_projection'->>'source_file_id' IS DISTINCT FROM r.source_file_id::text
 OR e->'record_projection'->'attempt' IS DISTINCT FROM jsonb_build_object('projection_id',r.projection_id::text,'attempt',r.attempts,'worker_id',r.worker_id::text)
 OR e->>'storage_id' IS DISTINCT FROM r.definition->'plan'->'context'->>'storage_id'
 OR NEW.policy IS DISTINCT FROM freightctl_intake_policy_prefix(policy.definition)||policy.definition_hash OR policy.state IS DISTINCT FROM 'active'
 OR proof->>'code' IS DISTINCT FROM 'transformed' OR proof->>'engine' IS DISTINCT FROM 'freightctl-record-projection-v1'
 OR proof->>'output_sha256' IS DISTINCT FROM NEW.sha256 OR proof->>'output_bytes' IS DISTINCT FROM NEW.size_bytes::text
 OR proof->>'output_contract_hash' IS DISTINCT FROM r.definition->'plan'->>'output_contract_hash'
 OR proof->>'rows' IS DISTINCT FROM proof->'source'->>'rows' OR proof->'source'->>'file_id' IS DISTINCT FROM r.source_file_id::text
 OR proof->'source'->>'sha256' IS DISTINCT FROM r.definition->'plan'->'context'->'source'->'file'->>'sha256'
 THEN RAISE EXCEPTION 'projection acceptance requires exact fenced intent and transformed bytes' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
