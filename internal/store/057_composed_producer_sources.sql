-- Composed producer tasks consume one exact completed owned output only.
-- Existing profiles, approvals, checks, grants and persistence meanings remain.

CREATE OR REPLACE FUNCTION freightctl_producer_projection_plan_current(t uuid,p uuid,a uuid,plan jsonb) RETURNS void LANGUAGE plpgsql AS $$
DECLARE b processing_output_policies;i intake_policies;
BEGIN
 PERFORM pg_advisory_xact_lock_shared(hashtextextended(t::text||':'||p::text||':processing-output-policy:'||(plan->'context'->'policy'->>'id'),0));
 SELECT * INTO b FROM processing_output_policies WHERE (tenant_id,partner_id,policy_id,policy_version)=(t,p,(plan->'context'->'policy'->>'id')::uuid,(plan->'context'->'policy'->>'version')::integer);
 SELECT * INTO i FROM intake_policies WHERE (tenant_id,partner_id,policy_id,version)=(t,p,b.policy_id,b.policy_version);
 IF ((plan->>'schema_version'='3' AND plan->>'profile'='producer-record-projection-v1' AND NOT (plan ? 'source_origin')) OR (plan->>'schema_version'='4' AND plan->>'profile'='composed-producer-record-projection-v1' AND jsonb_typeof(plan->'source_origin')='object')) IS DISTINCT FROM true
 OR a IS DISTINCT FROM nullif(current_setting('freightctl.actor_id',true),'')::uuid
 OR b.policy_id IS NULL OR i.policy_id IS NULL OR i.state<>'output_active' OR i.revision<>1
 OR plan->'output_binding' IS DISTINCT FROM b.binding OR b.binding->>'policy_hash' IS DISTINCT FROM i.definition_hash
 OR plan->'context'->'policy' IS DISTINCT FROM jsonb_build_object('id',i.policy_id::text,'version',i.version,'hash',i.definition_hash)
 OR b.producer_id<>a OR freightctl_processing_output_producer_current(t,p,b.binding) IS DISTINCT FROM true
 OR plan->'context'->>'authority_revision' IS DISTINCT FROM b.binding->'producer'->>'authority_revision'
 OR encode(sha256(convert_to(plan->'context'->>'namespace_root','UTF8')),'hex') IS DISTINCT FROM b.binding->'producer'->>'root_policy_digest'
 THEN RAISE EXCEPTION 'producer projection requires exact current output contract and actor snapshot' USING ERRCODE='23514';END IF;
END $$;

CREATE OR REPLACE FUNCTION freightctl_generated_output_policy_current(t uuid,p uuid,f uuid,a uuid,id uuid,v integer,h text) RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE plan jsonb;
BEGIN
 SELECT r.definition->'plan' INTO plan FROM files x JOIN events e ON (e.tenant_id,e.partner_id,e.event_id,e.resource_id,e.kind)=(x.tenant_id,x.partner_id,x.accepted_event_id,x.file_id,'FileAccepted')
 JOIN record_projection_slots s ON (s.tenant_id,s.partner_id,s.actor_id,s.file_id)=(t,p,a,f)
 JOIN record_projections r ON (r.tenant_id,r.partner_id,r.projection_id,r.actor_id)=(s.tenant_id,s.partner_id,s.projection_id,s.actor_id)
 WHERE (x.tenant_id,x.partner_id,x.file_id,e.actor_id)=(t,p,f,a) AND ((e.payload->>'schema_version'='6' AND r.definition->>'schema_version'='3' AND r.definition->'plan'->>'profile'='producer-record-projection-v1') OR (e.payload->>'schema_version'='7' AND r.definition->>'schema_version'='4' AND r.definition->'plan'->>'profile'='composed-producer-record-projection-v1'))
 AND e.payload->'record_projection'->>'id'=r.projection_id::text AND e.payload->'record_projection'->>'definition_hash'=r.definition_hash
 AND r.definition->'plan'->'context'->'policy'=jsonb_build_object('id',id::text,'version',v,'hash',h)
 AND (r.state='running' AND r.lease_until>clock_timestamp() OR r.state='completed' AND r.new_file_id=f);
 IF plan IS NULL THEN RETURN false;END IF;
 PERFORM freightctl_producer_projection_plan_current(t,p,a,plan);
 RETURN true;
END $$;

CREATE OR REPLACE FUNCTION freightctl_projection_actor_current(t uuid,p uuid,a uuid,plan jsonb) RETURNS boolean LANGUAGE sql AS $$
 SELECT EXISTS(SELECT 1 FROM credentials c WHERE (c.tenant_id,c.partner_id,c.actor_id)=(t,p,a)
 AND a=nullif(current_setting('freightctl.actor_id',true),'')::uuid AND c.revoked_at IS NULL
 AND (c.expires_at IS NULL OR c.expires_at>clock_timestamp()) AND c.namespace_root=plan->'context'->>'namespace_root'
 AND ((plan->>'schema_version'='1' AND plan->>'profile'='held-record-projection-v1' AND c.namespace_root='/'
 AND c.permissions @> ARRAY['admin','read','write','intake_manage','check_run','check_release']::text[])
 OR (((plan->>'schema_version'='2' AND plan->>'profile'='scoped-record-projection-v1') OR (plan->>'schema_version'='3' AND plan->>'profile'='producer-record-projection-v1') OR (plan->>'schema_version'='4' AND plan->>'profile'='composed-producer-record-projection-v1'))
 AND c.permissions @> ARRAY['read','write','check_run']::text[] AND c.permissions && ARRAY['workflow_manage','workflow_approve','workflow_execute']::text[])))
$$;

CREATE FUNCTION freightctl_produced_source_current(t uuid,p uuid,a uuid,source uuid,origin jsonb) RETURNS void LANGUAGE plpgsql AS $$
DECLARE f files;r record_projections;e events;b processing_output_policies;expected jsonb;
BEGIN
 SELECT * INTO f FROM files WHERE (tenant_id,partner_id,file_id)=(t,p,source);
 SELECT * INTO e FROM events WHERE (tenant_id,partner_id,event_id,resource_id,actor_id,kind)=(t,p,f.accepted_event_id,source,a,'FileAccepted');
 SELECT i.* INTO r FROM record_projections i JOIN record_projection_slots s USING(tenant_id,partner_id,projection_id,actor_id)
 WHERE (i.tenant_id,i.partner_id,i.actor_id,i.new_file_id,i.state,s.file_id)=(t,p,a,source,'completed',source)
 AND i.projection_id::text=e.payload->'record_projection'->>'id' AND i.definition_hash=e.payload->'record_projection'->>'definition_hash'
 AND ((i.definition->>'schema_version'='3' AND i.definition->'plan'->>'profile'='producer-record-projection-v1' AND e.payload->>'schema_version'='6') OR (i.definition->>'schema_version'='4' AND i.definition->'plan'->>'profile'='composed-producer-record-projection-v1' AND e.payload->>'schema_version'='7'));
 IF f.file_id IS NULL OR e.event_id IS NULL OR r.projection_id IS NULL
 OR e.payload->>'size_bytes' IS DISTINCT FROM f.size_bytes::text OR e.payload->>'sha256' IS DISTINCT FROM f.sha256 OR e.payload->>'policy' IS DISTINCT FROM f.policy
 THEN RAISE EXCEPTION 'composed source requires exact owned completed acceptance and slot' USING ERRCODE='23514';END IF;
 PERFORM freightctl_producer_projection_plan_current(t,p,a,r.definition->'plan');
 SELECT * INTO b FROM processing_output_policies WHERE (tenant_id,partner_id,policy_id,policy_version)=(t,p,(r.definition->'plan'->'context'->'policy'->>'id')::uuid,(r.definition->'plan'->'context'->'policy'->>'version')::integer);
 expected:=jsonb_build_object('profile','owned-produced-source-v1','file',jsonb_build_object('id',f.file_id::text,'size_bytes',f.size_bytes,'sha256',f.sha256,'policy',f.policy,'accepted_event_id',f.accepted_event_id::text),'projection_id',r.projection_id::text,'projection_hash',r.definition_hash,'producer_binding',b.binding);
 IF origin IS DISTINCT FROM expected THEN RAISE EXCEPTION 'composed source provenance differs from immutable lineage' USING ERRCODE='23514';END IF;
END $$;
REVOKE ALL ON FUNCTION freightctl_produced_source_current(uuid,uuid,uuid,uuid,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION freightctl_produced_source_current(uuid,uuid,uuid,uuid,jsonb) TO freightctl_runtime;

CREATE OR REPLACE FUNCTION freightctl_projection_current_composed(t uuid,p uuid,a uuid,source uuid,plan jsonb) RETURNS void LANGUAGE plpgsql AS $$
DECLARE cr credentials; f files; c file_checks; prior_policy intake_policies; output_policy intake_policies;
 s jsonb; b jsonb; mapping jsonb; col jsonb; columns jsonb:='[]'::jsonb; shape jsonb;
 ref jsonb; proof jsonb; sig file_signatures; k pgp_keys; scan scanner_profiles;
 expiry timestamptz; signature_expiry timestamptz; scan_expiry timestamptz; expected_check jsonb;
BEGIN
 PERFORM freightctl_producer_projection_plan_current(t,p,a,plan);
 PERFORM freightctl_produced_source_current(t,p,a,source,plan->'source_origin');
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
 SELECT * INTO output_policy FROM intake_policies WHERE (tenant_id,partner_id,policy_id,version,definition_hash,state)=(t,p,(b->'policy'->>'id')::uuid,(b->'policy'->>'version')::integer,b->'policy'->>'hash','output_active');
 IF prior_policy.policy_id IS NULL OR prior_policy.state<>'output_active' OR output_policy.policy_id IS NULL OR output_policy.state<>'output_active'
 OR plan->'source_policy' IS DISTINCT FROM jsonb_build_object('id',c.policy_id::text,'version',c.policy_version,'hash',c.policy_hash)
 OR b->'policy' IS DISTINCT FROM jsonb_build_object('id',output_policy.policy_id::text,'version',output_policy.version,'hash',output_policy.definition_hash)
 OR f.policy IS DISTINCT FROM freightctl_intake_policy_prefix(prior_policy.definition)||c.policy_hash
 OR c.report->>'file_id' IS DISTINCT FROM source::text OR c.report->>'sha256' IS DISTINCT FROM f.sha256
 OR c.report->>'bytes_read' IS DISTINCT FROM f.size_bytes::text OR c.report->>'policy_hash' IS DISTINCT FROM c.policy_hash
 OR c.report_hash !~ '^[0-9a-f]{64}$'
 OR c.report->>'code' IS DISTINCT FROM (CASE prior_policy.definition->>'kind' WHEN 'csv' THEN 'valid_csv' WHEN 'json_records' THEN 'valid_json_records' WHEN 'fixed_width' THEN 'valid_fixed_width' WHEN 'xml_records' THEN 'valid_xml_records' WHEN 'xlsx_records' THEN 'valid_xlsx_records' END)
 OR c.report->>'engine' IS DISTINCT FROM (CASE prior_policy.definition->>'kind' WHEN 'csv' THEN 'freightctl-csv-v1' WHEN 'json_records' THEN 'freightctl-json-records-v1' WHEN 'fixed_width' THEN 'freightctl-fixed-width-v1' WHEN 'xml_records' THEN 'freightctl-xml-records-v1' WHEN 'xlsx_records' THEN 'freightctl-xlsx-records-v1' END)
 THEN RAISE EXCEPTION 'projection source or output policy differs' USING ERRCODE='23514'; END IF;
 IF b->>'signature_mode' IS DISTINCT FROM (CASE WHEN output_policy.definition ? 'signature' THEN 'require_new' ELSE 'not_required' END)
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

CREATE OR REPLACE FUNCTION freightctl_projection_current(t uuid,p uuid,a uuid,source uuid,plan jsonb) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
 IF plan->>'schema_version'<>'4' AND plan ? 'source_origin' THEN RAISE EXCEPTION 'legacy projection cannot acquire source composition authority' USING ERRCODE='23514';END IF;
 IF plan->>'schema_version'='4' AND plan->>'profile'='composed-producer-record-projection-v1' THEN
  PERFORM freightctl_projection_current_composed(t,p,a,source,plan);
 ELSIF plan->>'schema_version'='3' AND plan->>'profile'='producer-record-projection-v1' THEN
  PERFORM freightctl_projection_current_producer(t,p,a,source,plan);
 ELSE
  IF plan ? 'output_binding' THEN RAISE EXCEPTION 'legacy projection cannot acquire producer output authority' USING ERRCODE='23514';END IF;
  PERFORM freightctl_projection_current_default(t,p,a,source,plan);
 END IF;
END $$;

REVOKE ALL ON FUNCTION freightctl_projection_current_composed(uuid,uuid,uuid,uuid,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION freightctl_projection_current_composed(uuid,uuid,uuid,uuid,jsonb) TO freightctl_runtime;

CREATE OR REPLACE FUNCTION freightctl_processing_current(t uuid,p uuid,a uuid,d jsonb,live boolean) RETURNS void LANGUAGE plpgsql AS $$
DECLARE w workflow_revisions;r workflow_runs;c credentials;b jsonb;task jsonb;context jsonb;
BEGIN
 b:=d->'workflow';context:=d->'plan'->'context';
 SELECT * INTO w FROM workflow_revisions WHERE (tenant_id,partner_id,actor_id,workflow_id,version)=(t,p,a,(b->>'workflow_id')::uuid,(b->>'workflow_version')::integer);
 IF live THEN
  PERFORM 1 FROM workflow_revisions WHERE (tenant_id,partner_id,workflow_id,version)=(t,p,w.workflow_id,w.version) FOR SHARE;
  -- Re-read after acquiring the lock; a concurrent revocation must be observed.
  SELECT * INTO w FROM workflow_revisions WHERE (tenant_id,partner_id,actor_id,workflow_id,version)=(t,p,a,(b->>'workflow_id')::uuid,(b->>'workflow_version')::integer);
 END IF;
 SELECT * INTO r FROM workflow_runs WHERE (tenant_id,partner_id,actor_id,run_id)=(t,p,a,(b->>'run_id')::uuid);
 SELECT * INTO c FROM credentials WHERE (tenant_id,partner_id,actor_id)=(t,p,a);
 task:=w.definition->'processing';
 IF NOT ((d->>'schema_version'='2' AND d->'plan'->>'profile'='scoped-record-projection-v1') OR (d->>'schema_version'='3' AND d->'plan'->>'profile'='producer-record-projection-v1') OR (d->>'schema_version'='4' AND d->'plan'->>'profile'='composed-producer-record-projection-v1'))
 OR w.workflow_id IS NULL OR r.run_id IS NULL OR c.actor_id IS NULL
 OR a IS DISTINCT FROM nullif(current_setting('freightctl.actor_id',true),'')::uuid
 OR c.revoked_at IS NOT NULL OR c.expires_at<=clock_timestamp()
 OR NOT c.permissions @> ARRAY['read','write','check_run','workflow_execute']::text[]
 OR c.namespace_root IS DISTINCT FROM context->>'namespace_root' OR c.authority_revision::text IS DISTINCT FROM context->>'authority_revision'
 OR w.definition->>'schema_version' IS DISTINCT FROM '3' OR task->>'kind' IS DISTINCT FROM 'records.project'
 OR w.definition_hash IS DISTINCT FROM b->>'workflow_hash' OR w.approval_authority<>c.authority_revision
 OR task->>'id' IS DISTINCT FROM b->>'step_id' OR task->'definition' IS DISTINCT FROM d->'plan'->'projection'
 OR task->'output_policy' IS DISTINCT FROM context->'policy' OR task->>'reason' IS DISTINCT FROM context->>'reason'
 OR coalesce(task->>'target_path','') IS DISTINCT FROM coalesce(context->'target'->'command'->>'path','')
 OR (r.workflow_id,r.workflow_version,r.workflow_hash) IS DISTINCT FROM (w.workflow_id,w.version,w.definition_hash)
 OR r.file_id::text IS DISTINCT FROM context->'source'->'file'->>'id' OR r.source IS DISTINCT FROM context->'source'->'file'
 OR r.namespace_root IS DISTINCT FROM c.namespace_root OR r.authority_revision<>c.authority_revision
 OR r.storage_id::text IS DISTINCT FROM context->>'storage_id'
 OR (live AND (w.state<>'approved' OR r.state='cancelled'))
 THEN RAISE EXCEPTION 'processing requires exact approved task,run,source and current scope' USING ERRCODE='23514'; END IF;
END $$;

CREATE OR REPLACE FUNCTION freightctl_projection_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE e jsonb; valid boolean:=false;
BEGIN
 IF freightctl_projection_actor_current(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.definition->'plan') IS DISTINCT FROM true THEN RAISE EXCEPTION 'projection actor profile or namespace changed' USING ERRCODE='23514'; END IF;
 IF NEW.definition->>'schema_version'='1' AND NEW.definition->'plan'->>'profile'='scoped-record-projection-v1' AND NOT EXISTS(SELECT 1 FROM credentials c WHERE (c.tenant_id,c.partner_id,c.actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id) AND CASE WHEN NEW.state IN ('proposed','cancelled') THEN 'workflow_manage' WHEN NEW.state='approved' THEN 'workflow_approve' ELSE 'workflow_execute' END=ANY(c.permissions)) THEN RAISE EXCEPTION 'scoped projection action requires its workflow grant' USING ERRCODE='23514'; END IF;
 SELECT payload INTO e FROM events WHERE (tenant_id,partner_id,event_id,actor_id,resource_id,kind)=(NEW.tenant_id,NEW.partner_id,NEW.changed_event_id,NEW.actor_id,NEW.projection_id,'RecordProjectionChanged');
 IF NOT (e ? 'lease_until') OR (e->>'lease_until')::timestamptz IS DISTINCT FROM NEW.lease_until OR e-'lease_until' IS DISTINCT FROM jsonb_build_object('id',NEW.projection_id::text,'source_file_id',NEW.source_file_id::text,'definition',NEW.definition,'definition_hash',NEW.definition_hash,'state',NEW.state,'revision',NEW.revision,'attempts',NEW.attempts,'worker_id',coalesce(NEW.worker_id::text,''),'new_file_id',coalesce(NEW.new_file_id::text,''),'result',NEW.result)
 THEN RAISE EXCEPTION 'projection requires its exact immutable event' USING ERRCODE='23514'; END IF;
 IF NEW.definition->>'schema_version' NOT IN ('1','2','3','4') OR ((NEW.definition->>'schema_version'='3') IS DISTINCT FROM (NEW.definition->'plan'->>'profile'='producer-record-projection-v1')) OR ((NEW.definition->>'schema_version'='4') IS DISTINCT FROM (NEW.definition->'plan'->>'profile'='composed-producer-record-projection-v1')) OR ((NEW.definition->>'schema_version' IN ('2','3','4')) IS DISTINCT FROM (NEW.definition ? 'workflow')) OR jsonb_typeof(NEW.definition->'staging_slots') IS DISTINCT FROM 'array' OR jsonb_array_length(NEW.definition->'staging_slots') IS DISTINCT FROM 3
 THEN RAISE EXCEPTION 'projection requires three preapproved slots' USING ERRCODE='23514'; END IF;
 IF TG_OP='INSERT' THEN
  PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id::text||':'||NEW.partner_id::text||':'||NEW.actor_id::text||':record-projections',0));
  valid:=((NEW.definition->>'schema_version'='1' AND NEW.state='proposed') OR (NEW.definition->>'schema_version' IN ('2','3','4') AND NEW.state='approved')) AND NEW.revision=1 AND NEW.attempts=0;
  IF (SELECT count(*) FROM record_projections WHERE actor_id=NEW.actor_id AND state IN ('proposed','approved','running','failed'))>=16 THEN RAISE EXCEPTION 'projection queue saturated' USING ERRCODE='23514'; END IF;
 ELSE
  IF (NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.projection_id,NEW.source_file_id,NEW.definition,NEW.definition_hash) IS DISTINCT FROM (OLD.tenant_id,OLD.partner_id,OLD.actor_id,OLD.projection_id,OLD.source_file_id,OLD.definition,OLD.definition_hash) OR NEW.revision<>OLD.revision+1 THEN RAISE EXCEPTION 'projection definition immutable' USING ERRCODE='23514'; END IF;
  IF NEW.state='approved' THEN valid:=OLD.state='proposed' AND NEW.attempts=0;
  ELSIF NEW.state='running' THEN valid:=(OLD.state IN ('approved','failed') OR (OLD.state='running' AND OLD.lease_until<=clock_timestamp())) AND NEW.attempts=OLD.attempts+1 AND NEW.worker_id IS NOT NULL AND NEW.lease_until>clock_timestamp() AND NEW.lease_until<=clock_timestamp()+interval '71 seconds';
  ELSIF NEW.state='cancelled' THEN valid:=(OLD.state IN ('proposed','approved','failed') OR (OLD.state='running' AND OLD.lease_until<=clock_timestamp())) AND NEW.attempts=OLD.attempts;
  ELSIF NEW.state IN ('failed','completed') THEN valid:=OLD.state='running' AND OLD.lease_until>clock_timestamp() AND NEW.attempts=OLD.attempts AND NEW.result->'attempt' IS NOT DISTINCT FROM jsonb_build_object('projection_id',OLD.projection_id::text,'attempt',OLD.attempts,'worker_id',OLD.worker_id::text);
  END IF;
 END IF;
 IF valid IS DISTINCT FROM true THEN RAISE EXCEPTION 'invalid or unfenced projection transition' USING ERRCODE='23514'; END IF;
 IF NEW.definition->>'schema_version' IN ('2','3','4') THEN PERFORM freightctl_processing_current(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.definition,NEW.state NOT IN ('cancelled','failed')); END IF;
 IF NEW.state NOT IN ('cancelled','failed') THEN PERFORM freightctl_projection_current(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.source_file_id,NEW.definition->'plan'); END IF;
 IF NEW.state='completed' THEN
  IF NEW.result->>'kind' IS DISTINCT FROM 'record_projection_output' OR NEW.result->>'acceptance' IS DISTINCT FROM 'durable-held-pending-checks-and-release'
  OR NOT EXISTS(SELECT 1 FROM record_projection_slots s JOIN files f ON (f.tenant_id,f.partner_id,f.file_id)=(s.tenant_id,s.partner_id,s.file_id)
   JOIN file_checks c ON (c.tenant_id,c.partner_id,c.file_id)=(f.tenant_id,f.partner_id,f.file_id)
   WHERE (s.tenant_id,s.partner_id,s.projection_id,s.file_id)=(NEW.tenant_id,NEW.partner_id,NEW.projection_id,NEW.new_file_id)
   AND NEW.result->'file'=jsonb_build_object('id',f.file_id::text,'size_bytes',f.size_bytes,'sha256',f.sha256,'policy',f.policy,'accepted_event_id',f.accepted_event_id::text)
   AND c.state='held' AND c.attempts=0 AND c.report='{}'::jsonb AND c.report_hash=''
   AND c.policy_hash=NEW.definition->'plan'->'context'->'policy'->>'hash'
   AND c.binding->>'storage_id'=NEW.definition->'plan'->'context'->>'storage_id'
   AND c.binding->>'namespace_root'=NEW.definition->'plan'->'context'->>'namespace_root'
   AND c.binding->>'authority_revision'=NEW.definition->'plan'->'context'->>'authority_revision'
   AND c.binding->'target' IS NOT DISTINCT FROM (CASE WHEN NEW.definition->'plan'->'context' ? 'target' THEN NEW.definition->'plan'->'context'->'target'->'command'||jsonb_build_object('file_id',f.file_id::text) ELSE 'null'::jsonb END)
   AND NOT EXISTS(SELECT 1 FROM file_signatures sig WHERE (sig.tenant_id,sig.partner_id,sig.file_id)=(f.tenant_id,f.partner_id,f.file_id)))
  THEN RAISE EXCEPTION 'projection completion requires atomic fresh held output' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION freightctl_processing_membership_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.definition->>'schema_version' IN ('2','3','4') THEN
  IF NOT EXISTS(SELECT 1 FROM workflow_processing b WHERE (b.tenant_id,b.partner_id,b.actor_id,b.projection_id,b.definition_hash)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.projection_id,NEW.definition_hash) AND b.run_id::text=NEW.definition->'workflow'->>'run_id')
  THEN RAISE EXCEPTION 'workflow processing intent must bind atomically to its run' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION freightctl_processing_review_effect_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE w uuid;v integer;h text;b jsonb;current_actor uuid;
BEGIN
 current_actor:=nullif(current_setting('freightctl.actor_id',true),'')::uuid;
 IF TG_TABLE_NAME='workflow_revisions' THEN
  IF NEW.definition->>'schema_version'<>'3' OR NEW.state<>'approved' THEN RETURN NEW;END IF;
  w:=NEW.workflow_id;v:=NEW.version;h:=NEW.definition_hash;
  IF TG_OP='UPDATE' AND OLD.state='draft' AND NOT EXISTS(SELECT 1 FROM processing_workflow_reviews r WHERE (r.tenant_id,r.partner_id,r.actor_id,r.workflow_id,r.workflow_version)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,w,v) AND r.adopted_revision>0)
  AND NOT EXISTS(SELECT 1 FROM credentials c WHERE (c.tenant_id,c.partner_id,c.actor_id)=(NEW.tenant_id,NEW.partner_id,current_actor) AND c.actor_id=NEW.actor_id AND c.authority_revision=NEW.approval_authority AND 'workflow_approve'=ANY(c.permissions) AND c.revoked_at IS NULL AND (c.expires_at IS NULL OR c.expires_at>clock_timestamp())) THEN RAISE EXCEPTION 'processing approval requires ordinary approval permission or exact independent adoption' USING ERRCODE='42501';END IF;
 ELSIF TG_TABLE_NAME='workflow_runs' THEN
  IF NEW.state NOT IN ('queued','running','succeeded') THEN RETURN NEW;END IF;
  IF NOT EXISTS(SELECT 1 FROM workflow_revisions c WHERE (c.tenant_id,c.partner_id,c.actor_id,c.workflow_id,c.version)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.workflow_id,NEW.workflow_version) AND c.definition->>'schema_version'='3') THEN RETURN NEW;END IF;
  w:=NEW.workflow_id;v:=NEW.workflow_version;h:=NEW.workflow_hash;
 ELSE
  IF NEW.definition->>'schema_version' NOT IN ('2','3','4') OR NOT (NEW.definition ? 'workflow') OR NEW.state IN ('cancelled','failed') THEN RETURN NEW;END IF;
  b:=NEW.definition->'workflow';w:=(b->>'workflow_id')::uuid;v:=(b->>'workflow_version')::integer;h:=b->>'workflow_hash';
 END IF;
 IF NOT freightctl_processing_review_current(NEW.tenant_id,NEW.partner_id,NEW.actor_id,w,v,h) THEN RAISE EXCEPTION 'independent processing approval expired,withdrawn or authority changed' USING ERRCODE='42501';END IF;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION freightctl_projection_slot_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r record_projections;
BEGIN
 SELECT * INTO r FROM record_projections WHERE (tenant_id,partner_id,projection_id,actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.projection_id,NEW.actor_id);
 IF r.projection_id IS NULL OR NOT ((r.definition->>'schema_version'='1' AND r.state='proposed') OR (r.definition->>'schema_version' IN ('2','3','4') AND r.state='approved' AND r.revision=1 AND r.attempts=0)) OR NEW.file_id=r.source_file_id OR to_jsonb(NEW.file_id::text) IS DISTINCT FROM r.definition->'staging_slots'->(NEW.ordinal-1)
 OR EXISTS(SELECT 1 FROM files WHERE (tenant_id,partner_id,file_id)=(NEW.tenant_id,NEW.partner_id,NEW.file_id))
 THEN RAISE EXCEPTION 'projection slot must be exact unused owned effect' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION freightctl_projection_acceptance_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r record_projections; e jsonb; policy intake_policies; proof jsonb;
BEGIN
 SELECT i.* INTO r FROM record_projections i JOIN record_projection_slots s USING(tenant_id,partner_id,projection_id) WHERE (s.tenant_id,s.partner_id,s.file_id)=(NEW.tenant_id,NEW.partner_id,NEW.file_id);
 SELECT payload INTO e FROM events WHERE (tenant_id,partner_id,event_id)=(NEW.tenant_id,NEW.partner_id,NEW.accepted_event_id);
 IF r.projection_id IS NULL THEN
  IF e ? 'record_projection' OR e->'schema_version' IN ('5'::jsonb,'6'::jsonb,'7'::jsonb) THEN RAISE EXCEPTION 'invented projection acceptance' USING ERRCODE='23514'; END IF;
  RETURN NEW;
 END IF;
 IF r.definition->>'schema_version' IN ('3','4') THEN
  PERFORM freightctl_producer_projection_plan_current(NEW.tenant_id,NEW.partner_id,r.actor_id,r.definition->'plan');
  IF r.definition->>'schema_version'='4' THEN PERFORM freightctl_produced_source_current(NEW.tenant_id,NEW.partner_id,r.actor_id,r.source_file_id,r.definition->'plan'->'source_origin');END IF;
  SELECT * INTO policy FROM intake_policies WHERE (tenant_id,partner_id,policy_id,version,definition_hash,state)=(NEW.tenant_id,NEW.partner_id,(r.definition->'plan'->'context'->'policy'->>'id')::uuid,(r.definition->'plan'->'context'->'policy'->>'version')::integer,r.definition->'plan'->'context'->'policy'->>'hash','output_active');
 ELSE
  SELECT * INTO policy FROM intake_policies WHERE (tenant_id,partner_id)=(NEW.tenant_id,NEW.partner_id) AND state IN ('active','retired','revoked') ORDER BY version DESC LIMIT 1;
 END IF;
 proof:=e->'record_projection'->'report';
 IF r.state<>'running' OR r.lease_until<=clock_timestamp() OR r.actor_id IS DISTINCT FROM nullif(current_setting('freightctl.actor_id',true),'')::uuid
 OR e->'schema_version' IS DISTINCT FROM (CASE WHEN r.definition->>'schema_version' IN ('3','4') THEN CASE WHEN r.definition->>'schema_version'='4' THEN '7'::jsonb ELSE '6'::jsonb END ELSE '5'::jsonb END) OR e->'record_projection'->>'id' IS DISTINCT FROM r.projection_id::text
 OR e->'record_projection'->>'definition_hash' IS DISTINCT FROM r.definition_hash OR e->'record_projection'->>'source_file_id' IS DISTINCT FROM r.source_file_id::text
 OR e->'record_projection'->'attempt' IS DISTINCT FROM jsonb_build_object('projection_id',r.projection_id::text,'attempt',r.attempts,'worker_id',r.worker_id::text)
 OR e->>'storage_id' IS DISTINCT FROM r.definition->'plan'->'context'->>'storage_id'
 OR NEW.policy IS DISTINCT FROM freightctl_intake_policy_prefix(policy.definition)||policy.definition_hash OR policy.state IS DISTINCT FROM (CASE WHEN r.definition->>'schema_version' IN ('3','4') THEN 'output_active' ELSE 'active' END)
 OR proof->>'code' IS DISTINCT FROM 'transformed' OR proof->>'engine' IS DISTINCT FROM 'freightctl-record-projection-v1'
 OR proof->>'output_sha256' IS DISTINCT FROM NEW.sha256 OR proof->>'output_bytes' IS DISTINCT FROM NEW.size_bytes::text
 OR proof->>'output_contract_hash' IS DISTINCT FROM r.definition->'plan'->>'output_contract_hash'
 OR proof->>'rows' IS DISTINCT FROM proof->'source'->>'rows' OR proof->'source'->>'file_id' IS DISTINCT FROM r.source_file_id::text
 OR proof->'source'->>'sha256' IS DISTINCT FROM r.definition->'plan'->'context'->'source'->'file'->>'sha256'
 THEN RAISE EXCEPTION 'projection acceptance requires exact fenced intent and transformed bytes' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
