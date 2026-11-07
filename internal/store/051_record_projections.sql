-- Durable processing is separate from input checks and publication authority.
CREATE TABLE record_projections (
 tenant_id uuid NOT NULL, partner_id uuid NOT NULL, actor_id uuid NOT NULL,
 projection_id uuid NOT NULL, source_file_id uuid NOT NULL,
 definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object' AND octet_length(definition::text)<=32768),
 definition_hash text NOT NULL CHECK(definition_hash ~ '^[0-9a-f]{64}$'),
 state text NOT NULL CHECK(state IN ('proposed','approved','running','failed','cancelled','completed')),
 revision bigint NOT NULL CHECK(revision>0), attempts integer NOT NULL CHECK(attempts BETWEEN 0 AND 3),
 worker_id uuid, lease_until timestamptz, new_file_id uuid,
 result jsonb NOT NULL CHECK(jsonb_typeof(result)='object' AND octet_length(result::text)<=8192), changed_event_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,projection_id),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,source_file_id) REFERENCES files(tenant_id,partner_id,file_id),
 FOREIGN KEY(tenant_id,partner_id,new_file_id) REFERENCES files(tenant_id,partner_id,file_id),
 FOREIGN KEY(tenant_id,partner_id,changed_event_id) REFERENCES events(tenant_id,partner_id,event_id),
 CHECK((state='running')=(worker_id IS NOT NULL AND lease_until IS NOT NULL)),
 CHECK(state='running' OR (worker_id IS NULL AND lease_until IS NULL)),
 CHECK((state='completed')=(new_file_id IS NOT NULL)),
 CHECK((state IN ('completed','failed'))=(result<>'{}'::jsonb))
);
CREATE INDEX record_projection_active ON record_projections(tenant_id,partner_id,actor_id,state) WHERE state IN ('proposed','approved','running','failed');
CREATE TABLE record_projection_slots (
 tenant_id uuid NOT NULL, partner_id uuid NOT NULL, actor_id uuid NOT NULL,
 projection_id uuid NOT NULL, ordinal integer NOT NULL CHECK(ordinal BETWEEN 1 AND 3), file_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,file_id), UNIQUE(tenant_id,partner_id,projection_id,ordinal),
 FOREIGN KEY(tenant_id,partner_id,projection_id) REFERENCES record_projections(tenant_id,partner_id,projection_id),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id)
);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['record_projections','record_projection_slots'] LOOP
  EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('CREATE POLICY scope ON %I USING(tenant_id=nullif(current_setting(''freightctl.tenant_id'',true),'''')::uuid AND partner_id=nullif(current_setting(''freightctl.partner_id'',true),'''')::uuid AND actor_id=nullif(current_setting(''freightctl.actor_id'',true),'''')::uuid) WITH CHECK(tenant_id=nullif(current_setting(''freightctl.tenant_id'',true),'''')::uuid AND partner_id=nullif(current_setting(''freightctl.partner_id'',true),'''')::uuid AND actor_id=nullif(current_setting(''freightctl.actor_id'',true),'''')::uuid)',t);
 END LOOP;
END $$;
GRANT SELECT,INSERT,UPDATE ON record_projections TO freightctl_runtime;
GRANT SELECT,INSERT ON record_projection_slots TO freightctl_runtime;

CREATE FUNCTION freightctl_projection_current(t uuid,p uuid,a uuid,source uuid,plan jsonb) RETURNS void LANGUAGE plpgsql AS $$
DECLARE cr credentials; f files; c file_checks; prior_policy intake_policies; output_policy intake_policies;
 s jsonb; b jsonb; mapping jsonb; col jsonb; columns jsonb:='[]'::jsonb; shape jsonb;
 ref jsonb; proof jsonb; sig file_signatures; k pgp_keys; scan scanner_profiles;
 expiry timestamptz; signature_expiry timestamptz; scan_expiry timestamptz; expected_check jsonb;
BEGIN
 b:=plan->'context'; s:=b->'source';
 SELECT * INTO cr FROM credentials WHERE (tenant_id,partner_id,actor_id)=(t,p,a);
 IF cr.actor_id IS NULL OR a IS DISTINCT FROM nullif(current_setting('freightctl.actor_id',true),'')::uuid
 OR cr.revoked_at IS NOT NULL OR cr.expires_at<=clock_timestamp() OR cr.namespace_root<>'/'
 OR b->>'namespace_root' IS DISTINCT FROM cr.namespace_root OR b->>'authority_revision' IS DISTINCT FROM cr.authority_revision::text
 OR NOT cr.permissions @> ARRAY['admin','read','write','intake_manage','check_run','check_release']::text[]
 OR plan->>'schema_version' IS DISTINCT FROM '1' OR plan->>'profile' IS DISTINCT FROM 'held-record-projection-v1'
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
 SELECT * INTO output_policy FROM intake_policies WHERE (tenant_id,partner_id)=(t,p) ORDER BY version DESC LIMIT 1;
 IF prior_policy.policy_id IS NULL OR prior_policy.state NOT IN ('active','retired') OR output_policy.policy_id IS NULL OR output_policy.state<>'active'
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
 OR EXISTS(SELECT 1 FROM namespace_entries WHERE tenant_id=t AND partner_id=p AND path=b->'target'->'command'->>'path' AND NOT deleted))
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
REVOKE ALL ON FUNCTION freightctl_projection_current(uuid,uuid,uuid,uuid,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION freightctl_projection_current(uuid,uuid,uuid,uuid,jsonb) TO freightctl_runtime;

CREATE FUNCTION freightctl_projection_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE e jsonb; valid boolean:=false;
BEGIN
 SELECT payload INTO e FROM events WHERE (tenant_id,partner_id,event_id,actor_id,resource_id,kind)=(NEW.tenant_id,NEW.partner_id,NEW.changed_event_id,NEW.actor_id,NEW.projection_id,'RecordProjectionChanged');
 IF NOT (e ? 'lease_until') OR (e->>'lease_until')::timestamptz IS DISTINCT FROM NEW.lease_until OR e-'lease_until' IS DISTINCT FROM jsonb_build_object('id',NEW.projection_id::text,'source_file_id',NEW.source_file_id::text,'definition',NEW.definition,'definition_hash',NEW.definition_hash,'state',NEW.state,'revision',NEW.revision,'attempts',NEW.attempts,'worker_id',coalesce(NEW.worker_id::text,''),'new_file_id',coalesce(NEW.new_file_id::text,''),'result',NEW.result)
 THEN RAISE EXCEPTION 'projection requires its exact immutable event' USING ERRCODE='23514'; END IF;
 IF NEW.definition->>'schema_version' IS DISTINCT FROM '1' OR jsonb_typeof(NEW.definition->'staging_slots') IS DISTINCT FROM 'array' OR jsonb_array_length(NEW.definition->'staging_slots') IS DISTINCT FROM 3
 THEN RAISE EXCEPTION 'projection requires three preapproved slots' USING ERRCODE='23514'; END IF;
 IF TG_OP='INSERT' THEN
  PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id::text||':'||NEW.partner_id::text||':'||NEW.actor_id::text||':record-projections',0));
  valid:=NEW.state='proposed' AND NEW.revision=1 AND NEW.attempts=0;
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
CREATE TRIGGER projection_guard BEFORE INSERT OR UPDATE ON record_projections FOR EACH ROW EXECUTE FUNCTION freightctl_projection_guard();

CREATE FUNCTION freightctl_projection_slot_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r record_projections;
BEGIN
 SELECT * INTO r FROM record_projections WHERE (tenant_id,partner_id,projection_id,actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.projection_id,NEW.actor_id);
 IF r.projection_id IS NULL OR r.state<>'proposed' OR NEW.file_id=r.source_file_id OR to_jsonb(NEW.file_id::text) IS DISTINCT FROM r.definition->'staging_slots'->(NEW.ordinal-1)
 OR EXISTS(SELECT 1 FROM files WHERE (tenant_id,partner_id,file_id)=(NEW.tenant_id,NEW.partner_id,NEW.file_id))
 THEN RAISE EXCEPTION 'projection slot must be exact unused owned effect' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER projection_slot_guard BEFORE INSERT ON record_projection_slots FOR EACH ROW EXECUTE FUNCTION freightctl_projection_slot_guard();
CREATE TRIGGER projection_slots_immutable BEFORE UPDATE OR DELETE ON record_projection_slots FOR EACH ROW EXECUTE FUNCTION freightctl_recheck_immutable();
CREATE TRIGGER projections_no_delete BEFORE DELETE ON record_projections FOR EACH ROW EXECUTE FUNCTION freightctl_recheck_immutable();

CREATE FUNCTION freightctl_projection_acceptance_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r record_projections; e jsonb; policy intake_policies; proof jsonb;
BEGIN
 SELECT i.* INTO r FROM record_projections i JOIN record_projection_slots s USING(tenant_id,partner_id,projection_id) WHERE (s.tenant_id,s.partner_id,s.file_id)=(NEW.tenant_id,NEW.partner_id,NEW.file_id);
 SELECT payload INTO e FROM events WHERE (tenant_id,partner_id,event_id)=(NEW.tenant_id,NEW.partner_id,NEW.accepted_event_id);
 IF r.projection_id IS NULL THEN
  IF e ? 'record_projection' OR e->'schema_version'='5'::jsonb THEN RAISE EXCEPTION 'invented projection acceptance' USING ERRCODE='23514'; END IF;
  RETURN NEW;
 END IF;
 SELECT * INTO policy FROM intake_policies WHERE (tenant_id,partner_id)=(NEW.tenant_id,NEW.partner_id) ORDER BY version DESC LIMIT 1;
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
CREATE TRIGGER projection_acceptance_guard BEFORE INSERT ON files FOR EACH ROW EXECUTE FUNCTION freightctl_projection_acceptance_guard();
CREATE FUNCTION freightctl_projection_commit_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r record_projections;
BEGIN
 SELECT i.* INTO r FROM record_projections i JOIN record_projection_slots s USING(tenant_id,partner_id,projection_id) WHERE (s.tenant_id,s.partner_id,s.file_id)=(NEW.tenant_id,NEW.partner_id,NEW.file_id);
 IF r.projection_id IS NOT NULL AND (r.state<>'completed' OR r.new_file_id IS DISTINCT FROM NEW.file_id OR r.result->'file'->>'accepted_event_id' IS DISTINCT FROM NEW.accepted_event_id::text) THEN RAISE EXCEPTION 'projection output requires atomic completion' USING ERRCODE='23514'; END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER projection_commit_guard AFTER INSERT ON files DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION freightctl_projection_commit_guard();
CREATE FUNCTION freightctl_projection_slots_commit_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (SELECT count(*) FROM record_projection_slots WHERE (tenant_id,partner_id,projection_id,actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.projection_id,NEW.actor_id))<>3 THEN RAISE EXCEPTION 'projection requires three immutable slots' USING ERRCODE='23514'; END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER projection_slots_commit_guard AFTER INSERT OR UPDATE ON record_projections DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION freightctl_projection_slots_commit_guard();
REVOKE ALL ON FUNCTION freightctl_projection_guard(),freightctl_projection_slot_guard(),freightctl_projection_acceptance_guard(),freightctl_projection_commit_guard(),freightctl_projection_slots_commit_guard() FROM PUBLIC;
