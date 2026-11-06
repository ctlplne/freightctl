-- A third explicit intake format retains existing immutable custody and release guards.
ALTER TABLE files DROP CONSTRAINT files_policy_check;
ALTER TABLE files ADD CONSTRAINT files_policy_check CHECK(policy='integrity-only-v1' OR policy ~ '^intake-(csv-v1|json-records-v1|fixed-width-v1):[0-9a-f]{64}$');

CREATE OR REPLACE FUNCTION freightctl_intake_policy_prefix(d jsonb) RETURNS text LANGUAGE sql IMMUTABLE STRICT AS $$
 SELECT CASE WHEN d->'schema_version'='1'::jsonb AND d->'kind'='"csv"'::jsonb THEN 'intake-csv-v1:'
             WHEN d->'schema_version'='2'::jsonb AND d->'kind'='"json_records"'::jsonb THEN 'intake-json-records-v1:'
             WHEN d->'schema_version'='3'::jsonb AND d->'kind'='"fixed_width"'::jsonb THEN 'intake-fixed-width-v1:'
             ELSE NULL END
$$;
CREATE OR REPLACE FUNCTION freightctl_controlled_policy_hash(policy text) RETURNS text LANGUAGE sql IMMUTABLE STRICT AS $$
 SELECT CASE WHEN policy ~ '^intake-(csv-v1|json-records-v1|fixed-width-v1):[0-9a-f]{64}$' THEN split_part(policy,':',2) ELSE NULL END
$$;

-- Existing freightctl_file_check_guard from 010_intake.sql;other guards retained.
CREATE OR REPLACE FUNCTION freightctl_file_check_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE p jsonb; valid boolean:=false;
BEGIN
 SELECT payload INTO p FROM events WHERE (tenant_id,partner_id,event_id)=(NEW.tenant_id,NEW.partner_id,NEW.changed_event_id) AND actor_id=NEW.actor_id AND resource_id=NEW.file_id AND kind='FileCheckChanged';
 IF p IS NULL OR p->>'file_id' IS DISTINCT FROM NEW.file_id::text OR p->>'policy_id' IS DISTINCT FROM NEW.policy_id::text OR p->>'policy_version' IS DISTINCT FROM NEW.policy_version::text OR p->>'policy_hash' IS DISTINCT FROM NEW.policy_hash OR p->'binding' IS DISTINCT FROM NEW.binding OR p->>'state' IS DISTINCT FROM NEW.state OR p->>'revision' IS DISTINCT FROM NEW.revision::text OR p->>'attempts' IS DISTINCT FROM NEW.attempts::text OR p->>'worker_id' IS DISTINCT FROM coalesce(NEW.worker_id::text,'') OR (p->>'lease_until')::timestamptz IS DISTINCT FROM NEW.lease_until OR p->'report' IS DISTINCT FROM NEW.report OR p->>'report_hash' IS DISTINCT FROM NEW.report_hash OR p->>'code' IS DISTINCT FROM NEW.code THEN RAISE EXCEPTION 'file check requires its exact event' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN
  valid:=NEW.state='held' AND NEW.revision=1 AND NEW.attempts=0 AND NEW.report='{}'::jsonb AND NEW.report_hash='' AND EXISTS(SELECT 1 FROM files f JOIN events e ON (e.tenant_id,e.partner_id,e.event_id)=(f.tenant_id,f.partner_id,f.accepted_event_id) WHERE (f.tenant_id,f.partner_id,f.file_id,freightctl_controlled_policy_hash(f.policy),e.actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.file_id,NEW.policy_hash,NEW.actor_id) AND NEW.binding->'file'=jsonb_build_object('id',f.file_id::text,'size_bytes',f.size_bytes,'sha256',f.sha256,'policy',f.policy,'accepted_event_id',f.accepted_event_id::text)) AND EXISTS(SELECT 1 FROM intake_policies i WHERE (i.tenant_id,i.partner_id,i.policy_id,i.version,i.definition_hash,i.state)=(NEW.tenant_id,NEW.partner_id,NEW.policy_id,NEW.policy_version,NEW.policy_hash,'active') AND freightctl_intake_policy_prefix(i.definition)||NEW.policy_hash=NEW.binding->'file'->>'policy');
 ELSE
  IF (NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.file_id,NEW.policy_id,NEW.policy_version,NEW.policy_hash,NEW.binding) IS DISTINCT FROM (OLD.tenant_id,OLD.partner_id,OLD.actor_id,OLD.file_id,OLD.policy_id,OLD.policy_version,OLD.policy_hash,OLD.binding) OR NEW.revision<>OLD.revision+1 THEN RAISE EXCEPTION 'file check binding is immutable' USING ERRCODE='23514';END IF;
  IF NEW.state='running' THEN valid:=(OLD.state IN ('held','failed') OR (OLD.state='running' AND OLD.lease_until<=clock_timestamp())) AND NEW.attempts=OLD.attempts+1 AND NEW.lease_until>clock_timestamp() AND NEW.lease_until<=clock_timestamp()+interval '71 seconds' AND NEW.report='{}'::jsonb AND NEW.report_hash='';
  ELSIF OLD.state='running' THEN valid:=NEW.state IN ('passed','rejected','failed') AND OLD.lease_until>clock_timestamp() AND NEW.attempts=OLD.attempts;
  ELSE valid:=OLD.state='passed' AND NEW.state='released' AND NEW.attempts=OLD.attempts AND NEW.report=OLD.report AND NEW.report_hash=OLD.report_hash;END IF;
 END IF;
 IF NEW.state IN ('passed','released') THEN
  valid:=valid AND EXISTS(SELECT 1 FROM intake_policies format_policy WHERE (format_policy.tenant_id,format_policy.partner_id,format_policy.policy_id,format_policy.version,format_policy.definition_hash,format_policy.state)=(NEW.tenant_id,NEW.partner_id,NEW.policy_id,NEW.policy_version,NEW.policy_hash,'active') AND ((format_policy.definition->'schema_version'='1'::jsonb AND format_policy.definition->'kind'='"csv"'::jsonb AND NEW.report->>'code'='valid_csv' AND NEW.report->>'engine'='freightctl-csv-v1') OR (format_policy.definition->'schema_version'='2'::jsonb AND format_policy.definition->'kind'='"json_records"'::jsonb AND NEW.report->>'code'='valid_json_records' AND NEW.report->>'engine'='freightctl-json-records-v1') OR (format_policy.definition->'schema_version'='3'::jsonb AND format_policy.definition->'kind'='"fixed_width"'::jsonb AND NEW.report->>'code'='valid_fixed_width' AND NEW.report->>'engine'='freightctl-fixed-width-v1'))) AND NEW.report->>'file_id'=NEW.file_id::text AND NEW.report->>'sha256'=NEW.binding->'file'->>'sha256' AND NEW.report->>'bytes_read'=NEW.binding->'file'->>'size_bytes' AND NEW.report->>'policy_hash'=NEW.policy_hash AND EXISTS(SELECT 1 FROM intake_policies i WHERE (i.tenant_id,i.partner_id,i.policy_id,i.version,i.definition_hash,i.state)=(NEW.tenant_id,NEW.partner_id,NEW.policy_id,NEW.policy_version,NEW.policy_hash,'active'));
 END IF;
 IF NOT coalesce(valid,false) THEN RAISE EXCEPTION 'invalid file check transition' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
