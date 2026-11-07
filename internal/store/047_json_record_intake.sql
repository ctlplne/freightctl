-- Separate format identities retain all historical CSV custody and guards.
-- New JSON checks still require their exact event,active policy,immutable bytes,
-- attempt/lease,signature/scanner proofs and separately authorized release.
ALTER TABLE files DROP CONSTRAINT files_policy_check;
ALTER TABLE files ADD CONSTRAINT files_policy_check CHECK(policy='integrity-only-v1' OR policy ~ '^intake-(csv-v1|json-records-v1):[0-9a-f]{64}$');

CREATE FUNCTION freightctl_intake_policy_prefix(d jsonb) RETURNS text LANGUAGE sql IMMUTABLE STRICT AS $$
 SELECT CASE WHEN d->'schema_version'='1'::jsonb AND d->'kind'='"csv"'::jsonb THEN 'intake-csv-v1:'
             WHEN d->'schema_version'='2'::jsonb AND d->'kind'='"json_records"'::jsonb THEN 'intake-json-records-v1:'
             ELSE NULL END
$$;
CREATE FUNCTION freightctl_controlled_policy_hash(policy text) RETURNS text LANGUAGE sql IMMUTABLE STRICT AS $$
 SELECT CASE WHEN policy ~ '^intake-(csv-v1|json-records-v1):[0-9a-f]{64}$' THEN split_part(policy,':',2) ELSE NULL END
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
  valid:=valid AND EXISTS(SELECT 1 FROM intake_policies format_policy WHERE (format_policy.tenant_id,format_policy.partner_id,format_policy.policy_id,format_policy.version,format_policy.definition_hash,format_policy.state)=(NEW.tenant_id,NEW.partner_id,NEW.policy_id,NEW.policy_version,NEW.policy_hash,'active') AND ((format_policy.definition->'schema_version'='1'::jsonb AND format_policy.definition->'kind'='"csv"'::jsonb AND NEW.report->>'code'='valid_csv' AND NEW.report->>'engine'='freightctl-csv-v1') OR (format_policy.definition->'schema_version'='2'::jsonb AND format_policy.definition->'kind'='"json_records"'::jsonb AND NEW.report->>'code'='valid_json_records' AND NEW.report->>'engine'='freightctl-json-records-v1'))) AND NEW.report->>'file_id'=NEW.file_id::text AND NEW.report->>'sha256'=NEW.binding->'file'->>'sha256' AND NEW.report->>'bytes_read'=NEW.binding->'file'->>'size_bytes' AND NEW.report->>'policy_hash'=NEW.policy_hash AND EXISTS(SELECT 1 FROM intake_policies i WHERE (i.tenant_id,i.partner_id,i.policy_id,i.version,i.definition_hash,i.state)=(NEW.tenant_id,NEW.partner_id,NEW.policy_id,NEW.policy_version,NEW.policy_hash,'active'));
 END IF;
 IF NOT coalesce(valid,false) THEN RAISE EXCEPTION 'invalid file check transition' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;

-- Existing freightctl_file_check_required from 010_intake.sql;other guards retained.
CREATE OR REPLACE FUNCTION freightctl_file_check_required() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.policy='integrity-only-v1' AND EXISTS(SELECT 1 FROM intake_policies i WHERE (i.tenant_id,i.partner_id)=(NEW.tenant_id,NEW.partner_id)) THEN RAISE EXCEPTION 'new acceptance cannot bypass a configured intake policy' USING ERRCODE='23514';END IF;
 IF freightctl_controlled_policy_hash(NEW.policy) IS NOT NULL AND NOT EXISTS(SELECT 1 FROM file_checks c WHERE (c.tenant_id,c.partner_id,c.file_id)=(NEW.tenant_id,NEW.partner_id,NEW.file_id) AND c.policy_hash=freightctl_controlled_policy_hash(NEW.policy)) THEN RAISE EXCEPTION 'controlled acceptance requires its bound check in the same transaction' USING ERRCODE='23514';END IF;RETURN NEW;
END $$;

-- Existing freightctl_file_available from 030_workflow_collections.sql;other guards retained.
CREATE OR REPLACE FUNCTION freightctl_file_available(t uuid,p uuid,f uuid) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT EXISTS(SELECT 1 FROM files v WHERE (v.tenant_id,v.partner_id,v.file_id)=(t,p,f) AND (v.policy='integrity-only-v1' OR EXISTS(SELECT 1 FROM file_releases c JOIN intake_policies i ON (i.tenant_id,i.partner_id,i.policy_id,i.version)=(c.tenant_id,c.partner_id,c.policy_id,c.policy_version) WHERE (c.tenant_id,c.partner_id,c.file_id,i.state)=(t,p,f,'active') AND v.policy=freightctl_intake_policy_prefix(i.definition)||c.policy_hash AND c.policy_hash=i.definition_hash AND ((NOT (i.definition ? 'signature') OR i.definition->'signature'='null'::jsonb) OR EXISTS(SELECT 1 FROM pgp_keys k WHERE (k.tenant_id,k.partner_id,k.key_id,k.version,k.definition_hash,k.state)=(c.tenant_id,c.partner_id,c.pgp_key_id,c.pgp_key_version,c.pgp_key_hash,'active') AND (k.valid_until IS NULL OR k.valid_until>clock_timestamp()) AND (c.signature_expires_at IS NULL OR c.signature_expires_at>clock_timestamp()))) AND ((NOT (i.definition ? 'scanner') OR i.definition->'scanner'='null'::jsonb) OR EXISTS(SELECT 1 FROM scanner_profiles s WHERE (s.tenant_id,s.partner_id,s.scanner_id,s.version,s.definition_hash,s.state)=(c.tenant_id,c.partner_id,c.scanner_id,c.scanner_version,c.scanner_hash,'active') AND s.valid_until>clock_timestamp() AND c.scan_expires_at>clock_timestamp())))))
 AND NOT EXISTS(SELECT 1 FROM workflow_collection_file_gates g WHERE (g.tenant_id,g.partner_id,g.file_id)=(t,p,f) AND NOT g.captured)
$$;

-- Existing freightctl_recheck_guard from 021_file_rechecks.sql;other guards retained.
CREATE OR REPLACE FUNCTION freightctl_recheck_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE e jsonb;d jsonb;s jsonb;f files;c file_checks;i intake_policies;cr credentials;sig file_signatures;
BEGIN
 SELECT payload INTO e FROM events WHERE (tenant_id,partner_id,event_id)=(NEW.tenant_id,NEW.partner_id,NEW.changed_event_id) AND actor_id=NEW.actor_id AND resource_id=NEW.recheck_id AND kind='FileRecheckChanged';
 IF e IS NULL OR e->>'id' IS DISTINCT FROM NEW.recheck_id::text OR e->>'source_file_id' IS DISTINCT FROM NEW.source_file_id::text OR e->'definition' IS DISTINCT FROM NEW.definition OR e->>'definition_hash' IS DISTINCT FROM NEW.definition_hash OR e->>'state' IS DISTINCT FROM NEW.state OR e->>'revision' IS DISTINCT FROM NEW.revision::text OR e->>'new_file_id' IS DISTINCT FROM coalesce(NEW.new_file_id::text,'') OR e->'result' IS DISTINCT FROM NEW.result THEN RAISE EXCEPTION 'recheck requires its exact immutable event' USING ERRCODE='23514';END IF;
 IF TG_OP='UPDATE' AND ((NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.recheck_id,NEW.source_file_id,NEW.definition,NEW.definition_hash) IS DISTINCT FROM (OLD.tenant_id,OLD.partner_id,OLD.actor_id,OLD.recheck_id,OLD.source_file_id,OLD.definition,OLD.definition_hash) OR NEW.revision<>OLD.revision+1 OR NOT ((OLD.state='proposed' AND NEW.state IN ('approved','cancelled')) OR (OLD.state='approved' AND NEW.state IN ('cancelled','copied')))) THEN RAISE EXCEPTION 'recheck definition or terminal transition is immutable' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id::text||':'||NEW.partner_id::text||':'||NEW.actor_id::text||':file-rechecks',0));END IF;
 IF TG_OP='INSERT' AND (NEW.state<>'proposed' OR NEW.revision<>1 OR (SELECT count(*) FROM file_rechecks WHERE actor_id=NEW.actor_id AND state IN ('proposed','approved'))>=16) THEN RAISE EXCEPTION 'invalid or saturated recheck proposal' USING ERRCODE='23514';END IF;
 d:=NEW.definition;s:=d->'plan'->'source';
 IF d->>'schema_version' IS DISTINCT FROM '1' OR jsonb_typeof(d->'staging_slots') IS DISTINCT FROM 'array' OR jsonb_array_length(d->'staging_slots') IS DISTINCT FROM 3 OR s->'file'->>'id' IS DISTINCT FROM NEW.source_file_id::text THEN RAISE EXCEPTION 'invalid recheck source/effects' USING ERRCODE='23514';END IF;
 IF NEW.state<>'cancelled' THEN
  SELECT * INTO cr FROM credentials WHERE (tenant_id,partner_id,actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id);
  IF cr.actor_id IS NULL OR cr.namespace_root<>'/' OR d->'plan'->>'namespace_root' IS DISTINCT FROM cr.namespace_root OR d->'plan'->>'authority_revision' IS DISTINCT FROM cr.authority_revision::text OR NOT cr.permissions @> ARRAY['admin','read','write','intake_manage','check_run','check_release']::text[] THEN RAISE EXCEPTION 'recheck requires current root check administration' USING ERRCODE='23514';END IF;
  SELECT * INTO f FROM files WHERE (tenant_id,partner_id,file_id)=(NEW.tenant_id,NEW.partner_id,NEW.source_file_id);
  IF f.file_id IS NULL OR s->'file' IS DISTINCT FROM jsonb_build_object('id',f.file_id::text,'size_bytes',f.size_bytes,'sha256',f.sha256,'policy',f.policy,'accepted_event_id',f.accepted_event_id::text) OR NOT EXISTS(SELECT 1 FROM events WHERE (tenant_id,partner_id,event_id,actor_id)=(f.tenant_id,f.partner_id,f.accepted_event_id,NEW.actor_id)) THEN RAISE EXCEPTION 'recheck source must be exact owned accepted bytes' USING ERRCODE='23514';END IF;
  SELECT * INTO c FROM file_checks WHERE (tenant_id,partner_id,file_id,actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.source_file_id,NEW.actor_id);
  IF c.file_id IS NOT NULL AND (c.binding->>'namespace_root' IS DISTINCT FROM cr.namespace_root OR s->'check'->>'policy_id' IS DISTINCT FROM c.policy_id::text OR s->'check'->>'policy_version' IS DISTINCT FROM c.policy_version::text OR s->'check'->>'attempts' IS DISTINCT FROM c.attempts::text OR s->'check'->>'code' IS DISTINCT FROM c.code OR coalesce(s->'check'->>'worker_id','') IS DISTINCT FROM coalesce(c.worker_id::text,'') OR (s->'check'->>'lease_until')::timestamptz IS DISTINCT FROM c.lease_until OR s->'check'->>'revision' IS DISTINCT FROM c.revision::text OR s->'check'->>'state' IS DISTINCT FROM c.state OR s->'check'->>'report_hash' IS DISTINCT FROM c.report_hash OR s->'check'->'binding' IS DISTINCT FROM c.binding OR s->'check'->>'policy_hash' IS DISTINCT FROM c.policy_hash OR (c.state='running' AND c.lease_until>clock_timestamp())) THEN RAISE EXCEPTION 'recheck source changed or worker lease live' USING ERRCODE='23514';END IF;
  IF c.file_id IS NULL AND (s ? 'check' OR f.policy<>'integrity-only-v1') THEN RAISE EXCEPTION 'invented source check' USING ERRCODE='23514';END IF;
  SELECT * INTO i FROM intake_policies WHERE (tenant_id,partner_id,policy_id,version,definition_hash,state)=(NEW.tenant_id,NEW.partner_id,(d->'plan'->'policy'->>'id')::uuid,(d->'plan'->'policy'->>'version')::integer,d->'plan'->'policy'->>'hash','active');
  IF i.policy_id IS NULL THEN RAISE EXCEPTION 'recheck requires exact current policy' USING ERRCODE='23514';END IF;
  IF c.file_id IS NOT NULL AND EXISTS(SELECT 1 FROM intake_policies prior_policy WHERE (prior_policy.tenant_id,prior_policy.partner_id,prior_policy.policy_id,prior_policy.version)=(c.tenant_id,c.partner_id,c.policy_id,c.policy_version) AND ((prior_policy.definition ? 'scanner' AND jsonb_typeof(i.definition->'scanner') IS DISTINCT FROM 'object') OR (prior_policy.definition ? 'signature' AND jsonb_typeof(i.definition->'signature') IS DISTINCT FROM 'object'))) THEN RAISE EXCEPTION 'recheck cannot remove required security control' USING ERRCODE='23514';END IF;
  IF d->'plan'->>'signature_mode' NOT IN ('not_required','require_new','reuse_exact') OR (coalesce(jsonb_typeof(i.definition->'signature'),'null')='object') IS DISTINCT FROM ((d->'plan'->>'signature_mode') IN ('require_new','reuse_exact')) THEN RAISE EXCEPTION 'invalid recheck signature mode' USING ERRCODE='23514';END IF;
  IF c.file_id IS NOT NULL AND EXISTS(SELECT 1 FROM intake_policies prior_policy WHERE (prior_policy.tenant_id,prior_policy.partner_id,prior_policy.policy_id,prior_policy.version)=(c.tenant_id,c.partner_id,c.policy_id,c.policy_version) AND coalesce((prior_policy.definition->'signature'->>'max_age_seconds')::bigint,0)>0 AND (coalesce((i.definition->'signature'->>'max_age_seconds')::bigint,0)=0 OR (i.definition->'signature'->>'max_age_seconds')::bigint>(prior_policy.definition->'signature'->>'max_age_seconds')::bigint)) THEN RAISE EXCEPTION 'recheck cannot loosen signature age' USING ERRCODE='23514';END IF;
  SELECT * INTO sig FROM file_signatures WHERE (tenant_id,partner_id,file_id,actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.source_file_id,NEW.actor_id);
  IF (sig.file_id IS NULL AND s ? 'signature') OR (sig.file_id IS NOT NULL AND s->'signature' IS DISTINCT FROM jsonb_build_object('file_id',sig.file_id::text,'object_id',sig.object_id::text,'storage_id',sig.storage_id::text,'size_bytes',sig.size_bytes,'sha256',sig.sha256,'data_sha256',sig.data_sha256,'policy_hash',sig.policy_hash,'key',jsonb_build_object('id',sig.key_id::text,'version',sig.key_version,'hash',sig.key_hash),'attached_event_id',sig.attached_event_id::text)) THEN RAISE EXCEPTION 'recheck requires exact original signature snapshot' USING ERRCODE='23514';END IF;
  IF d->'plan'->>'signature_mode'='reuse_exact' THEN
   IF sig.file_id IS NULL OR s->'signature'->>'object_id' IS DISTINCT FROM sig.object_id::text OR s->'signature'->>'storage_id' IS DISTINCT FROM sig.storage_id::text OR s->'signature'->>'sha256' IS DISTINCT FROM sig.sha256 OR s->'signature'->>'size_bytes' IS DISTINCT FROM sig.size_bytes::text OR i.definition->'signature'->'key' IS DISTINCT FROM jsonb_build_object('id',sig.key_id::text,'version',sig.key_version,'hash',sig.key_hash) THEN RAISE EXCEPTION 'recheck signature reuse requires exact artifact and selected signer' USING ERRCODE='23514';END IF;
  END IF;
 END IF;
 IF NEW.state='copied' THEN
  IF NEW.result->>'kind' IS DISTINCT FROM 'file_recheck_copy' OR NEW.result->>'acceptance' IS DISTINCT FROM 'durable-held-pending-checks-and-release' OR NEW.result->'file'->>'id' IS DISTINCT FROM NEW.new_file_id::text OR NEW.result->'file'->>'sha256' IS DISTINCT FROM f.sha256 OR NEW.result->'file'->>'size_bytes' IS DISTINCT FROM f.size_bytes::text THEN RAISE EXCEPTION 'invalid copied held revision result' USING ERRCODE='23514';END IF;
  IF NOT EXISTS(SELECT 1 FROM file_recheck_slots sl JOIN files nf ON (nf.tenant_id,nf.partner_id,nf.file_id)=(sl.tenant_id,sl.partner_id,sl.file_id) JOIN events ne ON (ne.tenant_id,ne.partner_id,ne.event_id)=(nf.tenant_id,nf.partner_id,nf.accepted_event_id) JOIN file_checks nc ON (nc.tenant_id,nc.partner_id,nc.file_id)=(nf.tenant_id,nf.partner_id,nf.file_id) WHERE (sl.tenant_id,sl.partner_id,sl.recheck_id,sl.file_id)=(NEW.tenant_id,NEW.partner_id,NEW.recheck_id,NEW.new_file_id) AND nf.sha256=f.sha256 AND nf.size_bytes=f.size_bytes AND nf.policy=freightctl_intake_policy_prefix(i.definition)||i.definition_hash AND ne.payload->>'recheck_id'=NEW.recheck_id::text AND ne.payload->>'source_file_id'=NEW.source_file_id::text AND NEW.result->'file'=jsonb_build_object('id',nf.file_id::text,'size_bytes',nf.size_bytes,'sha256',nf.sha256,'policy',nf.policy,'accepted_event_id',nf.accepted_event_id::text) AND nc.state='held' AND nc.attempts=0 AND nc.policy_hash=i.definition_hash AND nc.binding->>'storage_id'=d->'plan'->>'storage_id' AND nc.binding->>'namespace_root'=d->'plan'->>'namespace_root' AND nc.binding->>'authority_revision'=d->'plan'->>'authority_revision' AND nc.binding->'file'=NEW.result->'file' AND nc.binding->'target' IS NOT DISTINCT FROM CASE WHEN d->'plan' ? 'target' THEN (d->'plan'->'target'->'command')||jsonb_build_object('file_id',nf.file_id::text) ELSE 'null'::jsonb END AND ((d->'plan'->>'signature_mode'<>'reuse_exact' AND NOT EXISTS(SELECT 1 FROM file_signatures ns WHERE (ns.tenant_id,ns.partner_id,ns.file_id)=(sl.tenant_id,sl.partner_id,sl.file_id))) OR d->'plan'->>'signature_mode'='reuse_exact') AND (sl.signature_object_id IS NULL OR EXISTS(SELECT 1 FROM file_signatures ns WHERE (ns.tenant_id,ns.partner_id,ns.file_id,ns.object_id)=(sl.tenant_id,sl.partner_id,sl.file_id,sl.signature_object_id) AND ns.sha256=d->'plan'->'source'->'signature'->>'sha256' AND ns.size_bytes::text=d->'plan'->'source'->'signature'->>'size_bytes' AND NEW.result->'signature'=jsonb_build_object('file_id',ns.file_id::text,'object_id',ns.object_id::text,'storage_id',ns.storage_id::text,'size_bytes',ns.size_bytes,'sha256',ns.sha256,'data_sha256',ns.data_sha256,'policy_hash',ns.policy_hash,'key',jsonb_build_object('id',ns.key_id::text,'version',ns.key_version,'hash',ns.key_hash),'attached_event_id',ns.attached_event_id::text))))  THEN RAISE EXCEPTION 'copy completion requires atomic held revision and exact lineage' USING ERRCODE='23514';END IF;
 END IF;
 RETURN NEW;
END $$;

-- Existing freightctl_rechecked_acceptance_guard from 021_file_rechecks.sql;other guards retained.
CREATE OR REPLACE FUNCTION freightctl_rechecked_acceptance_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r file_rechecks;s jsonb;e jsonb;
BEGIN
 SELECT i.* INTO r FROM file_rechecks i JOIN file_recheck_slots sl USING(tenant_id,partner_id,recheck_id) WHERE (sl.tenant_id,sl.partner_id,sl.file_id)=(NEW.tenant_id,NEW.partner_id,NEW.file_id);
 SELECT payload INTO e FROM events WHERE (tenant_id,partner_id,event_id)=(NEW.tenant_id,NEW.partner_id,NEW.accepted_event_id);
 IF r.recheck_id IS NULL THEN
  IF e ? 'recheck_id' THEN RAISE EXCEPTION 'invented derived acceptance' USING ERRCODE='23514';END IF;
  RETURN NEW;
 END IF;
 s:=r.definition->'plan'->'source'->'file';
 IF r.state<>'approved' OR r.actor_id<>nullif(current_setting('freightctl.actor_id',true),'')::uuid OR NEW.sha256 IS DISTINCT FROM s->>'sha256' OR NEW.size_bytes::text IS DISTINCT FROM s->>'size_bytes' OR NEW.policy IS DISTINCT FROM (SELECT freightctl_intake_policy_prefix(i.definition)||i.definition_hash FROM intake_policies i WHERE (i.tenant_id,i.partner_id,i.policy_id::text,i.version::text,i.definition_hash,i.state)=(NEW.tenant_id,NEW.partner_id,r.definition->'plan'->'policy'->>'id',r.definition->'plan'->'policy'->>'version',r.definition->'plan'->'policy'->>'hash','active')) OR e->>'recheck_id' IS DISTINCT FROM r.recheck_id::text OR e->>'source_file_id' IS DISTINCT FROM r.source_file_id::text OR e->>'recheck_definition_hash' IS DISTINCT FROM r.definition_hash THEN RAISE EXCEPTION 'derived acceptance requires its exact approved intent' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;

-- Existing freightctl_artifact_exchange_policy_current from 042_artifact_exchanges.sql;other guards retained.
CREATE OR REPLACE FUNCTION freightctl_artifact_exchange_policy_current(t uuid,p uuid,f uuid) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT EXISTS(SELECT 1 FROM files v LEFT JOIN LATERAL (SELECT state,definition_hash,definition FROM intake_policies WHERE (tenant_id,partner_id)=(t,p) ORDER BY version DESC LIMIT 1) i ON true
 WHERE (v.tenant_id,v.partner_id,v.file_id)=(t,p,f) AND ((i.definition_hash IS NULL AND v.policy='integrity-only-v1') OR (i.state='active' AND v.policy=freightctl_intake_policy_prefix(i.definition)||i.definition_hash)))
 AND freightctl_file_available(t,p,f)
$$;

-- Existing freightctl_exchange_copy_acceptance_guard from 045_exchange_copy.sql;other guards retained.
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
 SELECT * INTO policy FROM intake_policies WHERE (tenant_id,partner_id)=(NEW.tenant_id,NEW.partner_id) ORDER BY version DESC LIMIT 1;
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
