CREATE TABLE file_rechecks(
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,actor_id uuid NOT NULL,recheck_id uuid NOT NULL,source_file_id uuid NOT NULL,
 definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object' AND octet_length(definition::text)<=16384),definition_hash text NOT NULL CHECK(definition_hash ~ '^[0-9a-f]{64}$'),
 state text NOT NULL CHECK(state IN ('proposed','approved','cancelled','copied')),revision bigint NOT NULL CHECK(revision>0),new_file_id uuid,result jsonb NOT NULL CHECK(jsonb_typeof(result)='object' AND octet_length(result::text)<=8192),changed_event_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,recheck_id),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,source_file_id) REFERENCES files(tenant_id,partner_id,file_id),
 FOREIGN KEY(tenant_id,partner_id,new_file_id) REFERENCES files(tenant_id,partner_id,file_id),
 FOREIGN KEY(tenant_id,partner_id,changed_event_id) REFERENCES events(tenant_id,partner_id,event_id),
 CHECK((state='copied')=(new_file_id IS NOT NULL)),CHECK((state='copied')=(result<>'{}'::jsonb))
);
CREATE TABLE file_recheck_slots(
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,actor_id uuid NOT NULL,recheck_id uuid NOT NULL,ordinal integer NOT NULL CHECK(ordinal BETWEEN 1 AND 3),file_id uuid NOT NULL,signature_object_id uuid,
 PRIMARY KEY(tenant_id,partner_id,file_id),UNIQUE(tenant_id,partner_id,recheck_id,ordinal),UNIQUE(tenant_id,partner_id,signature_object_id),
 FOREIGN KEY(tenant_id,partner_id,recheck_id) REFERENCES file_rechecks(tenant_id,partner_id,recheck_id),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id)
);
DO $$ DECLARE t text;BEGIN
 FOREACH t IN ARRAY ARRAY['file_rechecks','file_recheck_slots'] LOOP
  EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',t);EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('CREATE POLICY scope ON %I USING(tenant_id=nullif(current_setting(''freightctl.tenant_id'',true),'''')::uuid AND partner_id=nullif(current_setting(''freightctl.partner_id'',true),'''')::uuid AND actor_id=nullif(current_setting(''freightctl.actor_id'',true),'''')::uuid) WITH CHECK(tenant_id=nullif(current_setting(''freightctl.tenant_id'',true),'''')::uuid AND partner_id=nullif(current_setting(''freightctl.partner_id'',true),'''')::uuid AND actor_id=nullif(current_setting(''freightctl.actor_id'',true),'''')::uuid)',t);
 END LOOP;
END $$;
GRANT SELECT,INSERT,UPDATE ON file_rechecks TO freightctl_runtime;
GRANT SELECT,INSERT ON file_recheck_slots TO freightctl_runtime;
CREATE FUNCTION freightctl_recheck_guard() RETURNS trigger LANGUAGE plpgsql AS $$
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
  IF NOT EXISTS(SELECT 1 FROM file_recheck_slots sl JOIN files nf ON (nf.tenant_id,nf.partner_id,nf.file_id)=(sl.tenant_id,sl.partner_id,sl.file_id) JOIN events ne ON (ne.tenant_id,ne.partner_id,ne.event_id)=(nf.tenant_id,nf.partner_id,nf.accepted_event_id) JOIN file_checks nc ON (nc.tenant_id,nc.partner_id,nc.file_id)=(nf.tenant_id,nf.partner_id,nf.file_id) WHERE (sl.tenant_id,sl.partner_id,sl.recheck_id,sl.file_id)=(NEW.tenant_id,NEW.partner_id,NEW.recheck_id,NEW.new_file_id) AND nf.sha256=f.sha256 AND nf.size_bytes=f.size_bytes AND nf.policy='intake-csv-v1:'||i.definition_hash AND ne.payload->>'recheck_id'=NEW.recheck_id::text AND ne.payload->>'source_file_id'=NEW.source_file_id::text AND NEW.result->'file'=jsonb_build_object('id',nf.file_id::text,'size_bytes',nf.size_bytes,'sha256',nf.sha256,'policy',nf.policy,'accepted_event_id',nf.accepted_event_id::text) AND nc.state='held' AND nc.attempts=0 AND nc.policy_hash=i.definition_hash AND nc.binding->>'storage_id'=d->'plan'->>'storage_id' AND nc.binding->>'namespace_root'=d->'plan'->>'namespace_root' AND nc.binding->>'authority_revision'=d->'plan'->>'authority_revision' AND nc.binding->'file'=NEW.result->'file' AND nc.binding->'target' IS NOT DISTINCT FROM CASE WHEN d->'plan' ? 'target' THEN (d->'plan'->'target'->'command')||jsonb_build_object('file_id',nf.file_id::text) ELSE 'null'::jsonb END AND ((d->'plan'->>'signature_mode'<>'reuse_exact' AND NOT EXISTS(SELECT 1 FROM file_signatures ns WHERE (ns.tenant_id,ns.partner_id,ns.file_id)=(sl.tenant_id,sl.partner_id,sl.file_id))) OR d->'plan'->>'signature_mode'='reuse_exact') AND (sl.signature_object_id IS NULL OR EXISTS(SELECT 1 FROM file_signatures ns WHERE (ns.tenant_id,ns.partner_id,ns.file_id,ns.object_id)=(sl.tenant_id,sl.partner_id,sl.file_id,sl.signature_object_id) AND ns.sha256=d->'plan'->'source'->'signature'->>'sha256' AND ns.size_bytes::text=d->'plan'->'source'->'signature'->>'size_bytes' AND NEW.result->'signature'=jsonb_build_object('file_id',ns.file_id::text,'object_id',ns.object_id::text,'storage_id',ns.storage_id::text,'size_bytes',ns.size_bytes,'sha256',ns.sha256,'data_sha256',ns.data_sha256,'policy_hash',ns.policy_hash,'key',jsonb_build_object('id',ns.key_id::text,'version',ns.key_version,'hash',ns.key_hash),'attached_event_id',ns.attached_event_id::text))))  THEN RAISE EXCEPTION 'copy completion requires atomic held revision and exact lineage' USING ERRCODE='23514';END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER recheck_guard BEFORE INSERT OR UPDATE ON file_rechecks FOR EACH ROW EXECUTE FUNCTION freightctl_recheck_guard();
CREATE FUNCTION freightctl_recheck_slot_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r file_rechecks;s jsonb;
BEGIN
 SELECT * INTO r FROM file_rechecks WHERE (tenant_id,partner_id,recheck_id,actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.recheck_id,NEW.actor_id);
 s:=r.definition->'staging_slots'->(NEW.ordinal-1);
 IF r.state IS DISTINCT FROM 'proposed' OR ((r.definition->'plan'->>'signature_mode'='reuse_exact') IS DISTINCT FROM (NEW.signature_object_id IS NOT NULL)) OR s->>'file_id' IS DISTINCT FROM NEW.file_id::text OR coalesce(s->>'signature_object_id','') IS DISTINCT FROM coalesce(NEW.signature_object_id::text,'') OR NEW.file_id=r.source_file_id OR EXISTS(SELECT 1 FROM files WHERE (tenant_id,partner_id,file_id)=(NEW.tenant_id,NEW.partner_id,NEW.file_id)) THEN RAISE EXCEPTION 'staging slots must match proposed immutable recheck' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER recheck_slot_guard BEFORE INSERT ON file_recheck_slots FOR EACH ROW EXECUTE FUNCTION freightctl_recheck_slot_guard();
CREATE FUNCTION freightctl_recheck_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'recheck records cannot be deleted or staging slots changed' USING ERRCODE='23514';END $$;
CREATE TRIGGER recheck_slots_immutable BEFORE UPDATE OR DELETE ON file_recheck_slots FOR EACH ROW EXECUTE FUNCTION freightctl_recheck_immutable();
CREATE TRIGGER rechecks_no_delete BEFORE DELETE ON file_rechecks FOR EACH ROW EXECUTE FUNCTION freightctl_recheck_immutable();
CREATE FUNCTION freightctl_rechecked_acceptance_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r file_rechecks;s jsonb;e jsonb;
BEGIN
 SELECT i.* INTO r FROM file_rechecks i JOIN file_recheck_slots sl USING(tenant_id,partner_id,recheck_id) WHERE (sl.tenant_id,sl.partner_id,sl.file_id)=(NEW.tenant_id,NEW.partner_id,NEW.file_id);
 SELECT payload INTO e FROM events WHERE (tenant_id,partner_id,event_id)=(NEW.tenant_id,NEW.partner_id,NEW.accepted_event_id);
 IF r.recheck_id IS NULL THEN
  IF e ? 'recheck_id' THEN RAISE EXCEPTION 'invented derived acceptance' USING ERRCODE='23514';END IF;
  RETURN NEW;
 END IF;
 s:=r.definition->'plan'->'source'->'file';
 IF r.state<>'approved' OR r.actor_id<>nullif(current_setting('freightctl.actor_id',true),'')::uuid OR NEW.sha256 IS DISTINCT FROM s->>'sha256' OR NEW.size_bytes::text IS DISTINCT FROM s->>'size_bytes' OR NEW.policy IS DISTINCT FROM 'intake-csv-v1:'||(r.definition->'plan'->'policy'->>'hash') OR e->>'recheck_id' IS DISTINCT FROM r.recheck_id::text OR e->>'source_file_id' IS DISTINCT FROM r.source_file_id::text OR e->>'recheck_definition_hash' IS DISTINCT FROM r.definition_hash THEN RAISE EXCEPTION 'derived acceptance requires its exact approved intent' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER rechecked_acceptance_guard BEFORE INSERT ON files FOR EACH ROW EXECUTE FUNCTION freightctl_rechecked_acceptance_guard();
CREATE FUNCTION freightctl_recheck_commit_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM file_recheck_slots sl JOIN file_rechecks r USING(tenant_id,partner_id,recheck_id) WHERE (sl.tenant_id,sl.partner_id,sl.file_id)=(NEW.tenant_id,NEW.partner_id,NEW.file_id) AND (r.state<>'copied' OR r.new_file_id IS DISTINCT FROM NEW.file_id)) THEN RAISE EXCEPTION 'derived file requires atomic recheck completion' USING ERRCODE='23514';END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER recheck_commit_guard AFTER INSERT ON files DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION freightctl_recheck_commit_guard();
REVOKE ALL ON FUNCTION freightctl_recheck_guard(),freightctl_recheck_slot_guard(),freightctl_rechecked_acceptance_guard(),freightctl_recheck_commit_guard() FROM PUBLIC;

CREATE FUNCTION freightctl_recheck_slots_commit_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (SELECT count(*) FROM file_recheck_slots WHERE (tenant_id,partner_id,recheck_id,actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.recheck_id,NEW.actor_id))<>3 THEN RAISE EXCEPTION 'proposal requires its three immutable staging slots' USING ERRCODE='23514';END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER recheck_slots_commit_guard AFTER INSERT OR UPDATE ON file_rechecks DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION freightctl_recheck_slots_commit_guard();
REVOKE ALL ON FUNCTION freightctl_recheck_immutable(),freightctl_recheck_slots_commit_guard() FROM PUBLIC;
