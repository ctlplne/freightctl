-- Existing identities keep their exact grants. Bootstrap administrators only
-- receive the new explicit operation grants on subsequent enrollment.
ALTER TABLE credentials DROP CONSTRAINT credential_permissions_valid;
ALTER TABLE credentials ADD CONSTRAINT credential_permissions_valid CHECK(cardinality(permissions)<=15 AND permissions <@ ARRAY['read','write','list','manage_paths','inspect','audit_read','admin','connections_manage','deliver','workflow_manage','workflow_approve','workflow_execute','ai_manage','ai_use','ai_disclose']::text[]);
ALTER TABLE credentials ALTER COLUMN permissions SET DEFAULT ARRAY['read','write','list','manage_paths','inspect','audit_read','admin','connections_manage','deliver','workflow_manage','workflow_approve','workflow_execute','ai_manage','ai_use','ai_disclose']::text[];
CREATE TABLE ai_profiles (
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,actor_id uuid NOT NULL,profile_id uuid NOT NULL,
 version integer NOT NULL CHECK(version>0),definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object' AND octet_length(definition::text)<=8192),
 definition_hash text NOT NULL CHECK(definition_hash ~ '^[0-9a-f]{64}$'),state text NOT NULL CHECK(state IN ('active','revoked')),
 revision bigint NOT NULL CHECK(revision>0),changed_event_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,profile_id,version),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,changed_event_id) REFERENCES events(tenant_id,partner_id,event_id)
);
CREATE TABLE ai_jobs (
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,actor_id uuid NOT NULL,job_id uuid NOT NULL,
 profile_id uuid NOT NULL,profile_version integer NOT NULL,profile_hash text NOT NULL CHECK(profile_hash ~ '^[0-9a-f]{64}$'),
 authority_revision bigint NOT NULL CHECK(authority_revision>0),namespace_root text NOT NULL CHECK(namespace_root='/'),
 kind text NOT NULL CHECK(kind IN ('propose','diagnose')),bindings jsonb NOT NULL CHECK(jsonb_typeof(bindings)='object' AND octet_length(bindings::text)<=24576),
 context jsonb NOT NULL CHECK(jsonb_typeof(context)='object' AND octet_length(context::text)<=16384),context_hash text NOT NULL CHECK(context_hash ~ '^[0-9a-f]{64}$'),
 state text NOT NULL CHECK(state IN ('prepared','approved','running','succeeded','rejected','failed','superseded')),
 revision bigint NOT NULL CHECK(revision>0),attempts integer NOT NULL CHECK(attempts BETWEEN 0 AND 2),
 worker_id uuid,lease_until timestamptz,
 result jsonb NOT NULL CHECK(jsonb_typeof(result)='object' AND octet_length(result::text)<=16384),
 output_hash text NOT NULL CHECK(output_hash='' OR output_hash ~ '^[0-9a-f]{64}$'),
 code text NOT NULL CHECK(code ~ '^[a-z_]{1,64}$'),changed_event_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,job_id),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,profile_id,profile_version) REFERENCES ai_profiles(tenant_id,partner_id,profile_id,version),
 FOREIGN KEY(tenant_id,partner_id,changed_event_id) REFERENCES events(tenant_id,partner_id,event_id),
 CHECK((state='running')=(worker_id IS NOT NULL)),CHECK((worker_id IS NULL)=(lease_until IS NULL))
);
CREATE INDEX ai_open_jobs ON ai_jobs(tenant_id,partner_id,actor_id,state);
CREATE TABLE ai_receipts (
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,actor_id uuid NOT NULL,
 request_key text NOT NULL CHECK(request_key ~ '^[A-Za-z0-9._:-]{1,128}$'),request_hash text NOT NULL CHECK(request_hash ~ '^[0-9a-f]{64}$'),
 resource_id uuid NOT NULL,result jsonb NOT NULL CHECK(octet_length(result::text)<=32768),completed_event_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,actor_id,request_key),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,completed_event_id) REFERENCES events(tenant_id,partner_id,event_id)
);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['ai_profiles','ai_jobs','ai_receipts'] LOOP
  EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('CREATE POLICY scope ON %I USING(tenant_id=nullif(current_setting(''freightctl.tenant_id'',true),'''')::uuid AND partner_id=nullif(current_setting(''freightctl.partner_id'',true),'''')::uuid) WITH CHECK(tenant_id=nullif(current_setting(''freightctl.tenant_id'',true),'''')::uuid AND partner_id=nullif(current_setting(''freightctl.partner_id'',true),'''')::uuid)',t);
  EXECUTE format('CREATE POLICY identity_scope ON %I AS RESTRICTIVE USING(actor_id=nullif(current_setting(''freightctl.actor_id'',true),'''')::uuid) WITH CHECK(actor_id=nullif(current_setting(''freightctl.actor_id'',true),'''')::uuid)',t);
 END LOOP;
END $$;
GRANT SELECT,INSERT,UPDATE ON ai_profiles,ai_jobs TO freightctl_runtime;
GRANT SELECT,INSERT ON ai_receipts TO freightctl_runtime;
CREATE FUNCTION freightctl_ai_profile_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE p jsonb; maximum integer;
BEGIN
 SELECT payload INTO p FROM events WHERE (tenant_id,partner_id,event_id)=(NEW.tenant_id,NEW.partner_id,NEW.changed_event_id) AND actor_id=NEW.actor_id AND resource_id=NEW.profile_id AND kind='AIProfileChanged';
 IF p IS NULL OR p->>'id' IS DISTINCT FROM NEW.profile_id::text OR p->>'version' IS DISTINCT FROM NEW.version::text OR p->'definition' IS DISTINCT FROM NEW.definition OR p->>'definition_hash' IS DISTINCT FROM NEW.definition_hash OR p->>'state' IS DISTINCT FROM NEW.state OR p->>'revision' IS DISTINCT FROM NEW.revision::text THEN RAISE EXCEPTION 'AI profile requires its exact event' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN
  SELECT coalesce(max(version),0) INTO maximum FROM ai_profiles WHERE tenant_id=NEW.tenant_id AND partner_id=NEW.partner_id AND profile_id=NEW.profile_id;
  IF NEW.version<>maximum+1 OR NEW.state<>'active' OR NEW.revision<>1 THEN RAISE EXCEPTION 'invalid AI profile creation' USING ERRCODE='23514';END IF;
 ELSE
  IF (NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.profile_id,NEW.version,NEW.definition,NEW.definition_hash) IS DISTINCT FROM (OLD.tenant_id,OLD.partner_id,OLD.actor_id,OLD.profile_id,OLD.version,OLD.definition,OLD.definition_hash) OR NEW.revision<>OLD.revision+1 OR OLD.state<>'active' OR NEW.state<>'revoked' THEN RAISE EXCEPTION 'AI profile definition is immutable' USING ERRCODE='23514';END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER ai_profile_guard BEFORE INSERT OR UPDATE ON ai_profiles FOR EACH ROW EXECUTE FUNCTION freightctl_ai_profile_guard();
CREATE FUNCTION freightctl_ai_job_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE p jsonb; valid boolean:=false;
BEGIN
 SELECT payload INTO p FROM events WHERE (tenant_id,partner_id,event_id)=(NEW.tenant_id,NEW.partner_id,NEW.changed_event_id) AND actor_id=NEW.actor_id AND resource_id=NEW.job_id AND kind='AIJobChanged';
 IF p IS NULL OR p->>'id' IS DISTINCT FROM NEW.job_id::text OR p->>'profile_id' IS DISTINCT FROM NEW.profile_id::text OR p->>'profile_version' IS DISTINCT FROM NEW.profile_version::text OR p->>'profile_hash' IS DISTINCT FROM NEW.profile_hash OR p->>'authority_revision' IS DISTINCT FROM NEW.authority_revision::text OR p->>'namespace_root' IS DISTINCT FROM NEW.namespace_root OR p->>'kind' IS DISTINCT FROM NEW.kind OR p->'bindings' IS DISTINCT FROM NEW.bindings OR p->'context' IS DISTINCT FROM NEW.context OR p->>'context_hash' IS DISTINCT FROM NEW.context_hash OR p->>'state' IS DISTINCT FROM NEW.state OR p->>'revision' IS DISTINCT FROM NEW.revision::text OR p->>'attempts' IS DISTINCT FROM NEW.attempts::text OR p->>'worker_id' IS DISTINCT FROM coalesce(NEW.worker_id::text,'') OR (p->>'lease_until')::timestamptz IS DISTINCT FROM NEW.lease_until OR p->'result' IS DISTINCT FROM NEW.result OR p->>'output_hash' IS DISTINCT FROM NEW.output_hash OR p->>'code' IS DISTINCT FROM NEW.code THEN RAISE EXCEPTION 'AI job requires its exact event' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN
  valid:=NEW.state='prepared' AND NEW.revision=1 AND NEW.attempts=0 AND NEW.result='{}'::jsonb AND NEW.output_hash='' AND EXISTS(SELECT 1 FROM ai_profiles p WHERE (p.tenant_id,p.partner_id,p.actor_id,p.profile_id,p.version,p.definition_hash,p.state)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.profile_id,NEW.profile_version,NEW.profile_hash,'active'));
 ELSE
  IF (NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.job_id,NEW.profile_id,NEW.profile_version,NEW.profile_hash,NEW.authority_revision,NEW.namespace_root,NEW.kind,NEW.bindings,NEW.context,NEW.context_hash) IS DISTINCT FROM (OLD.tenant_id,OLD.partner_id,OLD.actor_id,OLD.job_id,OLD.profile_id,OLD.profile_version,OLD.profile_hash,OLD.authority_revision,OLD.namespace_root,OLD.kind,OLD.bindings,OLD.context,OLD.context_hash) OR NEW.revision<>OLD.revision+1 THEN RAISE EXCEPTION 'AI context and authority are immutable' USING ERRCODE='23514';END IF;
  IF NEW.state='running' THEN
   valid:=(OLD.state IN ('approved','failed') OR (OLD.state='running' AND OLD.lease_until<=clock_timestamp())) AND NEW.attempts=OLD.attempts+1 AND OLD.attempts<2 AND NEW.lease_until>clock_timestamp() AND NEW.lease_until<=clock_timestamp()+interval '71 seconds' AND NEW.result='{}'::jsonb AND NEW.output_hash='';
  ELSIF OLD.state='running' THEN
   valid:=NEW.state IN ('succeeded','rejected','failed','superseded') AND NEW.attempts=OLD.attempts AND OLD.lease_until>clock_timestamp();
  ELSE
   valid:=NEW.attempts=OLD.attempts AND ((OLD.state='prepared' AND NEW.state='approved') OR (OLD.state IN ('prepared','approved','failed') AND NEW.state='superseded')) AND NEW.result=OLD.result AND NEW.output_hash=OLD.output_hash;
  END IF;
 END IF;
 IF NOT coalesce(valid,false) THEN RAISE EXCEPTION 'invalid AI context/job transition' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER ai_job_guard BEFORE INSERT OR UPDATE ON ai_jobs FOR EACH ROW EXECUTE FUNCTION freightctl_ai_job_guard();
CREATE FUNCTION freightctl_ai_receipt_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM events e WHERE (e.tenant_id,e.partner_id,e.event_id)=(NEW.tenant_id,NEW.partner_id,NEW.completed_event_id) AND e.actor_id=NEW.actor_id AND e.resource_id=NEW.resource_id AND e.kind='AICommandCompleted' AND e.payload->>'request_key'=NEW.request_key AND e.payload->>'request_hash'=NEW.request_hash AND e.payload->'result'=NEW.result) THEN RAISE EXCEPTION 'AI receipt requires its exact event' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER ai_receipt_guard BEFORE INSERT ON ai_receipts FOR EACH ROW EXECUTE FUNCTION freightctl_ai_receipt_guard();
REVOKE ALL ON FUNCTION freightctl_ai_profile_guard(),freightctl_ai_job_guard(),freightctl_ai_receipt_guard() FROM PUBLIC;
