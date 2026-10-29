ALTER TABLE credentials DROP CONSTRAINT credential_permissions_valid;
ALTER TABLE credentials ADD CONSTRAINT credential_permissions_valid CHECK(cardinality(permissions)<=18 AND permissions <@ ARRAY['read','write','list','manage_paths','inspect','audit_read','admin','connections_manage','deliver','workflow_manage','workflow_approve','workflow_execute','ai_manage','ai_use','ai_disclose','intake_manage','check_run','check_release']::text[]);
ALTER TABLE credentials ALTER COLUMN permissions SET DEFAULT ARRAY['read','write','list','manage_paths','inspect','audit_read','admin','connections_manage','deliver','workflow_manage','workflow_approve','workflow_execute','ai_manage','ai_use','ai_disclose','intake_manage','check_run','check_release']::text[];
ALTER TABLE files DROP CONSTRAINT files_policy_check;
ALTER TABLE files ADD CONSTRAINT files_policy_check CHECK(policy='integrity-only-v1' OR policy ~ '^intake-csv-v1:[0-9a-f]{64}$');
CREATE TABLE intake_policies (
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,actor_id uuid NOT NULL,policy_id uuid NOT NULL,version integer NOT NULL CHECK(version>0),
 definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object' AND octet_length(definition::text)<=16384),definition_hash text NOT NULL CHECK(definition_hash ~ '^[0-9a-f]{64}$'),
 state text NOT NULL CHECK(state IN ('active','retired','revoked')),revision bigint NOT NULL CHECK(revision>0),changed_event_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,policy_id,version),UNIQUE(tenant_id,partner_id,version),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,changed_event_id) REFERENCES events(tenant_id,partner_id,event_id)
);
CREATE UNIQUE INDEX intake_one_active ON intake_policies(tenant_id,partner_id) WHERE state='active';
CREATE TABLE file_checks (
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,actor_id uuid NOT NULL,file_id uuid NOT NULL,
 policy_id uuid NOT NULL,policy_version integer NOT NULL,policy_hash text NOT NULL CHECK(policy_hash ~ '^[0-9a-f]{64}$'),
 binding jsonb NOT NULL CHECK(jsonb_typeof(binding)='object' AND octet_length(binding::text)<=8192),
 state text NOT NULL CHECK(state IN ('held','running','passed','rejected','failed','released')),
 revision bigint NOT NULL CHECK(revision>0),attempts integer NOT NULL CHECK(attempts BETWEEN 0 AND 3),worker_id uuid,lease_until timestamptz,
 report jsonb NOT NULL CHECK(jsonb_typeof(report)='object' AND octet_length(report::text)<=4096),report_hash text NOT NULL CHECK(report_hash='' OR report_hash ~ '^[0-9a-f]{64}$'),
 code text NOT NULL CHECK(code ~ '^[a-z_]{1,64}$'),changed_event_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,file_id),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,file_id) REFERENCES files(tenant_id,partner_id,file_id),
 FOREIGN KEY(tenant_id,partner_id,policy_id,policy_version) REFERENCES intake_policies(tenant_id,partner_id,policy_id,version),
 FOREIGN KEY(tenant_id,partner_id,changed_event_id) REFERENCES events(tenant_id,partner_id,event_id),
 CHECK((state='running')=(worker_id IS NOT NULL)),CHECK((worker_id IS NULL)=(lease_until IS NULL)),
 CHECK((state IN ('passed','released'))=(report_hash<>''))
);
CREATE INDEX checks_open ON file_checks(tenant_id,partner_id,actor_id,state);
-- Public release proofs contain no private intake target, authority snapshot or
-- parser data. Normal namespace/mount authorization still gates the bytes.
CREATE TABLE file_releases (
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,file_id uuid NOT NULL,actor_id uuid NOT NULL,policy_id uuid NOT NULL,policy_version integer NOT NULL,policy_hash text NOT NULL,report_hash text NOT NULL,released_event_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,file_id),
 FOREIGN KEY(tenant_id,partner_id,file_id) REFERENCES file_checks(tenant_id,partner_id,file_id),
 FOREIGN KEY(tenant_id,partner_id,policy_id,policy_version) REFERENCES intake_policies(tenant_id,partner_id,policy_id,version),
 FOREIGN KEY(tenant_id,partner_id,released_event_id) REFERENCES events(tenant_id,partner_id,event_id)
);
CREATE TABLE check_receipts (
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,actor_id uuid NOT NULL,request_key text NOT NULL CHECK(request_key ~ '^[A-Za-z0-9._:-]{1,128}$'),
 request_hash text NOT NULL CHECK(request_hash ~ '^[0-9a-f]{64}$'),resource_id uuid NOT NULL,result jsonb NOT NULL CHECK(octet_length(result::text)<=32768),completed_event_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,actor_id,request_key),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,completed_event_id) REFERENCES events(tenant_id,partner_id,event_id)
);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['intake_policies','file_checks','check_receipts','file_releases'] LOOP
  EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',t);EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('CREATE POLICY scope ON %I USING(tenant_id=nullif(current_setting(''freightctl.tenant_id'',true),'''')::uuid AND partner_id=nullif(current_setting(''freightctl.partner_id'',true),'''')::uuid) WITH CHECK(tenant_id=nullif(current_setting(''freightctl.tenant_id'',true),'''')::uuid AND partner_id=nullif(current_setting(''freightctl.partner_id'',true),'''')::uuid)',t);
  IF t IN ('file_checks','check_receipts') THEN EXECUTE format('CREATE POLICY identity_scope ON %I AS RESTRICTIVE USING(actor_id=nullif(current_setting(''freightctl.actor_id'',true),'''')::uuid) WITH CHECK(actor_id=nullif(current_setting(''freightctl.actor_id'',true),'''')::uuid)',t);END IF;
 END LOOP;
END $$;
GRANT SELECT,INSERT,UPDATE ON intake_policies,file_checks TO freightctl_runtime;
GRANT SELECT,INSERT ON check_receipts,file_releases TO freightctl_runtime;
CREATE FUNCTION freightctl_intake_policy_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE p jsonb; maximum integer;
BEGIN
 SELECT payload INTO p FROM events WHERE (tenant_id,partner_id,event_id)=(NEW.tenant_id,NEW.partner_id,NEW.changed_event_id) AND actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid AND resource_id=NEW.policy_id AND kind='IntakePolicyChanged';
 IF p IS NULL OR p->>'id' IS DISTINCT FROM NEW.policy_id::text OR p->>'version' IS DISTINCT FROM NEW.version::text OR p->'definition' IS DISTINCT FROM NEW.definition OR p->>'definition_hash' IS DISTINCT FROM NEW.definition_hash OR p->>'state' IS DISTINCT FROM NEW.state OR p->>'revision' IS DISTINCT FROM NEW.revision::text THEN RAISE EXCEPTION 'intake policy requires its exact event' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN
  SELECT coalesce(max(version),0) INTO maximum FROM intake_policies WHERE tenant_id=NEW.tenant_id AND partner_id=NEW.partner_id;
  IF NEW.version<>maximum+1 OR NEW.state<>'active' OR NEW.revision<>1 THEN RAISE EXCEPTION 'invalid intake policy creation' USING ERRCODE='23514';END IF;
 ELSE
  IF (NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.policy_id,NEW.version,NEW.definition,NEW.definition_hash) IS DISTINCT FROM (OLD.tenant_id,OLD.partner_id,OLD.actor_id,OLD.policy_id,OLD.version,OLD.definition,OLD.definition_hash) OR NEW.revision<>OLD.revision+1 OR OLD.state<>'active' OR NEW.state NOT IN ('retired','revoked') THEN RAISE EXCEPTION 'intake policy definition is immutable' USING ERRCODE='23514';END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER intake_policy_guard BEFORE INSERT OR UPDATE ON intake_policies FOR EACH ROW EXECUTE FUNCTION freightctl_intake_policy_guard();
CREATE FUNCTION freightctl_file_check_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE p jsonb; valid boolean:=false;
BEGIN
 SELECT payload INTO p FROM events WHERE (tenant_id,partner_id,event_id)=(NEW.tenant_id,NEW.partner_id,NEW.changed_event_id) AND actor_id=NEW.actor_id AND resource_id=NEW.file_id AND kind='FileCheckChanged';
 IF p IS NULL OR p->>'file_id' IS DISTINCT FROM NEW.file_id::text OR p->>'policy_id' IS DISTINCT FROM NEW.policy_id::text OR p->>'policy_version' IS DISTINCT FROM NEW.policy_version::text OR p->>'policy_hash' IS DISTINCT FROM NEW.policy_hash OR p->'binding' IS DISTINCT FROM NEW.binding OR p->>'state' IS DISTINCT FROM NEW.state OR p->>'revision' IS DISTINCT FROM NEW.revision::text OR p->>'attempts' IS DISTINCT FROM NEW.attempts::text OR p->>'worker_id' IS DISTINCT FROM coalesce(NEW.worker_id::text,'') OR (p->>'lease_until')::timestamptz IS DISTINCT FROM NEW.lease_until OR p->'report' IS DISTINCT FROM NEW.report OR p->>'report_hash' IS DISTINCT FROM NEW.report_hash OR p->>'code' IS DISTINCT FROM NEW.code THEN RAISE EXCEPTION 'file check requires its exact event' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN
  valid:=NEW.state='held' AND NEW.revision=1 AND NEW.attempts=0 AND NEW.report='{}'::jsonb AND NEW.report_hash='' AND EXISTS(SELECT 1 FROM files f JOIN events e ON (e.tenant_id,e.partner_id,e.event_id)=(f.tenant_id,f.partner_id,f.accepted_event_id) WHERE (f.tenant_id,f.partner_id,f.file_id,f.policy,e.actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.file_id,'intake-csv-v1:'||NEW.policy_hash,NEW.actor_id) AND NEW.binding->'file'=jsonb_build_object('id',f.file_id::text,'size_bytes',f.size_bytes,'sha256',f.sha256,'policy',f.policy,'accepted_event_id',f.accepted_event_id::text)) AND EXISTS(SELECT 1 FROM intake_policies i WHERE (i.tenant_id,i.partner_id,i.policy_id,i.version,i.definition_hash,i.state)=(NEW.tenant_id,NEW.partner_id,NEW.policy_id,NEW.policy_version,NEW.policy_hash,'active'));
 ELSE
  IF (NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.file_id,NEW.policy_id,NEW.policy_version,NEW.policy_hash,NEW.binding) IS DISTINCT FROM (OLD.tenant_id,OLD.partner_id,OLD.actor_id,OLD.file_id,OLD.policy_id,OLD.policy_version,OLD.policy_hash,OLD.binding) OR NEW.revision<>OLD.revision+1 THEN RAISE EXCEPTION 'file check binding is immutable' USING ERRCODE='23514';END IF;
  IF NEW.state='running' THEN valid:=(OLD.state IN ('held','failed') OR (OLD.state='running' AND OLD.lease_until<=clock_timestamp())) AND NEW.attempts=OLD.attempts+1 AND NEW.lease_until>clock_timestamp() AND NEW.lease_until<=clock_timestamp()+interval '71 seconds' AND NEW.report='{}'::jsonb AND NEW.report_hash='';
  ELSIF OLD.state='running' THEN valid:=NEW.state IN ('passed','rejected','failed') AND OLD.lease_until>clock_timestamp() AND NEW.attempts=OLD.attempts;
  ELSE valid:=OLD.state='passed' AND NEW.state='released' AND NEW.attempts=OLD.attempts AND NEW.report=OLD.report AND NEW.report_hash=OLD.report_hash;END IF;
 END IF;
 IF NEW.state IN ('passed','released') THEN
  valid:=valid AND NEW.report->>'code'='valid_csv' AND NEW.report->>'engine'='freightctl-csv-v1' AND NEW.report->>'file_id'=NEW.file_id::text AND NEW.report->>'sha256'=NEW.binding->'file'->>'sha256' AND NEW.report->>'bytes_read'=NEW.binding->'file'->>'size_bytes' AND NEW.report->>'policy_hash'=NEW.policy_hash AND EXISTS(SELECT 1 FROM intake_policies i WHERE (i.tenant_id,i.partner_id,i.policy_id,i.version,i.definition_hash,i.state)=(NEW.tenant_id,NEW.partner_id,NEW.policy_id,NEW.policy_version,NEW.policy_hash,'active'));
 END IF;
 IF NOT coalesce(valid,false) THEN RAISE EXCEPTION 'invalid file check transition' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER file_check_guard BEFORE INSERT OR UPDATE ON file_checks FOR EACH ROW EXECUTE FUNCTION freightctl_file_check_guard();
CREATE FUNCTION freightctl_check_receipt_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM events e WHERE (e.tenant_id,e.partner_id,e.event_id)=(NEW.tenant_id,NEW.partner_id,NEW.completed_event_id) AND e.actor_id=NEW.actor_id AND e.resource_id=NEW.resource_id AND e.kind='CheckCommandCompleted' AND e.payload->>'request_key'=NEW.request_key AND e.payload->>'request_hash'=NEW.request_hash AND e.payload->'result'=NEW.result) THEN RAISE EXCEPTION 'check receipt requires its exact event' USING ERRCODE='23514';END IF;RETURN NEW;
END $$;
CREATE TRIGGER check_receipt_guard BEFORE INSERT ON check_receipts FOR EACH ROW EXECUTE FUNCTION freightctl_check_receipt_guard();
CREATE FUNCTION freightctl_file_release_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM file_checks c WHERE (c.tenant_id,c.partner_id,c.file_id,c.actor_id,c.policy_id,c.policy_version,c.policy_hash,c.report_hash,c.changed_event_id,c.state)=(NEW.tenant_id,NEW.partner_id,NEW.file_id,NEW.actor_id,NEW.policy_id,NEW.policy_version,NEW.policy_hash,NEW.report_hash,NEW.released_event_id,'released')) THEN RAISE EXCEPTION 'release proof requires exact authorized checked transition' USING ERRCODE='23514';END IF;RETURN NEW;
END $$;
CREATE TRIGGER file_release_guard BEFORE INSERT ON file_releases FOR EACH ROW EXECUTE FUNCTION freightctl_file_release_guard();
CREATE FUNCTION freightctl_file_check_required() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.policy='integrity-only-v1' AND EXISTS(SELECT 1 FROM intake_policies i WHERE (i.tenant_id,i.partner_id)=(NEW.tenant_id,NEW.partner_id)) THEN RAISE EXCEPTION 'new acceptance cannot bypass a configured intake policy' USING ERRCODE='23514';END IF;
 IF NEW.policy LIKE 'intake-csv-v1:%' AND NOT EXISTS(SELECT 1 FROM file_checks c WHERE (c.tenant_id,c.partner_id,c.file_id)=(NEW.tenant_id,NEW.partner_id,NEW.file_id) AND 'intake-csv-v1:'||c.policy_hash=NEW.policy) THEN RAISE EXCEPTION 'controlled acceptance requires its bound check in the same transaction' USING ERRCODE='23514';END IF;RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER file_check_required AFTER INSERT ON files DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION freightctl_file_check_required();
CREATE FUNCTION freightctl_file_available(t uuid,p uuid,f uuid) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT EXISTS(SELECT 1 FROM files v WHERE (v.tenant_id,v.partner_id,v.file_id)=(t,p,f) AND (v.policy='integrity-only-v1' OR EXISTS(SELECT 1 FROM file_releases c JOIN intake_policies i ON (i.tenant_id,i.partner_id,i.policy_id,i.version)=(c.tenant_id,c.partner_id,c.policy_id,c.policy_version) WHERE (c.tenant_id,c.partner_id,c.file_id,i.state)=(t,p,f,'active') AND v.policy='intake-csv-v1:'||c.policy_hash AND c.policy_hash=i.definition_hash)))
$$;
CREATE FUNCTION freightctl_checked_publication_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.file_id IS NOT NULL AND NOT freightctl_file_available(NEW.tenant_id,NEW.partner_id,NEW.file_id) THEN RAISE EXCEPTION 'held or stale checked bytes cannot be published or dispatched' USING ERRCODE='23514';END IF;RETURN NEW;
END $$;
CREATE TRIGGER checked_namespace_guard BEFORE INSERT OR UPDATE ON namespace_entries FOR EACH ROW WHEN (NEW.kind='file' AND NOT NEW.deleted) EXECUTE FUNCTION freightctl_checked_publication_guard();
CREATE TRIGGER checked_delivery_guard BEFORE INSERT OR UPDATE ON delivery_intents FOR EACH ROW WHEN (NEW.state IN ('draft','queued','staging','publishing')) EXECUTE FUNCTION freightctl_checked_publication_guard();
REVOKE ALL ON FUNCTION freightctl_intake_policy_guard(),freightctl_file_check_guard(),freightctl_check_receipt_guard(),freightctl_file_release_guard(),freightctl_file_check_required(),freightctl_checked_publication_guard(),freightctl_file_available(uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION freightctl_file_available(uuid,uuid,uuid) TO freightctl_runtime;
