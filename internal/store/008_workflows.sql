-- Keep v1-v7 identities' permissions unchanged. Only new development bootstrap
-- identities default to these additional explicit operation grants.
ALTER TABLE credentials DROP CONSTRAINT credential_permissions_valid;
ALTER TABLE credentials ADD CONSTRAINT credential_permissions_valid CHECK(cardinality(permissions)<=12 AND permissions <@ ARRAY['read','write','list','manage_paths','inspect','audit_read','admin','connections_manage','deliver','workflow_manage','workflow_approve','workflow_execute']::text[]);
ALTER TABLE credentials ALTER COLUMN permissions SET DEFAULT ARRAY['read','write','list','manage_paths','inspect','audit_read','admin','connections_manage','deliver','workflow_manage','workflow_approve','workflow_execute']::text[];
CREATE TABLE connection_revisions (
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,actor_id uuid NOT NULL,connection_id uuid NOT NULL,
 version integer NOT NULL CHECK(version>0),definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object' AND octet_length(definition::text)<=8192),
 definition_hash text NOT NULL CHECK(definition_hash ~ '^[0-9a-f]{64}$'),
 state text NOT NULL CHECK(state IN ('active','revoked')),revision bigint NOT NULL CHECK(revision>0),changed_event_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,connection_id,version),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,changed_event_id) REFERENCES events(tenant_id,partner_id,event_id)
);
CREATE TABLE workflow_revisions (
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,actor_id uuid NOT NULL,workflow_id uuid NOT NULL,
 version integer NOT NULL CHECK(version>0),definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object' AND octet_length(definition::text)<=24576),
 definition_hash text NOT NULL CHECK(definition_hash ~ '^[0-9a-f]{64}$'),
 state text NOT NULL CHECK(state IN ('draft','approved','revoked')),revision bigint NOT NULL CHECK(revision>0),
 approval_authority bigint NOT NULL CHECK(approval_authority>=0),changed_event_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,workflow_id,version),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,changed_event_id) REFERENCES events(tenant_id,partner_id,event_id),
 CHECK((state='draft')=(approval_authority=0))
);
CREATE TABLE workflow_runs (
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,actor_id uuid NOT NULL,run_id uuid NOT NULL,
 workflow_id uuid NOT NULL,workflow_version integer NOT NULL,workflow_hash text NOT NULL CHECK(workflow_hash ~ '^[0-9a-f]{64}$'),
 file_id uuid NOT NULL,source jsonb NOT NULL CHECK(jsonb_typeof(source)='object' AND octet_length(source::text)<=1024),
 storage_id uuid NOT NULL,namespace_root text NOT NULL CHECK(namespace_root='/'),authority_revision bigint NOT NULL CHECK(authority_revision>0),
 state text NOT NULL CHECK(state IN ('queued','running','attention','succeeded','cancelled')),
 reason text NOT NULL CHECK(reason ~ '^[a-z_]{1,64}$'),revision bigint NOT NULL CHECK(revision>0),changed_event_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,run_id),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,workflow_id,workflow_version) REFERENCES workflow_revisions(tenant_id,partner_id,workflow_id,version),
 FOREIGN KEY(tenant_id,partner_id,file_id) REFERENCES files(tenant_id,partner_id,file_id),
 FOREIGN KEY(tenant_id,partner_id,changed_event_id) REFERENCES events(tenant_id,partner_id,event_id)
);
CREATE INDEX workflow_open_runs ON workflow_runs(tenant_id,partner_id,actor_id,state);
CREATE TABLE workflow_steps (
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,actor_id uuid NOT NULL,run_id uuid NOT NULL,
 step_id text NOT NULL CHECK(step_id ~ '^[a-z][a-z0-9_]{0,63}$'),ordinal integer NOT NULL CHECK(ordinal BETWEEN 1 AND 16),
 connection_id uuid NOT NULL,connection_version integer NOT NULL,connection_hash text NOT NULL CHECK(connection_hash ~ '^[0-9a-f]{64}$'),
 delivery_id uuid NOT NULL,created_event_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,run_id,step_id),UNIQUE(tenant_id,partner_id,run_id,ordinal),UNIQUE(tenant_id,partner_id,delivery_id),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,run_id) REFERENCES workflow_runs(tenant_id,partner_id,run_id),
 FOREIGN KEY(tenant_id,partner_id,connection_id,connection_version) REFERENCES connection_revisions(tenant_id,partner_id,connection_id,version),
 FOREIGN KEY(tenant_id,partner_id,delivery_id) REFERENCES delivery_intents(tenant_id,partner_id,delivery_id),
 FOREIGN KEY(tenant_id,partner_id,created_event_id) REFERENCES events(tenant_id,partner_id,event_id)
);
CREATE TABLE workflow_receipts (
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,actor_id uuid NOT NULL,
 request_key text NOT NULL CHECK(request_key ~ '^[A-Za-z0-9._:-]{1,128}$'),request_hash text NOT NULL CHECK(request_hash ~ '^[0-9a-f]{64}$'),
 resource_id uuid NOT NULL,result jsonb NOT NULL CHECK(octet_length(result::text)<=32768),completed_event_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,actor_id,request_key),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,completed_event_id) REFERENCES events(tenant_id,partner_id,event_id)
);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['connection_revisions','workflow_revisions','workflow_runs','workflow_steps','workflow_receipts'] LOOP
  EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('CREATE POLICY scope ON %I USING(tenant_id=nullif(current_setting(''freightctl.tenant_id'',true),'''')::uuid AND partner_id=nullif(current_setting(''freightctl.partner_id'',true),'''')::uuid) WITH CHECK(tenant_id=nullif(current_setting(''freightctl.tenant_id'',true),'''')::uuid AND partner_id=nullif(current_setting(''freightctl.partner_id'',true),'''')::uuid)',t);
  EXECUTE format('CREATE POLICY identity_scope ON %I AS RESTRICTIVE USING(actor_id=nullif(current_setting(''freightctl.actor_id'',true),'''')::uuid) WITH CHECK(actor_id=nullif(current_setting(''freightctl.actor_id'',true),'''')::uuid)',t);
 END LOOP;
END $$;
GRANT SELECT,INSERT,UPDATE ON connection_revisions,workflow_revisions,workflow_runs TO freightctl_runtime;
GRANT SELECT,INSERT ON workflow_steps,workflow_receipts TO freightctl_runtime;
CREATE FUNCTION freightctl_configuration_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE p jsonb; k text; rid uuid; expected text; maximum integer;
BEGIN
 IF TG_TABLE_NAME='connection_revisions' THEN rid:=NEW.connection_id;expected:='ConnectionRevisionChanged';ELSE rid:=NEW.workflow_id;expected:='WorkflowRevisionChanged';END IF;
 SELECT kind,payload INTO k,p FROM events WHERE (tenant_id,partner_id,event_id)=(NEW.tenant_id,NEW.partner_id,NEW.changed_event_id) AND actor_id=NEW.actor_id AND resource_id=rid;
 IF k IS DISTINCT FROM expected OR p->>'id' IS DISTINCT FROM rid::text OR p->>'version' IS DISTINCT FROM NEW.version::text OR p->>'revision' IS DISTINCT FROM NEW.revision::text OR p->'definition' IS DISTINCT FROM NEW.definition OR p->>'definition_hash' IS DISTINCT FROM NEW.definition_hash OR p->>'state' IS DISTINCT FROM NEW.state THEN
  RAISE EXCEPTION 'configuration requires its exact journal event' USING ERRCODE='23514';
 END IF;
 IF TG_OP='INSERT' THEN
  IF TG_TABLE_NAME='connection_revisions' THEN
   SELECT coalesce(max(version),0) INTO maximum FROM connection_revisions WHERE tenant_id=NEW.tenant_id AND partner_id=NEW.partner_id AND connection_id=rid;
   IF NEW.state<>'active' THEN RAISE EXCEPTION 'connection must register active' USING ERRCODE='23514';END IF;
  ELSE
   SELECT coalesce(max(version),0) INTO maximum FROM workflow_revisions WHERE tenant_id=NEW.tenant_id AND partner_id=NEW.partner_id AND workflow_id=rid;
   IF NEW.state<>'draft' THEN RAISE EXCEPTION 'workflow must start as draft' USING ERRCODE='23514';END IF;
  END IF;
  IF NEW.revision<>1 OR NEW.version<>maximum+1 THEN RAISE EXCEPTION 'configuration version must be contiguous' USING ERRCODE='23514';END IF;
 ELSE
  IF (NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.version,NEW.definition,NEW.definition_hash) IS DISTINCT FROM (OLD.tenant_id,OLD.partner_id,OLD.actor_id,OLD.version,OLD.definition,OLD.definition_hash) OR NEW.revision<>OLD.revision+1 THEN
   RAISE EXCEPTION 'configuration definition is immutable' USING ERRCODE='23514';
  END IF;
  IF TG_TABLE_NAME='connection_revisions' THEN
   IF NEW.connection_id<>OLD.connection_id OR OLD.state<>'active' OR NEW.state<>'revoked' THEN RAISE EXCEPTION 'invalid connection transition' USING ERRCODE='23514';END IF;
  ELSE
   IF NEW.workflow_id<>OLD.workflow_id OR NOT ((OLD.state='draft' AND NEW.state='approved') OR (OLD.state='approved' AND NEW.state='revoked' AND NEW.approval_authority=OLD.approval_authority)) THEN
    RAISE EXCEPTION 'invalid workflow transition' USING ERRCODE='23514';END IF;
  END IF;
 END IF;
 IF TG_TABLE_NAME='workflow_revisions' THEN
  IF p->>'approval_authority' IS DISTINCT FROM NEW.approval_authority::text THEN RAISE EXCEPTION 'approval authority must match its event' USING ERRCODE='23514';END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER connection_guard BEFORE INSERT OR UPDATE ON connection_revisions FOR EACH ROW EXECUTE FUNCTION freightctl_configuration_guard();
CREATE TRIGGER workflow_guard BEFORE INSERT OR UPDATE ON workflow_revisions FOR EACH ROW EXECUTE FUNCTION freightctl_configuration_guard();
CREATE FUNCTION freightctl_run_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE p jsonb;
BEGIN
 SELECT payload INTO p FROM events WHERE (tenant_id,partner_id,event_id)=(NEW.tenant_id,NEW.partner_id,NEW.changed_event_id) AND actor_id=NEW.actor_id AND resource_id=NEW.run_id AND kind='WorkflowRunChanged';
 IF p IS NULL OR p->>'id' IS DISTINCT FROM NEW.run_id::text OR p->>'workflow_id' IS DISTINCT FROM NEW.workflow_id::text OR p->>'workflow_version' IS DISTINCT FROM NEW.workflow_version::text OR p->>'workflow_hash' IS DISTINCT FROM NEW.workflow_hash OR p->>'file_id' IS DISTINCT FROM NEW.file_id::text OR p->'source' IS DISTINCT FROM NEW.source OR p->>'storage_id' IS DISTINCT FROM NEW.storage_id::text OR p->>'namespace_root' IS DISTINCT FROM NEW.namespace_root OR p->>'authority_revision' IS DISTINCT FROM NEW.authority_revision::text OR p->>'state' IS DISTINCT FROM NEW.state OR p->>'reason' IS DISTINCT FROM NEW.reason OR p->>'revision' IS DISTINCT FROM NEW.revision::text THEN
  RAISE EXCEPTION 'workflow run requires its exact event' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.state<>'queued' OR NEW.revision<>1 OR NOT EXISTS(SELECT 1 FROM workflow_revisions w WHERE (w.tenant_id,w.partner_id,w.workflow_id,w.version,w.actor_id,w.definition_hash,w.state,w.approval_authority)=(NEW.tenant_id,NEW.partner_id,NEW.workflow_id,NEW.workflow_version,NEW.actor_id,NEW.workflow_hash,'approved',NEW.authority_revision)) OR NOT EXISTS(SELECT 1 FROM files f WHERE (f.tenant_id,f.partner_id,f.file_id)=(NEW.tenant_id,NEW.partner_id,NEW.file_id) AND NEW.source=jsonb_build_object('id',f.file_id::text,'size_bytes',f.size_bytes,'sha256',f.sha256,'policy',f.policy,'accepted_event_id',f.accepted_event_id::text)) THEN
   RAISE EXCEPTION 'run requires exact approved workflow and accepted source' USING ERRCODE='23514';END IF;
 ELSE
  IF (NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.run_id,NEW.workflow_id,NEW.workflow_version,NEW.workflow_hash,NEW.file_id,NEW.source,NEW.storage_id,NEW.namespace_root,NEW.authority_revision) IS DISTINCT FROM (OLD.tenant_id,OLD.partner_id,OLD.actor_id,OLD.run_id,OLD.workflow_id,OLD.workflow_version,OLD.workflow_hash,OLD.file_id,OLD.source,OLD.storage_id,OLD.namespace_root,OLD.authority_revision) OR OLD.state IN ('succeeded','cancelled') OR NEW.state='queued' OR NEW.revision<>OLD.revision+1 THEN
   RAISE EXCEPTION 'invalid workflow run transition' USING ERRCODE='23514';END IF;
  IF NEW.state='succeeded' AND EXISTS(SELECT 1 FROM workflow_steps s JOIN delivery_intents d USING(tenant_id,partner_id,delivery_id) WHERE (s.tenant_id,s.partner_id,s.run_id)=(NEW.tenant_id,NEW.partner_id,NEW.run_id) AND d.state<>'succeeded') THEN RAISE EXCEPTION 'run success requires every exact intent receipt' USING ERRCODE='23514';END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER workflow_run_guard BEFORE INSERT OR UPDATE ON workflow_runs FOR EACH ROW EXECUTE FUNCTION freightctl_run_guard();
CREATE FUNCTION freightctl_workflow_step_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE e jsonb; planned jsonb;
BEGIN
 IF NOT EXISTS(SELECT 1 FROM delivery_intents d WHERE (d.tenant_id,d.partner_id,d.actor_id,d.delivery_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.delivery_id) AND d.definition ? 'workflow_binding') THEN RAISE EXCEPTION 'workflow step requires a bound delivery' USING ERRCODE='23514';END IF;
 SELECT payload INTO e FROM events WHERE (tenant_id,partner_id,event_id)=(NEW.tenant_id,NEW.partner_id,NEW.created_event_id) AND actor_id=NEW.actor_id AND resource_id=NEW.run_id AND kind='WorkflowStepBound';
 SELECT w.definition->'steps'->(NEW.ordinal-1) INTO planned FROM workflow_runs r JOIN workflow_revisions w ON (w.tenant_id,w.partner_id,w.workflow_id,w.version)=(r.tenant_id,r.partner_id,r.workflow_id,r.workflow_version) WHERE (r.tenant_id,r.partner_id,r.run_id,r.actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.run_id,NEW.actor_id);
 IF e IS NULL OR e->>'run_id' IS DISTINCT FROM NEW.run_id::text OR e->>'step_id' IS DISTINCT FROM NEW.step_id OR e->>'ordinal' IS DISTINCT FROM NEW.ordinal::text OR e->>'delivery_id' IS DISTINCT FROM NEW.delivery_id::text OR e->>'connection_id' IS DISTINCT FROM NEW.connection_id::text OR e->>'connection_version' IS DISTINCT FROM NEW.connection_version::text OR e->>'connection_hash' IS DISTINCT FROM NEW.connection_hash OR planned->>'id' IS DISTINCT FROM NEW.step_id OR planned->>'kind' IS DISTINCT FROM 'sftp.deliver' OR planned->'connection'->>'id' IS DISTINCT FROM NEW.connection_id::text OR planned->'connection'->>'version' IS DISTINCT FROM NEW.connection_version::text OR planned->'connection'->>'hash' IS DISTINCT FROM NEW.connection_hash THEN
  RAISE EXCEPTION 'step must match its exact workflow and binding event' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER workflow_step_guard BEFORE INSERT ON workflow_steps FOR EACH ROW EXECUTE FUNCTION freightctl_workflow_step_guard();
CREATE FUNCTION freightctl_workflow_binding_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.definition ? 'workflow_binding' AND NOT EXISTS(
  SELECT 1 FROM workflow_steps s JOIN workflow_runs r USING(tenant_id,partner_id,run_id) JOIN workflow_revisions w ON (w.tenant_id,w.partner_id,w.workflow_id,w.version)=(r.tenant_id,r.partner_id,r.workflow_id,r.workflow_version) JOIN connection_revisions c ON (c.tenant_id,c.partner_id,c.connection_id,c.version)=(s.tenant_id,s.partner_id,s.connection_id,s.connection_version)
  WHERE (s.tenant_id,s.partner_id,s.actor_id,s.delivery_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.delivery_id)
  AND NEW.definition->'workflow_binding'=jsonb_build_object('workflow_id',r.workflow_id::text,'workflow_version',r.workflow_version,'workflow_hash',r.workflow_hash,'run_id',r.run_id::text,'step_id',s.step_id,'connection_id',s.connection_id::text,'connection_version',s.connection_version,'connection_hash',s.connection_hash)
  AND NEW.definition->'source'=r.source AND NEW.file_id=r.file_id AND NEW.definition->>'storage_id'=r.storage_id::text AND NEW.definition->>'namespace_root'=r.namespace_root AND NEW.definition->>'authority_revision'=r.authority_revision::text
  AND NEW.definition->'destination'=c.definition->'destination' AND NEW.definition->>'directory'=c.definition->>'directory' AND NEW.definition->>'filename'=w.definition->'steps'->(s.ordinal-1)->>'filename' AND c.definition_hash=s.connection_hash) THEN
  RAISE EXCEPTION 'delivery requires exact workflow run, step, source and connection bindings' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER workflow_delivery_binding AFTER INSERT OR UPDATE ON delivery_intents DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION freightctl_workflow_binding_guard();
CREATE FUNCTION freightctl_workflow_run_complete() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM workflow_revisions w WHERE (w.tenant_id,w.partner_id,w.workflow_id,w.version)=(NEW.tenant_id,NEW.partner_id,NEW.workflow_id,NEW.workflow_version) AND jsonb_array_length(w.definition->'steps')=(SELECT count(*) FROM workflow_steps s WHERE (s.tenant_id,s.partner_id,s.run_id)=(NEW.tenant_id,NEW.partner_id,NEW.run_id))) THEN
  RAISE EXCEPTION 'run must bind all workflow step intents atomically' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER workflow_run_complete AFTER INSERT OR UPDATE ON workflow_runs DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION freightctl_workflow_run_complete();
CREATE FUNCTION freightctl_workflow_receipt_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM events e WHERE (e.tenant_id,e.partner_id,e.event_id)=(NEW.tenant_id,NEW.partner_id,NEW.completed_event_id) AND e.actor_id=NEW.actor_id AND e.resource_id=NEW.resource_id AND e.kind='WorkflowCommandCompleted' AND e.payload->>'request_key'=NEW.request_key AND e.payload->>'request_hash'=NEW.request_hash AND e.payload->'result'=NEW.result) THEN RAISE EXCEPTION 'workflow receipt requires its exact event' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER workflow_receipt_guard BEFORE INSERT ON workflow_receipts FOR EACH ROW EXECUTE FUNCTION freightctl_workflow_receipt_guard();
REVOKE ALL ON FUNCTION freightctl_configuration_guard(),freightctl_run_guard(),freightctl_workflow_step_guard(),freightctl_workflow_binding_guard(),freightctl_workflow_run_complete(),freightctl_workflow_receipt_guard() FROM PUBLIC;
