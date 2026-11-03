-- Registered FTPS workflows retain exact immutable revisions, source, intents
-- and dispatch consent. No historical migration, role, grant or table changes.
CREATE OR REPLACE FUNCTION freightctl_outbound_dispatch_expected_effect(original delivery_intents,recipient text) RETURNS jsonb LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE d jsonb:=original.definition;dest jsonb;expected jsonb;
BEGIN
 IF d->>'schema_version'='2' THEN
  dest:=d->'ftps'->'destination';
  expected:=jsonb_build_object('protocol','ftps','address',dest->>'address','user',dest->>'user','directory',d->>'directory','filename',d->>'filename','final_path',rtrim(d->>'directory','/')||'/'||original.delivery_id::text||'-'||(d->>'filename'),'host_fingerprint','','key_fingerprint','','key_reference_sha256','','recipient_fingerprint','',
   'ftps',jsonb_build_object('mode',dest->>'mode','server_name',dest->>'server_name','ca_sha256',dest->>'ca_sha256','ca_reference_sha256',encode(sha256(convert_to(dest->>'ca_reference','UTF8')),'hex'),'password_reference_sha256',encode(sha256(convert_to(dest->>'password_reference','UTF8')),'hex'),'staging_path',rtrim(d->'ftps'->>'staging_directory','/')||'/.freightctl-'||original.delivery_id::text||'.partial','receiver_contract',d->'ftps'->'receiver_contract'));
 ELSE
  expected:=jsonb_build_object('protocol','sftp','address',d->'destination'->>'address','user',d->'destination'->>'user','directory',d->>'directory','filename',d->>'filename','final_path',rtrim(d->>'directory','/')||'/'||original.delivery_id::text||'-'||(d->>'filename'),'host_fingerprint',d->'destination'->'host'->>'Fingerprint','key_fingerprint',d->'destination'->>'key_fingerprint','key_reference_sha256',encode(sha256(convert_to(d->'destination'->>'key_reference','UTF8')),'hex'),'recipient_fingerprint',recipient);
  IF d ? 'encryption' THEN expected:=expected||jsonb_build_object('encryption',d->'encryption');END IF;
 END IF;
 IF d ? 'workflow_binding' THEN expected:=expected||jsonb_build_object('workflow_binding',d->'workflow_binding');END IF;
 RETURN expected;
END $$;

CREATE OR REPLACE FUNCTION freightctl_ftps_delivery_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE d jsonb:=NEW.definition;f jsonb;dest jsonb;c jsonb;
BEGIN
 IF d->>'schema_version'='1' AND NOT d ? 'ftps' THEN RETURN NEW;END IF;
 IF d->>'schema_version' IS DISTINCT FROM '2' THEN RAISE EXCEPTION 'unsupported delivery protocol definition' USING ERRCODE='23514';END IF;
 f:=d->'ftps';dest:=f->'destination';c:=f->'receiver_contract';
 IF ARRAY(SELECT jsonb_object_keys(d-'dispatch_approval_policy'-'workflow_binding') ORDER BY 1) IS DISTINCT FROM ARRAY['authority_revision','destination','directory','filename','ftps','namespace_root','schema_version','source','storage_id']::text[]
 OR d->'destination' IS DISTINCT FROM '{"address":"","user":"","host":{"Wire":null,"Fingerprint":""},"key_reference":"","key_fingerprint":""}'::jsonb
 OR ARRAY(SELECT jsonb_object_keys(f) ORDER BY 1) IS DISTINCT FROM ARRAY['destination','receiver_contract','staging_directory']::text[]
 OR ARRAY(SELECT jsonb_object_keys(dest) ORDER BY 1) IS DISTINCT FROM ARRAY['address','ca_reference','ca_sha256','mode','password_reference','password_sha256','server_name','user']::text[]
 OR coalesce(dest->>'mode','') NOT IN ('explicit','implicit')
 OR coalesce(dest->>'ca_sha256','') !~ '^[0-9a-f]{64}$' OR coalesce(dest->>'password_sha256','') !~ '^[0-9a-f]{64}$'
 OR coalesce(c->>'document_sha256','') !~ '^[0-9a-f]{64}$'
 OR c IS DISTINCT FROM jsonb_build_object('schema_version',1,'document_sha256',c->>'document_sha256','staging_visibility','receiver-private','rename','may-replace','duplicates','receiver-deduplicates-delivery-id','receipt','exact-readback')
 OR coalesce(f->>'staging_directory','')='' OR coalesce(d->>'directory','')='' OR f->>'staging_directory'=d->>'directory'
 THEN RAISE EXCEPTION 'invalid distinct FTPS receiver contract' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION freightctl_ftps_connection_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE d jsonb:=NEW.definition;f jsonb;dest jsonb;c jsonb;
BEGIN
 IF d->>'schema_version'='1' AND NOT d ? 'ftps' THEN RETURN NEW;END IF;
 IF d->>'schema_version' IS DISTINCT FROM '2' THEN RAISE EXCEPTION 'unsupported delivery protocol definition' USING ERRCODE='23514';END IF;
 f:=d->'ftps';dest:=f->'destination';c:=f->'receiver_contract';
 IF ARRAY(SELECT jsonb_object_keys(d) ORDER BY 1) IS DISTINCT FROM ARRAY['destination','directory','ftps','schema_version']::text[]
 OR d->'destination' IS DISTINCT FROM '{"address":"","user":"","host":{"Wire":null,"Fingerprint":""},"key_reference":"","key_fingerprint":""}'::jsonb
 OR ARRAY(SELECT jsonb_object_keys(f) ORDER BY 1) IS DISTINCT FROM ARRAY['destination','receiver_contract','staging_directory']::text[]
 OR ARRAY(SELECT jsonb_object_keys(dest) ORDER BY 1) IS DISTINCT FROM ARRAY['address','ca_reference','ca_sha256','mode','password_reference','password_sha256','server_name','user']::text[]
 OR coalesce(dest->>'mode','') NOT IN ('explicit','implicit')
 OR coalesce(dest->>'ca_sha256','') !~ '^[0-9a-f]{64}$' OR coalesce(dest->>'password_sha256','') !~ '^[0-9a-f]{64}$'
 OR coalesce(c->>'document_sha256','') !~ '^[0-9a-f]{64}$'
 OR c IS DISTINCT FROM jsonb_build_object('schema_version',1,'document_sha256',c->>'document_sha256','staging_visibility','receiver-private','rename','may-replace','duplicates','receiver-deduplicates-delivery-id','receipt','exact-readback')
 OR coalesce(f->>'staging_directory','')='' OR coalesce(d->>'directory','')='' OR f->>'staging_directory'=d->>'directory'
 THEN RAISE EXCEPTION 'invalid distinct FTPS receiver contract' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER ftps_connection_guard BEFORE INSERT OR UPDATE ON connection_revisions FOR EACH ROW EXECUTE FUNCTION freightctl_ftps_connection_guard();
REVOKE ALL ON FUNCTION freightctl_ftps_connection_guard() FROM PUBLIC;

CREATE OR REPLACE FUNCTION freightctl_workflow_step_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE e jsonb; planned jsonb;configured jsonb;
BEGIN
 IF NOT EXISTS(SELECT 1 FROM delivery_intents d WHERE (d.tenant_id,d.partner_id,d.actor_id,d.delivery_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.delivery_id) AND d.definition ? 'workflow_binding') THEN RAISE EXCEPTION 'workflow step requires a bound delivery' USING ERRCODE='23514';END IF;
 SELECT payload INTO e FROM events WHERE (tenant_id,partner_id,event_id)=(NEW.tenant_id,NEW.partner_id,NEW.created_event_id) AND actor_id=NEW.actor_id AND resource_id=NEW.run_id AND kind='WorkflowStepBound';
 SELECT freightctl_planned_step(w.definition,r.execution_plan,NEW.ordinal) INTO planned FROM workflow_runs r JOIN workflow_revisions w ON (w.tenant_id,w.partner_id,w.workflow_id,w.version)=(r.tenant_id,r.partner_id,r.workflow_id,r.workflow_version) WHERE (r.tenant_id,r.partner_id,r.run_id,r.actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.run_id,NEW.actor_id);
 SELECT definition INTO configured FROM connection_revisions WHERE (tenant_id,partner_id,connection_id,version,definition_hash)=(NEW.tenant_id,NEW.partner_id,NEW.connection_id,NEW.connection_version,NEW.connection_hash);
 IF configured->>'schema_version' IS DISTINCT FROM CASE planned->>'kind' WHEN 'sftp.deliver' THEN '1' WHEN 'ftps.deliver' THEN '2' END OR e IS NULL OR e->>'run_id' IS DISTINCT FROM NEW.run_id::text OR e->>'step_id' IS DISTINCT FROM NEW.step_id OR e->>'ordinal' IS DISTINCT FROM NEW.ordinal::text OR e->>'delivery_id' IS DISTINCT FROM NEW.delivery_id::text OR e->>'connection_id' IS DISTINCT FROM NEW.connection_id::text OR e->>'connection_version' IS DISTINCT FROM NEW.connection_version::text OR e->>'connection_hash' IS DISTINCT FROM NEW.connection_hash OR planned->>'id' IS DISTINCT FROM NEW.step_id OR coalesce(planned->>'kind','') NOT IN ('sftp.deliver','ftps.deliver') OR planned->'connection'->>'id' IS DISTINCT FROM NEW.connection_id::text OR planned->'connection'->>'version' IS DISTINCT FROM NEW.connection_version::text OR planned->'connection'->>'hash' IS DISTINCT FROM NEW.connection_hash THEN
  RAISE EXCEPTION 'step must match its exact workflow and binding event' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION freightctl_workflow_binding_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.definition ? 'workflow_binding' AND NOT EXISTS(
  SELECT 1 FROM workflow_steps s JOIN workflow_runs r USING(tenant_id,partner_id,run_id) JOIN workflow_revisions w ON (w.tenant_id,w.partner_id,w.workflow_id,w.version)=(r.tenant_id,r.partner_id,r.workflow_id,r.workflow_version) JOIN connection_revisions c ON (c.tenant_id,c.partner_id,c.connection_id,c.version)=(s.tenant_id,s.partner_id,s.connection_id,s.connection_version)
  WHERE (s.tenant_id,s.partner_id,s.actor_id,s.delivery_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.delivery_id)
  AND NEW.definition->'workflow_binding'=jsonb_build_object('workflow_id',r.workflow_id::text,'workflow_version',r.workflow_version,'workflow_hash',r.workflow_hash,'run_id',r.run_id::text,'step_id',s.step_id,'connection_id',s.connection_id::text,'connection_version',s.connection_version,'connection_hash',s.connection_hash)
  AND NEW.definition->'source'=r.source AND NEW.file_id=r.file_id AND NEW.definition->>'storage_id'=r.storage_id::text AND NEW.definition->>'namespace_root'=r.namespace_root AND NEW.definition->>'authority_revision'=r.authority_revision::text
  AND ((NEW.definition->>'schema_version'='1' AND c.definition->>'schema_version'='1' AND NOT NEW.definition ? 'ftps' AND NOT c.definition ? 'ftps' AND freightctl_planned_step(w.definition,r.execution_plan,s.ordinal)->>'kind'='sftp.deliver')
   OR (NEW.definition->>'schema_version'='2' AND c.definition->>'schema_version'='2' AND NEW.definition->'ftps'=c.definition->'ftps' AND freightctl_planned_step(w.definition,r.execution_plan,s.ordinal)->>'kind'='ftps.deliver'))
  AND NEW.definition->'destination'=c.definition->'destination' AND NEW.definition->>'directory'=c.definition->>'directory' AND NEW.definition->>'filename'=freightctl_planned_step(w.definition,r.execution_plan,s.ordinal)->>'filename' AND c.definition_hash=s.connection_hash) THEN
  RAISE EXCEPTION 'delivery requires exact workflow run, step, source and connection bindings' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
