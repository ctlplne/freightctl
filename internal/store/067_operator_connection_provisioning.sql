-- A narrow non-login projector can write an operator-approved connection to
-- another actor's private catalog. Runtime row and event authority stay intact.
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='freightctl_connection_writer') THEN
  BEGIN CREATE ROLE freightctl_connection_writer NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL;END;
 END IF;
 IF EXISTS(SELECT 1 FROM pg_roles r WHERE r.rolname='freightctl_connection_writer' AND
 (r.rolcanlogin OR r.rolinherit OR r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR
 EXISTS(SELECT 1 FROM pg_auth_members m WHERE m.member=r.oid OR m.roleid=r.oid))) THEN
  RAISE EXCEPTION 'connection writer must be an isolated non-login role';
 END IF;
END $$;
GRANT USAGE ON SCHEMA public TO freightctl_connection_writer;
GRANT SELECT (tenant_id,partner_id,actor_id,namespace_root,authority_revision,permissions,revoked_at,expires_at) ON credentials TO freightctl_connection_writer;
GRANT SELECT ON events TO freightctl_connection_writer;
GRANT SELECT,INSERT ON connection_revisions TO freightctl_connection_writer;
GRANT UPDATE (state,revision,changed_event_id) ON connection_revisions TO freightctl_connection_writer;
GRANT EXECUTE ON FUNCTION freightctl_authority_read_lock(uuid,uuid) TO freightctl_connection_writer;
-- PostgreSQL checks EXECUTE on the functions referenced by the table's
-- constraints, even for an inserted SFTP row with no local or DAV profile.
GRANT EXECUTE ON FUNCTION freightctl_local_collection_connection(jsonb),freightctl_dav_collection_connection(jsonb) TO freightctl_connection_writer;

-- Keep the original tenant/partner policy and the runtime actor restriction.
ALTER POLICY identity_scope ON connection_revisions
 USING (actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid OR current_user='freightctl_connection_writer')
 WITH CHECK (actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid OR current_user='freightctl_connection_writer');
CREATE OR REPLACE TRIGGER connection_guard BEFORE INSERT OR UPDATE ON connection_revisions FOR EACH ROW
 WHEN (current_user<>'freightctl_connection_writer') EXECUTE FUNCTION freightctl_configuration_guard();

CREATE FUNCTION freightctl_connection_provision_project() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog,public,pg_temp SET row_security=on AS $$
DECLARE
 r jsonb:=NEW.result;
 bound jsonb;
 original jsonb;
 source public.connection_revisions;
 journal_id uuid:=(r->>'event_id')::uuid;
 prior_event uuid;
 recipient uuid:=(r->>'recipient_actor_id')::uuid;
BEGIN
 IF NEW.actor_id IS DISTINCT FROM nullif(current_setting('freightctl.actor_id',true),'')::uuid THEN
  RAISE EXCEPTION 'connection provisioning requires the recording actor' USING ERRCODE='42501';
 END IF;
 PERFORM public.freightctl_authority_read_lock(NEW.tenant_id,NEW.partner_id);
 IF NOT EXISTS(SELECT 1 FROM public.credentials c WHERE (c.tenant_id,c.partner_id,c.actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id)
   AND c.namespace_root='/' AND c.permissions @> ARRAY['admin','connections_manage']::text[] AND c.revoked_at IS NULL
   AND (c.expires_at IS NULL OR c.expires_at>clock_timestamp()) AND c.authority_revision::text=r->>'operator_authority_revision') THEN
  RAISE EXCEPTION 'connection provisioning requires current operator authority' USING ERRCODE='42501';
 END IF;
 SELECT e.payload INTO bound FROM public.events e
  WHERE (e.tenant_id,e.partner_id,e.actor_id,e.event_id,e.resource_id,e.kind)=
        (NEW.tenant_id,NEW.partner_id,NEW.actor_id,journal_id,NEW.resource_id,'OperatorConnectionChanged');
 IF bound IS NULL OR bound->>'request_key' IS DISTINCT FROM NEW.request_key OR bound->>'request_hash' IS DISTINCT FROM NEW.request_hash
   OR bound->'provision' IS DISTINCT FROM (r - 'event_id') OR r->>'operator_actor_id' IS DISTINCT FROM NEW.actor_id::text
   OR r->'connection'->>'id' IS DISTINCT FROM NEW.resource_id::text OR r->'connection'->>'version' IS DISTINCT FROM '1'
   OR r->'connection'->>'hash' IS DISTINCT FROM r->'source'->>'hash' OR recipient IS NULL OR recipient=NEW.actor_id THEN
  RAISE EXCEPTION 'connection provisioning requires its exact operator event and receipt' USING ERRCODE='23514';
 END IF;
 IF r->>'operation'='provision' THEN
  IF r->>'state' IS DISTINCT FROM 'active' OR r->>'revision' IS DISTINCT FROM '1' OR r ? 'provision_event_id'
    OR NEW.resource_id::text=r->'source'->>'id' THEN
   RAISE EXCEPTION 'invalid provisioned connection identity' USING ERRCODE='23514';
  END IF;
  IF NOT EXISTS(SELECT 1 FROM public.credentials c WHERE (c.tenant_id,c.partner_id,c.actor_id)=(NEW.tenant_id,NEW.partner_id,recipient)
    AND c.namespace_root='/' AND c.permissions @> ARRAY['read','deliver','workflow_execute']::text[]
    AND c.authority_revision::text=r->>'recipient_authority_revision' AND c.revoked_at IS NULL
    AND (c.expires_at IS NULL OR c.expires_at>clock_timestamp())) THEN
   RAISE EXCEPTION 'reviewed connection recipient authority changed' USING ERRCODE='40001';
  END IF;
  SELECT c.* INTO source FROM public.connection_revisions c
   WHERE (c.tenant_id,c.partner_id,c.actor_id,c.connection_id,c.version,c.definition_hash,c.state)=
         (NEW.tenant_id,NEW.partner_id,NEW.actor_id,(r->'source'->>'id')::uuid,(r->'source'->>'version')::integer,r->'source'->>'hash','active')
    AND c.definition->>'schema_version'='1' FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION 'approved source connection changed' USING ERRCODE='55000';END IF;
  INSERT INTO public.connection_revisions(tenant_id,partner_id,actor_id,connection_id,version,definition,definition_hash,state,revision,changed_event_id)
   VALUES(NEW.tenant_id,NEW.partner_id,recipient,NEW.resource_id,1,source.definition,source.definition_hash,'active',1,journal_id);
 ELSIF r->>'operation'='revoke' THEN
  prior_event:=(r->>'provision_event_id')::uuid;
  SELECT e.payload->'provision' INTO original FROM public.events e
   WHERE (e.tenant_id,e.partner_id,e.actor_id,e.event_id,e.resource_id,e.kind)=
         (NEW.tenant_id,NEW.partner_id,NEW.actor_id,prior_event,NEW.resource_id,'OperatorConnectionChanged');
  IF original->>'operation' IS DISTINCT FROM 'provision' OR original->'source' IS DISTINCT FROM r->'source'
    OR original->'connection' IS DISTINCT FROM r->'connection' OR original->>'recipient_actor_id' IS DISTINCT FROM r->>'recipient_actor_id'
    OR original->>'recipient_authority_revision' IS DISTINCT FROM r->>'recipient_authority_revision'
    OR r->>'state' IS DISTINCT FROM 'revoked' OR r->>'revision' IS DISTINCT FROM '2' THEN
   RAISE EXCEPTION 'revocation requires the original operator provision' USING ERRCODE='23514';
  END IF;
  UPDATE public.connection_revisions SET state='revoked',revision=2,changed_event_id=journal_id
   WHERE (tenant_id,partner_id,actor_id,connection_id,version,definition_hash,state,revision,changed_event_id)=
         (NEW.tenant_id,NEW.partner_id,recipient,NEW.resource_id,1,r->'connection'->>'hash','active',1,prior_event);
  IF NOT FOUND THEN RAISE EXCEPTION 'provisioned connection changed' USING ERRCODE='55000';END IF;
 ELSE
  RAISE EXCEPTION 'unknown connection provisioning operation' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
ALTER FUNCTION freightctl_connection_provision_project() OWNER TO freightctl_connection_writer;
REVOKE ALL ON FUNCTION freightctl_connection_provision_project() FROM PUBLIC;
CREATE TRIGGER operator_connection_projection AFTER INSERT ON workflow_receipts FOR EACH ROW
 WHEN (NEW.result->>'profile'='operator-provisioned-connection-v1') EXECUTE FUNCTION freightctl_connection_provision_project();

CREATE FUNCTION freightctl_operator_connection_event_complete() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM public.workflow_receipts w WHERE (w.tenant_id,w.partner_id,w.actor_id,w.resource_id,w.request_key,w.request_hash)=
  (NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.resource_id,NEW.payload->>'request_key',NEW.payload->>'request_hash')
   AND w.result->>'profile'='operator-provisioned-connection-v1' AND w.result->>'event_id'=NEW.event_id::text
   AND w.result-'event_id'=NEW.payload->'provision') THEN
  RAISE EXCEPTION 'operator connection event requires its atomic receipt' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION freightctl_operator_connection_event_complete() FROM PUBLIC;
CREATE CONSTRAINT TRIGGER operator_connection_event_complete AFTER INSERT ON events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
 WHEN (NEW.kind='OperatorConnectionChanged') EXECUTE FUNCTION freightctl_operator_connection_event_complete();

CREATE FUNCTION freightctl_connection_writer_safe() RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT EXISTS(SELECT 1 FROM pg_roles r JOIN pg_proc f ON f.oid='public.freightctl_connection_provision_project()'::regprocedure AND f.proowner=r.oid
 WHERE r.rolname='freightctl_connection_writer' AND NOT(r.rolcanlogin OR r.rolinherit OR r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication)
 AND f.prosecdef AND 'row_security=on'=ANY(f.proconfig) AND EXISTS(SELECT 1 FROM unnest(f.proconfig)c WHERE replace(c,' ','')='search_path=pg_catalog,public,pg_temp')
 AND NOT has_function_privilege('freightctl_runtime',f.oid,'EXECUTE') AND NOT has_schema_privilege(r.oid,'public','CREATE')
 AND NOT EXISTS(SELECT 1 FROM pg_auth_members m WHERE m.member=r.oid OR m.roleid=r.oid)
 AND NOT EXISTS(SELECT 1 FROM pg_class c WHERE c.relnamespace='public'::regnamespace AND c.relowner=r.oid))
$$;
