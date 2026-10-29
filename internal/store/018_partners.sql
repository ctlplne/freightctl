-- Tenant directory authority is separate from partner account/file grants.
CREATE TABLE tenant_administrators(
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,actor_id uuid NOT NULL,
 authority_revision bigint NOT NULL CHECK(authority_revision>0),revision bigint NOT NULL CHECK(revision>0),
 state text NOT NULL CHECK(state IN ('active','revoked')),event_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,event_id) REFERENCES events(tenant_id,partner_id,event_id)
);
CREATE TABLE tenant_admin_commands(
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,actor_id uuid NOT NULL,
 request_key text NOT NULL CHECK(request_key ~ '^[A-Za-z0-9._:-]{1,128}$'),
 request_hash text NOT NULL CHECK(request_hash ~ '^[0-9a-f]{64}$'),event_id uuid NOT NULL,
 definition jsonb NOT NULL CHECK(octet_length(definition::text)<=4096),
 result jsonb NOT NULL CHECK(octet_length(result::text)<=8192),
 PRIMARY KEY(tenant_id,partner_id,request_key),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,event_id) REFERENCES events(tenant_id,partner_id,event_id)
);
DO $$ DECLARE t text;BEGIN
 FOREACH t IN ARRAY ARRAY['tenant_administrators','tenant_admin_commands'] LOOP
  EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',t);EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('CREATE POLICY scope ON %I USING(tenant_id=nullif(current_setting(''freightctl.tenant_id'',true),'''')::uuid AND partner_id=nullif(current_setting(''freightctl.partner_id'',true),'''')::uuid AND actor_id=nullif(current_setting(''freightctl.actor_id'',true),'''')::uuid)',t);
 END LOOP;
END $$;
REVOKE ALL ON tenant_administrators,tenant_admin_commands FROM PUBLIC;
GRANT SELECT ON tenant_administrators,tenant_admin_commands TO freightctl_runtime;

CREATE FUNCTION freightctl_tenant_manager(t uuid) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT t=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND EXISTS(
 SELECT 1 FROM public.tenant_administrators a JOIN public.credentials c USING(tenant_id,partner_id,actor_id)
 WHERE a.tenant_id=t AND a.partner_id=nullif(current_setting('freightctl.partner_id',true),'')::uuid AND a.actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid
 AND a.state='active' AND a.authority_revision=c.authority_revision AND c.namespace_root='/' AND c.permissions @> ARRAY['admin','accounts_manage']::text[]
 AND c.revoked_at IS NULL AND (c.expires_at IS NULL OR c.expires_at>clock_timestamp()))
$$;
CREATE FUNCTION freightctl_tenant_admin_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE e events;r jsonb;c credentials;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'tenant authority cannot be deleted' USING ERRCODE='23514';END IF;
 SELECT * INTO e FROM events WHERE (tenant_id,partner_id,event_id,actor_id,resource_id,kind)=(NEW.tenant_id,NEW.partner_id,NEW.event_id,NEW.actor_id,NEW.actor_id,'TenantAdministratorChanged');r:=e.payload->'membership';
 IF r IS NULL OR (r->>'tenant_id',r->>'partner_id',r->>'actor_id',r->>'authority_revision',r->>'revision',r->>'state',r->>'event_id') IS DISTINCT FROM
 (NEW.tenant_id::text,NEW.partner_id::text,NEW.actor_id::text,NEW.authority_revision::text,NEW.revision::text,NEW.state,NEW.event_id::text) THEN RAISE EXCEPTION 'tenant authority needs exact event' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.revision<>1 OR NEW.state<>'active' THEN RAISE EXCEPTION 'invalid tenant authority creation' USING ERRCODE='23514';END IF;
 ELSE
  IF (NEW.tenant_id,NEW.partner_id,NEW.actor_id) IS DISTINCT FROM (OLD.tenant_id,OLD.partner_id,OLD.actor_id) OR NEW.revision<>OLD.revision+1 THEN RAISE EXCEPTION 'tenant authority revision changed' USING ERRCODE='23514';END IF;
 END IF;
 IF NEW.state='active' THEN
  SELECT * INTO c FROM credentials WHERE (tenant_id,partner_id,actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id);
  IF c.authority_revision IS DISTINCT FROM NEW.authority_revision OR c.namespace_root<>'/' OR NOT(c.permissions @> ARRAY['admin','accounts_manage']::text[]) OR c.revoked_at IS NOT NULL OR c.expires_at<=clock_timestamp() THEN RAISE EXCEPTION 'tenant authority requires current root administrator' USING ERRCODE='23514';END IF;
 END IF;RETURN NEW;
END $$;
CREATE TRIGGER tenant_admin_guard BEFORE INSERT OR UPDATE OR DELETE ON tenant_administrators FOR EACH ROW EXECUTE FUNCTION freightctl_tenant_admin_guard();
CREATE FUNCTION freightctl_tenant_admin_receipt_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE e events;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'tenant authority receipts are immutable' USING ERRCODE='23514';END IF;
 SELECT * INTO e FROM events WHERE (tenant_id,partner_id,event_id,actor_id,kind)=(NEW.tenant_id,NEW.partner_id,NEW.event_id,NEW.actor_id,'TenantAdministratorChanged');
 IF e.payload->>'request_key' IS DISTINCT FROM NEW.request_key OR e.payload->>'request_hash' IS DISTINCT FROM NEW.request_hash OR e.payload->'request' IS DISTINCT FROM NEW.definition OR e.payload->'membership' IS DISTINCT FROM NEW.result OR NOT EXISTS(
 SELECT 1 FROM tenant_administrators a WHERE (a.tenant_id,a.partner_id,a.actor_id,a.event_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.event_id)) THEN RAISE EXCEPTION 'tenant authority receipt needs exact event/projection' USING ERRCODE='23514';END IF;RETURN NEW;
END $$;
CREATE TRIGGER tenant_admin_receipt_guard BEFORE INSERT OR UPDATE OR DELETE ON tenant_admin_commands FOR EACH ROW EXECUTE FUNCTION freightctl_tenant_admin_receipt_guard();

CREATE TABLE partner_registrations(
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,actor_id uuid NOT NULL,target_partner_id uuid NOT NULL,admin_id uuid NOT NULL,
 request_key text NOT NULL CHECK(request_key ~ '^[A-Za-z0-9._:-]{1,128}$'),request_hash text NOT NULL CHECK(request_hash ~ '^[0-9a-f]{64}$'),
 definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object' AND octet_length(definition::text)<=8192),
 event_id uuid NOT NULL,enrollment_event_id uuid NOT NULL,result jsonb NOT NULL CHECK(octet_length(result::text)<=8192),
 PRIMARY KEY(tenant_id,target_partner_id),UNIQUE(tenant_id,partner_id,actor_id,request_key),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,event_id) REFERENCES events(tenant_id,partner_id,event_id),
 FOREIGN KEY(tenant_id,target_partner_id,admin_id) REFERENCES credentials(tenant_id,partner_id,actor_id) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(tenant_id,target_partner_id,enrollment_event_id) REFERENCES events(tenant_id,partner_id,event_id) DEFERRABLE INITIALLY DEFERRED
);
ALTER TABLE partner_registrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE partner_registrations FORCE ROW LEVEL SECURITY;
CREATE POLICY directory ON partner_registrations USING(tenant_id=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND freightctl_tenant_manager(tenant_id))
 WITH CHECK(tenant_id=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND partner_id=nullif(current_setting('freightctl.partner_id',true),'')::uuid AND actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid AND freightctl_tenant_manager(tenant_id));
GRANT SELECT,INSERT ON partner_registrations TO freightctl_runtime;

DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='freightctl_partners_writer') THEN
  BEGIN CREATE ROLE freightctl_partners_writer NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL;END;
 END IF;
 IF EXISTS(SELECT 1 FROM pg_roles r WHERE r.rolname='freightctl_partners_writer' AND
 (r.rolcanlogin OR r.rolinherit OR r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR EXISTS(SELECT 1 FROM pg_auth_members m WHERE m.member=r.oid OR m.roleid=r.oid))) THEN RAISE EXCEPTION 'partner writer must be isolated non-login role';END IF;
END $$;
GRANT USAGE ON SCHEMA public TO freightctl_partners_writer;
GRANT SELECT ON tenant_administrators TO freightctl_partners_writer;
GRANT SELECT,INSERT ON partners,events TO freightctl_partners_writer;
-- UPDATE is needed by PostgreSQL for FOR SHARE on the controlling credential.
-- The role has no login/membership; its trigger never issues credential UPDATE.
GRANT SELECT,INSERT,UPDATE ON credentials TO freightctl_partners_writer;
CREATE POLICY tenant_directory ON partners TO freightctl_runtime,freightctl_partners_writer USING(tenant_id=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND freightctl_tenant_manager(tenant_id));

CREATE FUNCTION freightctl_project_partner() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog,public,pg_temp SET row_security=on AS $$
DECLARE e public.events;m public.credentials;d jsonb;p text[];control_partner text;manager text;tenant_revision bigint;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'partner enrollment is immutable' USING ERRCODE='23514';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id::text||':partner-directory',0));
 control_partner:=current_setting('freightctl.partner_id',true);manager:=current_setting('freightctl.actor_id',true);
 IF NOT public.freightctl_partner_writer_safe() OR NOT public.freightctl_tenant_manager(NEW.tenant_id) OR NEW.partner_id::text IS DISTINCT FROM control_partner OR NEW.actor_id::text IS DISTINCT FROM manager THEN RAISE EXCEPTION 'partner enrollment needs tenant authority' USING ERRCODE='42501';END IF;
 SELECT * INTO m FROM public.credentials WHERE (tenant_id,partner_id,actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id) FOR SHARE;
 SELECT revision INTO tenant_revision FROM public.tenant_administrators WHERE (tenant_id,partner_id,actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id) AND state='active' AND authority_revision=m.authority_revision;
 SELECT * INTO e FROM public.events WHERE (tenant_id,partner_id,event_id,actor_id,resource_id,kind)=(NEW.tenant_id,NEW.partner_id,NEW.event_id,NEW.actor_id,NEW.target_partner_id,'PartnerRegistered');d:=NEW.definition;
 IF e.payload->>'request_key' IS DISTINCT FROM NEW.request_key OR e.payload->>'request_hash' IS DISTINCT FROM NEW.request_hash OR e.payload->'definition' IS DISTINCT FROM d OR e.payload->'partner' IS DISTINCT FROM NEW.result OR e.payload->>'enrollment_event_id' IS DISTINCT FROM NEW.enrollment_event_id::text THEN RAISE EXCEPTION 'partner enrollment requires exact event/receipt' USING ERRCODE='23514';END IF;
 IF ARRAY(SELECT jsonb_object_keys(d) ORDER BY 1) IS DISTINCT FROM ARRAY['admin_id','admin_label','credential_sha256','expected_authority_revision','expected_tenant_revision','label','partner_id','permissions']::text[] OR d->>'partner_id' IS DISTINCT FROM NEW.target_partner_id::text OR d->>'admin_id' IS DISTINCT FROM NEW.admin_id::text OR d->>'credential_sha256' !~ '^[0-9a-f]{64}$' OR jsonb_typeof(d->'permissions') IS DISTINCT FROM 'array' OR jsonb_typeof(d->'label') IS DISTINCT FROM 'string' OR jsonb_typeof(d->'admin_label') IS DISTINCT FROM 'string' THEN RAISE EXCEPTION 'invalid partner definition' USING ERRCODE='23514';END IF;
 IF (d->>'expected_authority_revision')::bigint IS DISTINCT FROM m.authority_revision OR (d->>'expected_tenant_revision')::bigint IS DISTINCT FROM tenant_revision THEN RAISE EXCEPTION 'reviewed tenant authority changed' USING ERRCODE='23514';END IF;
 IF octet_length(d->>'label') NOT BETWEEN 1 AND 128 OR octet_length(d->>'admin_label') NOT BETWEEN 1 AND 128 OR d->>'label' ~ '[[:cntrl:]]' OR d->>'admin_label' ~ '[[:cntrl:]]' THEN RAISE EXCEPTION 'invalid partner labels' USING ERRCODE='23514';END IF;
 p:=ARRAY(SELECT jsonb_array_elements_text(d->'permissions'));
 IF cardinality(p)>21 OR p<>ARRAY(SELECT DISTINCT unnest(p) ORDER BY 1) OR NOT(p<@m.permissions) OR NOT(p @> ARRAY['admin','accounts_manage']::text[]) THEN RAISE EXCEPTION 'initial administrator grants exceed manager authority' USING ERRCODE='42501';END IF;
 IF (NEW.result->>'id',NEW.result->>'admin_id',NEW.result->>'label',NEW.result->>'admin_label',NEW.result->>'event_id',NEW.result->>'namespace_root') IS DISTINCT FROM (NEW.target_partner_id::text,NEW.admin_id::text,d->>'label',d->>'admin_label',NEW.event_id::text,'/') OR NEW.result->'permissions' IS DISTINCT FROM d->'permissions' OR (NEW.result->>'registered_at')::timestamptz IS DISTINCT FROM e.happened_at THEN RAISE EXCEPTION 'partner result differs from definition' USING ERRCODE='23514';END IF;
 -- The definer has no bypass privilege. Switch only after validating the
 -- controlling actor; restore both settings before returning to its caller.
 PERFORM set_config('freightctl.partner_id',NEW.target_partner_id::text,true),set_config('freightctl.actor_id',NEW.admin_id::text,true);
 INSERT INTO public.partners(tenant_id,partner_id) VALUES(NEW.tenant_id,NEW.target_partner_id);
 INSERT INTO public.credentials(tenant_id,partner_id,actor_id,token_hash,permissions,namespace_root,account_label) VALUES(NEW.tenant_id,NEW.target_partner_id,NEW.admin_id,d->>'credential_sha256',p,'/',d->>'admin_label');
 INSERT INTO public.events(tenant_id,partner_id,event_id,actor_id,kind,resource_id,payload) VALUES(NEW.tenant_id,NEW.target_partner_id,NEW.enrollment_event_id,NEW.admin_id,'PartnerAdministratorEnrolled',NEW.admin_id,jsonb_build_object('control_partner_id',NEW.partner_id,'manager_actor_id',NEW.actor_id,'registration_event_id',NEW.event_id,'permissions',p,'namespace_root','/','authority_revision',1));
 PERFORM set_config('freightctl.partner_id',control_partner,true),set_config('freightctl.actor_id',manager,true);
 RETURN NEW;
END $$;
ALTER FUNCTION freightctl_project_partner() OWNER TO freightctl_partners_writer;
REVOKE ALL ON FUNCTION freightctl_project_partner() FROM PUBLIC;
CREATE TRIGGER partner_projection BEFORE INSERT OR UPDATE OR DELETE ON partner_registrations FOR EACH ROW EXECUTE FUNCTION freightctl_project_partner();
CREATE FUNCTION freightctl_partner_writer_safe() RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT EXISTS(SELECT 1 FROM pg_roles r JOIN pg_proc f ON f.oid='public.freightctl_project_partner()'::regprocedure AND f.proowner=r.oid
 WHERE r.rolname='freightctl_partners_writer' AND NOT(r.rolcanlogin OR r.rolinherit OR r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication)
 AND f.prosecdef AND 'row_security=on'=ANY(f.proconfig) AND EXISTS(SELECT 1 FROM unnest(f.proconfig)c WHERE replace(c,' ','')='search_path=pg_catalog,public,pg_temp')
 AND NOT has_schema_privilege(r.oid,'public','CREATE') AND NOT EXISTS(SELECT 1 FROM pg_auth_members m WHERE m.member=r.oid OR m.roleid=r.oid)
 AND NOT EXISTS(SELECT 1 FROM pg_class c WHERE c.relnamespace='public'::regnamespace AND c.relowner=r.oid))
$$;
REVOKE ALL ON FUNCTION freightctl_tenant_admin_guard(),freightctl_tenant_admin_receipt_guard() FROM PUBLIC;
