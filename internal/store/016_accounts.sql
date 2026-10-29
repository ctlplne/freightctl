-- The ordinary runtime keeps SELECT-only credential-table access. A NOLOGIN,
-- non-owner, non-BYPASSRLS role owns only the narrow projection trigger below.
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='freightctl_accounts_writer') THEN
  BEGIN CREATE ROLE freightctl_accounts_writer NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL;END;
 END IF;
 IF EXISTS(SELECT 1 FROM pg_roles r WHERE r.rolname='freightctl_accounts_writer' AND
  (r.rolcanlogin OR r.rolinherit OR r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR
   EXISTS(SELECT 1 FROM pg_auth_members m WHERE m.member=r.oid OR m.roleid=r.oid))) THEN
  RAISE EXCEPTION 'account writer must be an isolated non-login role';
 END IF;
END $$;

ALTER TABLE credentials ADD COLUMN account_label text NOT NULL DEFAULT '' CHECK(octet_length(account_label)<=128 AND account_label !~ '[[:cntrl:]]');
ALTER TABLE credentials ADD COLUMN account_revision bigint NOT NULL DEFAULT 1 CHECK(account_revision>0);
ALTER TABLE credentials ADD COLUMN expires_at timestamptz;
ALTER TABLE credentials ADD COLUMN account_event_id uuid;
ALTER TABLE credentials ADD FOREIGN KEY(tenant_id,partner_id,account_event_id) REFERENCES events(tenant_id,partner_id,event_id);
ALTER TABLE credentials DROP CONSTRAINT credential_permissions_valid;
ALTER TABLE credentials ADD CONSTRAINT credential_permissions_valid CHECK(cardinality(permissions)<=21 AND permissions <@ ARRAY['read','write','list','manage_paths','inspect','audit_read','admin','connections_manage','deliver','workflow_manage','workflow_approve','workflow_execute','ai_manage','ai_use','ai_disclose','intake_manage','check_run','check_release','pgp_manage','scanner_manage','accounts_manage']::text[]);
ALTER TABLE credentials ALTER COLUMN permissions SET DEFAULT ARRAY['read','write','list','manage_paths','inspect','audit_read','admin','connections_manage','deliver','workflow_manage','workflow_approve','workflow_execute','ai_manage','ai_use','ai_disclose','intake_manage','check_run','check_release','pgp_manage','scanner_manage','accounts_manage']::text[];
CREATE INDEX account_listing ON credentials(tenant_id,partner_id,actor_id);
CREATE OR REPLACE FUNCTION freightctl_credential_revision() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (ARRAY(SELECT unnest(NEW.permissions) ORDER BY 1),NEW.namespace_root,NEW.revoked_at,NEW.token_hash,NEW.expires_at)
  IS DISTINCT FROM (ARRAY(SELECT unnest(OLD.permissions) ORDER BY 1),OLD.namespace_root,OLD.revoked_at,OLD.token_hash,OLD.expires_at) THEN
  NEW.authority_revision:=OLD.authority_revision+1;
 ELSIF NEW.authority_revision<>OLD.authority_revision THEN
  RAISE EXCEPTION 'authority revision cannot be assigned independently' USING ERRCODE='23514';
 END IF;
 NEW.account_revision:=OLD.account_revision+1;
 RETURN NEW;
END $$;

CREATE TABLE account_revisions(
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,manager_actor_id uuid NOT NULL,account_id uuid NOT NULL,
 revision bigint NOT NULL CHECK(revision>0),authority_revision bigint NOT NULL CHECK(authority_revision>0),
 operation text NOT NULL CHECK(operation IN ('create','update','rotate','revoke')),
 request_key text NOT NULL CHECK(request_key ~ '^[A-Za-z0-9._:-]{1,128}$'),request_hash text NOT NULL CHECK(request_hash ~ '^[0-9a-f]{64}$'),
 definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object' AND octet_length(definition::text)<=8192),event_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,account_id,revision),
 FOREIGN KEY(tenant_id,partner_id,manager_actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,account_id) REFERENCES credentials(tenant_id,partner_id,actor_id) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(tenant_id,partner_id,event_id) REFERENCES events(tenant_id,partner_id,event_id)
);
CREATE TABLE account_commands(
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,actor_id uuid NOT NULL,
 request_key text NOT NULL CHECK(request_key ~ '^[A-Za-z0-9._:-]{1,128}$'),request_hash text NOT NULL CHECK(request_hash ~ '^[0-9a-f]{64}$'),
 account_id uuid NOT NULL,event_id uuid NOT NULL,result jsonb NOT NULL CHECK(octet_length(result::text)<=16384),
 PRIMARY KEY(tenant_id,partner_id,actor_id,request_key),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,account_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,event_id) REFERENCES events(tenant_id,partner_id,event_id)
);
DO $$ DECLARE t text;BEGIN
 FOREACH t IN ARRAY ARRAY['account_revisions','account_commands'] LOOP
  EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',t);EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('CREATE POLICY scope ON %I USING(tenant_id=nullif(current_setting(''freightctl.tenant_id'',true),'''')::uuid AND partner_id=nullif(current_setting(''freightctl.partner_id'',true),'''')::uuid) WITH CHECK(tenant_id=nullif(current_setting(''freightctl.tenant_id'',true),'''')::uuid AND partner_id=nullif(current_setting(''freightctl.partner_id'',true),'''')::uuid)',t);
 END LOOP;
END $$;
CREATE POLICY account_revision_actor ON account_revisions AS RESTRICTIVE USING(manager_actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid) WITH CHECK(manager_actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid);
CREATE POLICY account_command_actor ON account_commands AS RESTRICTIVE USING(actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid) WITH CHECK(actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid);
GRANT SELECT,INSERT ON account_revisions,account_commands TO freightctl_runtime;

CREATE FUNCTION freightctl_account_manager(t uuid,p uuid) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT t=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND p=nullif(current_setting('freightctl.partner_id',true),'')::uuid AND EXISTS(
 SELECT 1 FROM public.credentials c WHERE (c.tenant_id,c.partner_id,c.actor_id)=(t,p,nullif(current_setting('freightctl.actor_id',true),'')::uuid)
 AND c.namespace_root='/' AND c.permissions @> ARRAY['admin','accounts_manage']::text[] AND c.revoked_at IS NULL AND (c.expires_at IS NULL OR c.expires_at>clock_timestamp()))
$$;

-- Existing runtime policies are unchanged for that role. The isolated writer
-- gets only manager-scoped access for revoking this command's target sessions.
ALTER POLICY browser_session_reader ON browser_sessions TO freightctl_runtime;
ALTER POLICY browser_session_writer ON browser_sessions TO freightctl_runtime;
ALTER POLICY browser_session_update ON browser_sessions TO freightctl_runtime;
CREATE POLICY account_session_writer ON browser_sessions AS RESTRICTIVE TO freightctl_accounts_writer
 USING(freightctl_account_manager(tenant_id,partner_id)) WITH CHECK(freightctl_account_manager(tenant_id,partner_id));
CREATE OR REPLACE FUNCTION freightctl_browser_session_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE p jsonb;e events;active_count integer;managed boolean;
BEGIN
 SELECT * INTO e FROM public.events WHERE (tenant_id,partner_id,event_id)=(NEW.tenant_id,NEW.partner_id,NEW.changed_event_id)
 AND actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid AND resource_id=NEW.session_id AND kind='BrowserSessionChanged';p:=e.payload;
 managed:=TG_OP='UPDATE' AND current_user='freightctl_accounts_writer' AND freightctl_account_manager(NEW.tenant_id,NEW.partner_id) AND EXISTS(
  SELECT 1 FROM public.account_revisions a WHERE (a.tenant_id,a.partner_id,a.account_id,a.manager_actor_id,a.event_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,e.actor_id,(p->>'account_change_event_id')::uuid)
  AND a.authority_revision>NEW.authority_revision);
 IF p IS NULL OR (e.actor_id IS DISTINCT FROM NEW.actor_id AND NOT coalesce(managed,false)) OR p->>'id' IS DISTINCT FROM NEW.session_id::text OR p->>'secret_sha256' IS DISTINCT FROM NEW.secret_hash OR p->>'credential_sha256' IS DISTINCT FROM NEW.credential_hash OR p->>'request_key' IS DISTINCT FROM NEW.request_key OR p->>'namespace_root' IS DISTINCT FROM NEW.namespace_root OR p->>'authority_revision' IS DISTINCT FROM NEW.authority_revision::text OR p->>'lifetime_seconds' IS DISTINCT FROM NEW.lifetime_seconds::text OR (p->>'expires_at')::timestamptz IS DISTINCT FROM NEW.expires_at OR p->>'state' IS DISTINCT FROM NEW.state OR p->>'revision' IS DISTINCT FROM NEW.revision::text THEN RAISE EXCEPTION 'browser session requires exact event proof' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN
  PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id::text||':'||NEW.partner_id::text||':'||NEW.actor_id::text||':browser-sessions',0));
  SELECT count(*) INTO active_count FROM public.browser_sessions WHERE (tenant_id,partner_id,actor_id,state)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,'active') AND expires_at>clock_timestamp();
  IF NEW.state<>'active' OR NEW.revision<>1 OR NEW.expires_at<=clock_timestamp() OR NEW.expires_at>e.happened_at+make_interval(secs=>NEW.lifetime_seconds) OR active_count>=8 OR NOT EXISTS(SELECT 1 FROM public.credentials c WHERE (c.tenant_id,c.partner_id,c.actor_id,c.namespace_root,c.authority_revision,c.token_hash)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.namespace_root,NEW.authority_revision,NEW.credential_hash) AND c.revoked_at IS NULL AND (c.expires_at IS NULL OR c.expires_at>=NEW.expires_at)) THEN RAISE EXCEPTION 'invalid browser session admission' USING ERRCODE='23514';END IF;
 ELSE
  IF (NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.session_id,NEW.secret_hash,NEW.credential_hash,NEW.request_key,NEW.namespace_root,NEW.authority_revision,NEW.lifetime_seconds,NEW.expires_at) IS DISTINCT FROM (OLD.tenant_id,OLD.partner_id,OLD.actor_id,OLD.session_id,OLD.secret_hash,OLD.credential_hash,OLD.request_key,OLD.namespace_root,OLD.authority_revision,OLD.lifetime_seconds,OLD.expires_at) OR OLD.state<>'active' OR NEW.state<>'revoked' OR NEW.revision<>OLD.revision+1 THEN RAISE EXCEPTION 'browser session authority and expiry are immutable' USING ERRCODE='23514';END IF;
 END IF;RETURN NEW;
END $$;

CREATE FUNCTION freightctl_project_account() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog,public,pg_temp SET row_security=on AS $$
DECLARE e public.events;m public.credentials;prior public.credentials;d jsonb;p text[];x timestamptz;revoked boolean;actual_auth bigint;actual_revision bigint;s public.browser_sessions;sid uuid;count_sessions integer;
BEGIN
 IF NOT public.freightctl_account_writer_safe() OR NOT public.freightctl_account_manager(NEW.tenant_id,NEW.partner_id) OR NEW.manager_actor_id<>nullif(current_setting('freightctl.actor_id',true),'')::uuid OR NEW.account_id=NEW.manager_actor_id THEN RAISE EXCEPTION 'account command requires a scoped manager and another target' USING ERRCODE='42501';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id::text||':'||NEW.partner_id::text||':accounts',0));
 SELECT * INTO m FROM public.credentials WHERE (tenant_id,partner_id,actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.manager_actor_id) FOR SHARE;
 SELECT * INTO e FROM public.events WHERE (tenant_id,partner_id,event_id,actor_id,resource_id,kind)=(NEW.tenant_id,NEW.partner_id,NEW.event_id,NEW.manager_actor_id,NEW.account_id,'AccountChanged');d:=NEW.definition;
 IF e.payload->>'account_id' IS DISTINCT FROM NEW.account_id::text OR e.payload->>'revision' IS DISTINCT FROM NEW.revision::text OR e.payload->>'authority_revision' IS DISTINCT FROM NEW.authority_revision::text OR e.payload->>'operation' IS DISTINCT FROM NEW.operation OR e.payload->>'request_key' IS DISTINCT FROM NEW.request_key OR e.payload->>'request_hash' IS DISTINCT FROM NEW.request_hash OR e.payload->'definition' IS DISTINCT FROM d THEN RAISE EXCEPTION 'account revision requires its exact journal event' USING ERRCODE='23514';END IF;
 IF ARRAY(SELECT jsonb_object_keys(d) ORDER BY 1)<>ARRAY['credential_sha256','expires_at','label','namespace_root','permissions','revoked']::text[] OR jsonb_typeof(d->'permissions') IS DISTINCT FROM 'array' OR jsonb_typeof(d->'revoked') IS DISTINCT FROM 'boolean' OR jsonb_typeof(d->'credential_sha256') IS DISTINCT FROM 'string' OR d->>'credential_sha256' !~ '^[0-9a-f]{64}$' OR jsonb_typeof(d->'label') IS DISTINCT FROM 'string' OR jsonb_typeof(d->'namespace_root') IS DISTINCT FROM 'string' OR jsonb_typeof(d->'expires_at') NOT IN ('string','null') OR octet_length(d->>'label')>128 OR d->>'label' ~ '[[:cntrl:]]' THEN RAISE EXCEPTION 'invalid account definition' USING ERRCODE='23514';END IF;
 p:=ARRAY(SELECT jsonb_array_elements_text(d->'permissions'));x:=(d->>'expires_at')::timestamptz;revoked:=(d->>'revoked')::boolean;
 IF cardinality(p)>21 OR p<>ARRAY(SELECT DISTINCT unnest(p) ORDER BY 1) OR NOT(p<@m.permissions) THEN RAISE EXCEPTION 'account grant exceeds manager authority' USING ERRCODE='42501';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id::text||':'||NEW.partner_id::text||':'||NEW.account_id::text||':browser-sessions',0));
 SELECT * INTO prior FROM public.credentials WHERE (tenant_id,partner_id,actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.account_id) FOR UPDATE;
 IF prior.actor_id IS NULL THEN
  IF (SELECT count(*) FROM public.credentials)>=10000 THEN RAISE EXCEPTION 'account admission bound reached' USING ERRCODE='23514';END IF;
  IF NEW.operation<>'create' OR NEW.revision<>1 OR NEW.authority_revision<>1 OR revoked THEN RAISE EXCEPTION 'invalid account creation' USING ERRCODE='23514';END IF;
 ELSE
  IF NEW.operation='create' OR NEW.revision<>prior.account_revision+1 OR prior.revoked_at IS NOT NULL OR NOT(prior.permissions<@m.permissions) THEN RAISE EXCEPTION 'invalid account transition or target authority' USING ERRCODE='23514';END IF;
  IF NEW.operation='rotate' AND (d->>'credential_sha256'=prior.token_hash OR (d->>'label',p,d->>'namespace_root',x,revoked) IS DISTINCT FROM (prior.account_label,ARRAY(SELECT unnest(prior.permissions) ORDER BY 1),prior.namespace_root,prior.expires_at,false)) THEN RAISE EXCEPTION 'rotation can change only credential proof' USING ERRCODE='23514';END IF;
  IF NEW.operation='revoke' AND ((d->>'credential_sha256',d->>'label',p,d->>'namespace_root',x,revoked) IS DISTINCT FROM (prior.token_hash,prior.account_label,ARRAY(SELECT unnest(prior.permissions) ORDER BY 1),prior.namespace_root,prior.expires_at,true)) THEN RAISE EXCEPTION 'revocation cannot change account policy' USING ERRCODE='23514';END IF;
  IF NEW.operation='update' AND (d->>'credential_sha256'<>prior.token_hash OR revoked) THEN RAISE EXCEPTION 'policy update cannot rotate or revoke implicitly' USING ERRCODE='23514';END IF;
 END IF;
 IF NEW.operation IN ('create','update') AND ((x IS NOT NULL AND x<=clock_timestamp()) OR (d->>'namespace_root'<>'/' AND NOT EXISTS(SELECT 1 FROM public.namespace_entries n WHERE (n.tenant_id,n.partner_id,n.path,n.kind,n.deleted)=(NEW.tenant_id,NEW.partner_id,d->>'namespace_root','dir',false)))) THEN RAISE EXCEPTION 'account requires future expiry and an existing virtual root' USING ERRCODE='23514';END IF;
 IF prior.actor_id IS NULL THEN
  INSERT INTO public.credentials(tenant_id,partner_id,actor_id,token_hash,permissions,namespace_root,account_label,expires_at,account_revision,authority_revision,account_event_id)
  VALUES(NEW.tenant_id,NEW.partner_id,NEW.account_id,d->>'credential_sha256',p,d->>'namespace_root',d->>'label',x,NEW.revision,NEW.authority_revision,NEW.event_id) RETURNING authority_revision,account_revision INTO actual_auth,actual_revision;
 ELSE
  UPDATE public.credentials SET token_hash=d->>'credential_sha256',permissions=p,namespace_root=d->>'namespace_root',account_label=d->>'label',expires_at=x,revoked_at=CASE WHEN revoked THEN e.happened_at ELSE NULL END,account_event_id=NEW.event_id
  WHERE (tenant_id,partner_id,actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.account_id) RETURNING authority_revision,account_revision INTO actual_auth,actual_revision;
 END IF;
 IF ARRAY(SELECT jsonb_object_keys(e.payload->'account') ORDER BY 1) IS DISTINCT FROM ARRAY['authority_revision','changed_event_id','expires_at','id','label','namespace_root','observed_at','permissions','revision','state']::text[]
 OR (e.payload->'account'->>'id',e.payload->'account'->>'label',e.payload->'account'->>'namespace_root',e.payload->'account'->>'revision',e.payload->'account'->>'authority_revision',e.payload->'account'->>'changed_event_id',e.payload->'account'->>'state') IS DISTINCT FROM (NEW.account_id::text,d->>'label',d->>'namespace_root',NEW.revision::text,NEW.authority_revision::text,NEW.event_id::text,CASE WHEN revoked THEN 'revoked' WHEN x<=e.happened_at THEN 'expired' ELSE 'active' END)
 OR e.payload->'account'->'permissions' IS DISTINCT FROM d->'permissions' OR (e.payload->'account'->>'expires_at')::timestamptz IS DISTINCT FROM x OR (e.payload->'account'->>'observed_at')::timestamptz IS DISTINCT FROM e.happened_at THEN RAISE EXCEPTION 'account result differs from its projection' USING ERRCODE='23514';END IF;
 IF actual_auth IS DISTINCT FROM NEW.authority_revision OR actual_revision IS DISTINCT FROM NEW.revision THEN RAISE EXCEPTION 'account authority projection differs' USING ERRCODE='23514';END IF;
 IF prior.actor_id IS NOT NULL AND actual_auth<>prior.authority_revision THEN
  count_sessions:=0;
  FOR s IN SELECT * FROM public.browser_sessions WHERE (tenant_id,partner_id,actor_id,state)=(NEW.tenant_id,NEW.partner_id,NEW.account_id,'active') AND expires_at>clock_timestamp() ORDER BY session_id LIMIT 9 FOR UPDATE LOOP
   count_sessions:=count_sessions+1;IF count_sessions>8 THEN RAISE EXCEPTION 'account session invalidation exceeds admission bound' USING ERRCODE='23514';END IF;
   sid:=gen_random_uuid();
   INSERT INTO public.events(tenant_id,partner_id,event_id,actor_id,kind,resource_id,payload) VALUES(NEW.tenant_id,NEW.partner_id,sid,NEW.manager_actor_id,'BrowserSessionChanged',s.session_id,
    jsonb_build_object('id',s.session_id,'secret_sha256',s.secret_hash,'credential_sha256',s.credential_hash,'request_key',s.request_key,'namespace_root',s.namespace_root,'authority_revision',s.authority_revision,'lifetime_seconds',s.lifetime_seconds,'expires_at',s.expires_at,'state','revoked','revision',s.revision+1,'account_change_event_id',NEW.event_id));
   UPDATE public.browser_sessions SET state='revoked',revision=s.revision+1,changed_event_id=sid WHERE (tenant_id,partner_id,session_id)=(s.tenant_id,s.partner_id,s.session_id);
  END LOOP;
 END IF;RETURN NEW;
END $$;
CREATE TRIGGER account_projection AFTER INSERT ON account_revisions FOR EACH ROW EXECUTE FUNCTION freightctl_project_account();

CREATE FUNCTION freightctl_account_writer_safe() RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT EXISTS(SELECT 1 FROM pg_roles r JOIN pg_proc f ON f.oid='public.freightctl_project_account()'::regprocedure AND f.proowner=r.oid
 WHERE r.rolname='freightctl_accounts_writer' AND NOT(r.rolcanlogin OR r.rolinherit OR r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication)
 AND f.prosecdef AND 'row_security=on'=ANY(f.proconfig) AND EXISTS(SELECT 1 FROM unnest(f.proconfig) c WHERE replace(c,' ','')='search_path=pg_catalog,public,pg_temp')
 AND NOT has_schema_privilege(r.oid,'public','CREATE') AND NOT EXISTS(SELECT 1 FROM pg_auth_members m WHERE m.member=r.oid OR m.roleid=r.oid)
 AND NOT EXISTS(SELECT 1 FROM pg_class c WHERE c.relnamespace='public'::regnamespace AND c.relowner=r.oid))
$$;

CREATE FUNCTION freightctl_account_receipt_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE e events;
BEGIN
 SELECT * INTO e FROM public.events WHERE (tenant_id,partner_id,event_id,actor_id,resource_id,kind)=(NEW.tenant_id,NEW.partner_id,NEW.event_id,NEW.actor_id,NEW.account_id,'AccountChanged');
 IF e.payload->>'request_key' IS DISTINCT FROM NEW.request_key OR e.payload->>'request_hash' IS DISTINCT FROM NEW.request_hash OR NEW.result IS DISTINCT FROM jsonb_build_object('account',e.payload->'account','replayed',false) OR NOT EXISTS(SELECT 1 FROM public.account_revisions a WHERE (a.tenant_id,a.partner_id,a.account_id,a.event_id,a.manager_actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.account_id,NEW.event_id,NEW.actor_id)) THEN RAISE EXCEPTION 'account receipt requires its exact event and projection' USING ERRCODE='23514';END IF;RETURN NEW;
END $$;
CREATE TRIGGER account_receipt BEFORE INSERT ON account_commands FOR EACH ROW EXECUTE FUNCTION freightctl_account_receipt_guard();
CREATE FUNCTION freightctl_account_event_complete() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM public.account_commands c JOIN public.account_revisions a ON (a.tenant_id,a.partner_id,a.event_id,a.manager_actor_id)=(c.tenant_id,c.partner_id,c.event_id,c.actor_id)
 WHERE (c.tenant_id,c.partner_id,c.event_id,c.actor_id,c.account_id)=(NEW.tenant_id,NEW.partner_id,NEW.event_id,NEW.actor_id,NEW.resource_id)) THEN RAISE EXCEPTION 'account event requires atomic projection and command receipt' USING ERRCODE='23514';END IF;RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER account_event_complete AFTER INSERT ON events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN(NEW.kind='AccountChanged') EXECUTE FUNCTION freightctl_account_event_complete();

GRANT USAGE ON SCHEMA public TO freightctl_accounts_writer;
GRANT SELECT ON credentials,events,namespace_entries,account_revisions,browser_sessions TO freightctl_accounts_writer;
GRANT INSERT,UPDATE ON credentials TO freightctl_accounts_writer;
GRANT INSERT ON events TO freightctl_accounts_writer;
GRANT UPDATE ON browser_sessions TO freightctl_accounts_writer;
-- Only the trigger may exercise the writer's rights; the runtime cannot SET ROLE.
GRANT CREATE ON SCHEMA public TO freightctl_accounts_writer;
ALTER FUNCTION freightctl_project_account() OWNER TO freightctl_accounts_writer;
REVOKE CREATE ON SCHEMA public FROM freightctl_accounts_writer;
REVOKE ALL ON FUNCTION freightctl_project_account(),freightctl_account_manager(uuid,uuid),freightctl_account_writer_safe(),freightctl_account_receipt_guard(),freightctl_account_event_complete() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION freightctl_account_manager(uuid,uuid),freightctl_account_writer_safe() TO freightctl_runtime,freightctl_accounts_writer;
