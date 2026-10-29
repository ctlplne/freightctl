CREATE TABLE onboarding_plans(
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,plan_id uuid NOT NULL,version integer NOT NULL CHECK(version>0),
 definition_hash text NOT NULL CHECK(definition_hash ~ '^[0-9a-f]{64}$'),
 definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object' AND octet_length(definition::text)<=32768),
 actor_id uuid NOT NULL,event_id uuid NOT NULL,created_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,plan_id,version),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,event_id) REFERENCES events(tenant_id,partner_id,event_id)
);
CREATE TABLE onboarding_commands(
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,actor_id uuid NOT NULL,
 request_key text NOT NULL CHECK(request_key ~ '^[A-Za-z0-9._:-]{1,128}$'),
 request_hash text NOT NULL CHECK(request_hash ~ '^[0-9a-f]{64}$'),plan_id uuid NOT NULL,version integer NOT NULL,
 result jsonb NOT NULL CHECK(octet_length(result::text)<=32768),event_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,actor_id,request_key),
 FOREIGN KEY(tenant_id,partner_id,plan_id,version) REFERENCES onboarding_plans(tenant_id,partner_id,plan_id,version),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,event_id) REFERENCES events(tenant_id,partner_id,event_id)
);
CREATE FUNCTION freightctl_onboarding_manager(t uuid,p uuid) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT t=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND p=nullif(current_setting('freightctl.partner_id',true),'')::uuid
 AND EXISTS(SELECT 1 FROM public.credentials c WHERE c.tenant_id=t AND c.partner_id=p
 AND c.actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid AND c.namespace_root='/'
 AND c.permissions @> ARRAY['admin','accounts_manage']::text[] AND c.revoked_at IS NULL AND (c.expires_at IS NULL OR c.expires_at>clock_timestamp()))
$$;
ALTER TABLE onboarding_plans ENABLE ROW LEVEL SECURITY;
ALTER TABLE onboarding_plans FORCE ROW LEVEL SECURITY;
ALTER TABLE onboarding_commands ENABLE ROW LEVEL SECURITY;
ALTER TABLE onboarding_commands FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON onboarding_plans USING(tenant_id=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND partner_id=nullif(current_setting('freightctl.partner_id',true),'')::uuid AND freightctl_onboarding_manager(tenant_id,partner_id))
 WITH CHECK(freightctl_onboarding_manager(tenant_id,partner_id) AND actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid);
CREATE POLICY scope ON onboarding_commands USING(tenant_id=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND partner_id=nullif(current_setting('freightctl.partner_id',true),'')::uuid AND freightctl_onboarding_manager(tenant_id,partner_id) AND actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid)
 WITH CHECK(freightctl_onboarding_manager(tenant_id,partner_id) AND actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid);
REVOKE ALL ON onboarding_plans,onboarding_commands FROM PUBLIC;
GRANT SELECT,INSERT ON onboarding_plans,onboarding_commands TO freightctl_runtime;
CREATE FUNCTION freightctl_onboarding_plan_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE e events;maximum integer;d jsonb;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'onboarding plan versions are immutable' USING ERRCODE='23514';END IF;
 IF NOT freightctl_onboarding_manager(NEW.tenant_id,NEW.partner_id) THEN RAISE EXCEPTION 'onboarding requires partner account authority' USING ERRCODE='42501';END IF;
 SELECT * INTO e FROM events WHERE (tenant_id,partner_id,event_id,actor_id,kind,resource_id)=(NEW.tenant_id,NEW.partner_id,NEW.event_id,NEW.actor_id,'OnboardingPlanRecorded',NEW.plan_id);
 d:=NEW.definition;
 IF e.payload->>'id' IS DISTINCT FROM NEW.plan_id::text OR e.payload->>'version' IS DISTINCT FROM NEW.version::text OR e.payload->>'definition_hash' IS DISTINCT FROM NEW.definition_hash OR e.payload->'definition' IS DISTINCT FROM d OR e.payload->>'author_id' IS DISTINCT FROM NEW.actor_id::text OR e.payload->>'event_id' IS DISTINCT FROM NEW.event_id::text OR e.payload->>'state' IS DISTINCT FROM 'draft' OR e.payload->>'name' IS DISTINCT FROM d->>'name' OR (e.payload->>'created_at')::timestamptz IS DISTINCT FROM NEW.created_at OR NEW.created_at IS DISTINCT FROM e.happened_at THEN RAISE EXCEPTION 'onboarding version requires exact event' USING ERRCODE='23514';END IF;
 IF ARRAY(SELECT jsonb_object_keys(d) ORDER BY 1) IS DISTINCT FROM ARRAY['contacts','name','requirements','schema_version']::text[] OR d->>'schema_version' IS DISTINCT FROM '1' OR jsonb_typeof(d->'name') IS DISTINCT FROM 'string' OR octet_length(d->>'name') NOT BETWEEN 1 AND 128 OR jsonb_typeof(d->'contacts') IS DISTINCT FROM 'array' OR jsonb_typeof(d->'requirements') IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'invalid onboarding definition' USING ERRCODE='23514';END IF;
 IF jsonb_array_length(d->'contacts') NOT BETWEEN 1 AND 64 OR jsonb_array_length(d->'requirements') NOT BETWEEN 1 AND 64 THEN RAISE EXCEPTION 'onboarding document bounds' USING ERRCODE='23514';END IF;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(d->'contacts') c WHERE jsonb_typeof(c) IS DISTINCT FROM 'object' OR ARRAY(SELECT jsonb_object_keys(c) ORDER BY 1) IS DISTINCT FROM ARRAY['email','id','name','phone','role']::text[] OR c->>'id' !~ '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$' OR jsonb_typeof(c->'name') IS DISTINCT FROM 'string' OR jsonb_typeof(c->'role') IS DISTINCT FROM 'string' OR jsonb_typeof(c->'email') IS DISTINCT FROM 'string' OR jsonb_typeof(c->'phone') IS DISTINCT FROM 'string' OR octet_length(c->>'name') NOT BETWEEN 1 AND 128 OR octet_length(c->>'role') NOT BETWEEN 1 AND 64 OR octet_length(c->>'email') NOT BETWEEN 1 AND 254 OR octet_length(c->>'phone')>64)
 OR (SELECT count(*) FROM jsonb_array_elements(d->'contacts'))<>(SELECT count(DISTINCT c->>'id') FROM jsonb_array_elements(d->'contacts') c) THEN RAISE EXCEPTION 'invalid onboarding contacts' USING ERRCODE='23514';END IF;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(d->'requirements') r WHERE jsonb_typeof(r) IS DISTINCT FROM 'object' OR ARRAY(SELECT jsonb_object_keys(r) ORDER BY 1) IS DISTINCT FROM ARRAY['contact_id','direction','id','name','notes','protocol','receipt_contract','required_receipt']::text[] OR r->>'id' !~ '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$' OR jsonb_typeof(r->'name') IS DISTINCT FROM 'string' OR octet_length(r->>'name') NOT BETWEEN 1 AND 128 OR coalesce(r->>'direction','') NOT IN ('send','receive') OR coalesce(r->>'protocol','') NOT IN ('sftp','https','ftps-explicit','ftps-implicit','webdav','as1','as2','as3','as4','oftp2','pesit','smtp','queue','other') OR coalesce(r->>'required_receipt','') NOT IN ('transport','integrity','business') OR jsonb_typeof(r->'notes') IS DISTINCT FROM 'string' OR octet_length(r->>'notes')>2048 OR jsonb_typeof(r->'receipt_contract') IS DISTINCT FROM 'string' OR octet_length(r->>'receipt_contract')>512 OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(d->'contacts') c WHERE c->>'id'=r->>'contact_id'))
 OR (SELECT count(*) FROM jsonb_array_elements(d->'requirements'))<>(SELECT count(DISTINCT r->>'id') FROM jsonb_array_elements(d->'requirements') r) THEN RAISE EXCEPTION 'invalid onboarding requirements' USING ERRCODE='23514';END IF;
 SELECT coalesce(max(version),0) INTO maximum FROM onboarding_plans WHERE tenant_id=NEW.tenant_id AND partner_id=NEW.partner_id AND plan_id=NEW.plan_id;
 IF NEW.version<>maximum+1 THEN RAISE EXCEPTION 'onboarding version must be contiguous' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER onboarding_plan_guard BEFORE INSERT OR UPDATE OR DELETE ON onboarding_plans FOR EACH ROW EXECUTE FUNCTION freightctl_onboarding_plan_guard();
CREATE FUNCTION freightctl_onboarding_command_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE e events;p onboarding_plans;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'onboarding receipts are immutable' USING ERRCODE='23514';END IF;
 SELECT * INTO e FROM events WHERE (tenant_id,partner_id,event_id,actor_id,resource_id,kind)=(NEW.tenant_id,NEW.partner_id,NEW.event_id,NEW.actor_id,NEW.plan_id,'OnboardingCommandCompleted');
 SELECT * INTO p FROM onboarding_plans WHERE (tenant_id,partner_id,plan_id,version)=(NEW.tenant_id,NEW.partner_id,NEW.plan_id,NEW.version);
 IF e.payload->>'request_key' IS DISTINCT FROM NEW.request_key OR e.payload->>'request_hash' IS DISTINCT FROM NEW.request_hash OR e.payload->'result' IS DISTINCT FROM NEW.result OR NEW.result->>'id' IS DISTINCT FROM p.plan_id::text OR NEW.result->>'version' IS DISTINCT FROM p.version::text OR NEW.result->>'definition_hash' IS DISTINCT FROM p.definition_hash OR NEW.result->'definition' IS DISTINCT FROM p.definition OR NEW.result->>'event_id' IS DISTINCT FROM p.event_id::text OR NEW.result->>'author_id' IS DISTINCT FROM p.actor_id::text OR NEW.result->>'state' IS DISTINCT FROM 'draft' OR NEW.result->>'name' IS DISTINCT FROM p.definition->>'name' OR (NEW.result->>'created_at')::timestamptz IS DISTINCT FROM p.created_at THEN RAISE EXCEPTION 'onboarding receipt requires exact event and version' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER onboarding_command_guard BEFORE INSERT OR UPDATE OR DELETE ON onboarding_commands FOR EACH ROW EXECUTE FUNCTION freightctl_onboarding_command_guard();
REVOKE ALL ON FUNCTION freightctl_onboarding_plan_guard(),freightctl_onboarding_command_guard() FROM PUBLIC;
