-- A test record and its ordinary run/intents are committed before contact.
CREATE TABLE onboarding_tests (
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,actor_id uuid NOT NULL,test_id uuid NOT NULL,run_id uuid NOT NULL,
 plan_id uuid NOT NULL,plan_version integer NOT NULL,
 definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object' AND octet_length(definition::text)<=12288),
 definition_hash text NOT NULL CHECK(definition_hash ~ '^[0-9a-f]{64}$'),
 created_at timestamptz NOT NULL,created_event_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,test_id),CHECK(test_id=run_id),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,plan_id,plan_version) REFERENCES onboarding_plans(tenant_id,partner_id,plan_id,version),
 FOREIGN KEY(tenant_id,partner_id,run_id) REFERENCES workflow_runs(tenant_id,partner_id,run_id),
 FOREIGN KEY(tenant_id,partner_id,created_event_id) REFERENCES events(tenant_id,partner_id,event_id)
);
CREATE INDEX onboarding_tests_history ON onboarding_tests(tenant_id,partner_id,actor_id,plan_id,test_id);
ALTER TABLE onboarding_tests ENABLE ROW LEVEL SECURITY;
ALTER TABLE onboarding_tests FORCE ROW LEVEL SECURITY;
-- Workers must see their immutable link even while management permissions are
-- being revoked. Ordinary current credential/authority checks still gate work.
CREATE POLICY scope ON onboarding_tests USING(
 tenant_id=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND partner_id=nullif(current_setting('freightctl.partner_id',true),'')::uuid
 AND actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid)
 WITH CHECK(tenant_id=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND partner_id=nullif(current_setting('freightctl.partner_id',true),'')::uuid
 AND actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid AND freightctl_onboarding_manager(tenant_id,partner_id));
REVOKE ALL ON onboarding_tests FROM PUBLIC;
GRANT SELECT,INSERT ON onboarding_tests TO freightctl_runtime;

CREATE FUNCTION freightctl_onboarding_test_run_current(t uuid,p uuid,a uuid,r uuid,authority bigint,root text) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT NOT EXISTS(SELECT 1 FROM onboarding_tests x WHERE (x.tenant_id,x.partner_id,x.actor_id,x.run_id)=(t,p,a,r))
 OR EXISTS(SELECT 1 FROM onboarding_tests x JOIN onboarding_probes probe ON (probe.tenant_id,probe.partner_id,probe.actor_id,probe.probe_id)=(x.tenant_id,x.partner_id,x.actor_id,(x.definition->'probe'->>'id')::uuid)
 WHERE (x.tenant_id,x.partner_id,x.actor_id,x.run_id)=(t,p,a,r)
 AND x.definition->>'authority_revision'=authority::text AND x.definition->>'namespace_root'=root
 AND probe.state='succeeded' AND probe.revision::text=x.definition->'probe'->>'revision' AND probe.definition_hash=x.definition->'probe'->>'hash'
 AND probe.definition->'plan'=x.definition->'plan' AND probe.definition->>'requirement_id'=x.definition->>'requirement_id' AND probe.definition->'connection'=x.definition->'connection'
 AND freightctl_onboarding_probe_current(t,p,a,probe.definition))
$$;
CREATE FUNCTION freightctl_onboarding_test_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE e jsonb;d jsonb;k text;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'onboarding test lineage is immutable' USING ERRCODE='23514';END IF;
 d:=NEW.definition;
 SELECT payload INTO e FROM events WHERE (tenant_id,partner_id,actor_id,event_id,resource_id,kind)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.created_event_id,NEW.test_id,'OnboardingTestRecorded');
 IF e IS NULL OR e->>'id' IS DISTINCT FROM NEW.test_id::text OR e->>'run_id' IS DISTINCT FROM NEW.run_id::text OR e->>'author_id' IS DISTINCT FROM NEW.actor_id::text OR e->'definition' IS DISTINCT FROM d OR e->>'definition_hash' IS DISTINCT FROM NEW.definition_hash OR (e->>'created_at')::timestamptz IS DISTINCT FROM NEW.created_at THEN RAISE EXCEPTION 'onboarding test requires exact journal record' USING ERRCODE='23514';END IF;
 IF ARRAY(SELECT jsonb_object_keys(d) ORDER BY 1) IS DISTINCT FROM ARRAY['authority_revision','connection','effect','file','namespace_root','plan','probe','profile','required_receipt','requirement_id','schema_version','step_id','storage_id','workflow','workflow_revision']::text[]
 OR d->>'schema_version' IS DISTINCT FROM '1' OR d->>'profile' IS DISTINCT FROM 'single-sftp-test-v1' OR d->>'namespace_root' IS DISTINCT FROM '/' OR d->'plan'->>'id' IS DISTINCT FROM NEW.plan_id::text OR d->'plan'->>'version' IS DISTINCT FROM NEW.plan_version::text
 OR coalesce(d->>'required_receipt','') NOT IN ('transport','integrity','business') OR coalesce((d->>'authority_revision')::bigint,0)<1 THEN RAISE EXCEPTION 'invalid onboarding test definition' USING ERRCODE='23514';END IF;
 FOREACH k IN ARRAY ARRAY['plan','workflow','connection'] LOOP
  IF jsonb_typeof(d->k) IS DISTINCT FROM 'object' OR ARRAY(SELECT jsonb_object_keys(d->k) ORDER BY 1) IS DISTINCT FROM ARRAY['hash','id','version']::text[] OR coalesce(d->k->>'hash','') !~ '^[0-9a-f]{64}$' THEN RAISE EXCEPTION 'invalid test reference' USING ERRCODE='23514';END IF;
 END LOOP;
 IF jsonb_typeof(d->'probe') IS DISTINCT FROM 'object' OR ARRAY(SELECT jsonb_object_keys(d->'probe') ORDER BY 1) IS DISTINCT FROM ARRAY['hash','id','revision']::text[] OR coalesce(d->'probe'->>'hash','') !~ '^[0-9a-f]{64}$' THEN RAISE EXCEPTION 'invalid test probe' USING ERRCODE='23514';END IF;
 IF jsonb_typeof(d->'effect') IS DISTINCT FROM 'object'
 OR ARRAY(SELECT jsonb_object_keys((d->'effect')-'encryption') ORDER BY 1) IS DISTINCT FROM ARRAY['address','directory','filename','host_fingerprint','key_fingerprint','recipient_fingerprint','user']::text[] THEN RAISE EXCEPTION 'invalid test effect' USING ERRCODE='23514';END IF;
 FOREACH k IN ARRAY ARRAY['address','directory','filename','host_fingerprint','key_fingerprint','recipient_fingerprint','user'] LOOP
  IF jsonb_typeof(d->'effect'->k) IS DISTINCT FROM 'string' THEN RAISE EXCEPTION 'invalid test effect value' USING ERRCODE='23514';END IF;
 END LOOP;
 IF d->'effect' ? 'encryption' THEN
  IF jsonb_typeof(d->'effect'->'encryption') IS DISTINCT FROM 'object'
  OR ARRAY(SELECT jsonb_object_keys(d->'effect'->'encryption') ORDER BY 1) IS DISTINCT FROM ARRAY['key','profile']::text[]
  OR jsonb_typeof(d->'effect'->'encryption'->'key') IS DISTINCT FROM 'object'
  OR ARRAY(SELECT jsonb_object_keys(d->'effect'->'encryption'->'key') ORDER BY 1) IS DISTINCT FROM ARRAY['hash','id','version']::text[]
  OR coalesce(d->'effect'->>'recipient_fingerprint','') !~ '^([0-9a-f]{40}|[0-9a-f]{64})$' THEN RAISE EXCEPTION 'invalid test recipient' USING ERRCODE='23514';END IF;
 END IF;
 IF NOT EXISTS(SELECT 1 FROM workflow_runs r JOIN workflow_revisions w ON (w.tenant_id,w.partner_id,w.actor_id,w.workflow_id,w.version)=(r.tenant_id,r.partner_id,r.actor_id,r.workflow_id,r.workflow_version)
 JOIN workflow_steps s ON (s.tenant_id,s.partner_id,s.actor_id,s.run_id)=(r.tenant_id,r.partner_id,r.actor_id,r.run_id)
 JOIN delivery_intents intent ON (intent.tenant_id,intent.partner_id,intent.actor_id,intent.delivery_id)=(s.tenant_id,s.partner_id,s.actor_id,s.delivery_id)
 JOIN connection_revisions c ON (c.tenant_id,c.partner_id,c.actor_id,c.connection_id,c.version)=(s.tenant_id,s.partner_id,s.actor_id,s.connection_id,s.connection_version)
 WHERE (r.tenant_id,r.partner_id,r.actor_id,r.run_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.run_id)
 AND r.state='queued' AND r.revision=1 AND r.source=d->'file' AND r.storage_id::text=d->>'storage_id' AND r.namespace_root=d->>'namespace_root' AND r.authority_revision::text=d->>'authority_revision'
 AND w.workflow_id::text=d->'workflow'->>'id' AND w.version::text=d->'workflow'->>'version' AND w.definition_hash=d->'workflow'->>'hash' AND w.revision::text=d->>'workflow_revision' AND w.state='approved' AND w.approval_authority=r.authority_revision
 AND jsonb_array_length(w.definition->'steps')=1 AND s.step_id=d->>'step_id' AND s.ordinal=1 AND s.connection_id::text=d->'connection'->>'id' AND s.connection_version::text=d->'connection'->>'version' AND s.connection_hash=d->'connection'->>'hash'
 AND d->'effect'->>'address'=c.definition->'destination'->>'address' AND d->'effect'->>'user'=c.definition->'destination'->>'user' AND d->'effect'->>'directory'=c.definition->>'directory' AND d->'effect'->>'filename'=w.definition->'steps'->0->>'filename'
 AND d->'effect'->>'host_fingerprint'=c.definition->'destination'->'host'->>'Fingerprint' AND d->'effect'->>'key_fingerprint'=c.definition->'destination'->>'key_fingerprint'
 AND d->'effect'->'encryption' IS NOT DISTINCT FROM w.definition->'steps'->0->'encryption'
 AND ((NOT (d->'effect' ? 'encryption') AND d->'effect'->>'recipient_fingerprint'='') OR EXISTS(SELECT 1 FROM pgp_keys recipient WHERE (recipient.tenant_id,recipient.partner_id,recipient.key_id,recipient.version,recipient.definition_hash)=(NEW.tenant_id,NEW.partner_id,(d->'effect'->'encryption'->'key'->>'id')::uuid,(d->'effect'->'encryption'->'key'->>'version')::integer,d->'effect'->'encryption'->'key'->>'hash') AND recipient.definition->>'fingerprint'=d->'effect'->>'recipient_fingerprint'))
 AND intent.state='queued' AND intent.attempts=0 AND intent.lease_owner IS NULL) THEN RAISE EXCEPTION 'test must precede its exact ordinary run effects' USING ERRCODE='23514';END IF;
 IF NOT EXISTS(SELECT 1 FROM onboarding_probes probe JOIN onboarding_plans plan ON (plan.tenant_id,plan.partner_id,plan.plan_id,plan.version)=(probe.tenant_id,probe.partner_id,probe.plan_id,probe.plan_version)
 WHERE (probe.tenant_id,probe.partner_id,probe.actor_id,probe.probe_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,(d->'probe'->>'id')::uuid)
 AND probe.state='succeeded' AND probe.revision::text=d->'probe'->>'revision' AND probe.definition_hash=d->'probe'->>'hash' AND probe.definition->'plan'=d->'plan' AND probe.definition->'connection'=d->'connection' AND probe.requirement_id::text=d->>'requirement_id'
 AND freightctl_onboarding_probe_current(NEW.tenant_id,NEW.partner_id,NEW.actor_id,probe.definition)
 AND EXISTS(SELECT 1 FROM jsonb_array_elements(plan.definition->'requirements') req WHERE req->>'id'=d->>'requirement_id' AND req->>'required_receipt'=d->>'required_receipt')) THEN RAISE EXCEPTION 'test requires exact successful current probe and requirement' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER onboarding_test_guard BEFORE INSERT OR UPDATE OR DELETE ON onboarding_tests FOR EACH ROW EXECUTE FUNCTION freightctl_onboarding_test_guard();
CREATE FUNCTION freightctl_onboarding_test_effect_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.definition ? 'workflow_binding' AND NEW.state IN ('staging','publishing','succeeded') AND NOT freightctl_onboarding_test_run_current(NEW.tenant_id,NEW.partner_id,NEW.actor_id,(NEW.definition->'workflow_binding'->>'run_id')::uuid,(NEW.definition->>'authority_revision')::bigint,NEW.definition->>'namespace_root') THEN RAISE EXCEPTION 'onboarding test bindings changed' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER onboarding_test_effect_guard BEFORE INSERT OR UPDATE ON delivery_intents FOR EACH ROW EXECUTE FUNCTION freightctl_onboarding_test_effect_guard();
REVOKE ALL ON FUNCTION freightctl_onboarding_test_guard(),freightctl_onboarding_test_effect_guard() FROM PUBLIC;
