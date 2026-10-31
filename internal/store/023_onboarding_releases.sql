-- Approval and activation govern explicit production dispatches. Ordinary runs
-- and pre-contact test records retain their existing meanings.
CREATE TABLE onboarding_releases (
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,actor_id uuid NOT NULL,release_id uuid NOT NULL,
 plan_id uuid NOT NULL,plan_version integer NOT NULL,plan_hash text NOT NULL,
 definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object' AND octet_length(definition::text)<=32768),
 definition_hash text NOT NULL CHECK(definition_hash ~ '^[0-9a-f]{64}$'),
 state text NOT NULL CHECK(state IN ('proposed','approved','active','suspended','revoked')),
 revision bigint NOT NULL CHECK(revision>0),approved_revision bigint NOT NULL CHECK(approved_revision>=0),
 created_at timestamptz NOT NULL,changed_event_id uuid NOT NULL,storage_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,release_id),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,plan_id,plan_version) REFERENCES onboarding_plans(tenant_id,partner_id,plan_id,version),
 FOREIGN KEY(tenant_id,partner_id,changed_event_id) REFERENCES events(tenant_id,partner_id,event_id)
);
CREATE UNIQUE INDEX onboarding_one_active_release ON onboarding_releases(tenant_id,partner_id,actor_id,plan_id) WHERE state='active';
CREATE INDEX onboarding_release_history ON onboarding_releases(tenant_id,partner_id,actor_id,plan_id,release_id);
CREATE TABLE onboarding_dispatches (
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,actor_id uuid NOT NULL,run_id uuid NOT NULL,
 release_id uuid NOT NULL,release_revision bigint NOT NULL,requirement_id uuid NOT NULL,
 definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object' AND octet_length(definition::text)<=16384),
 definition_hash text NOT NULL CHECK(definition_hash ~ '^[0-9a-f]{64}$'),created_event_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,run_id),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,release_id) REFERENCES onboarding_releases(tenant_id,partner_id,release_id),
 FOREIGN KEY(tenant_id,partner_id,run_id) REFERENCES workflow_runs(tenant_id,partner_id,run_id),
 FOREIGN KEY(tenant_id,partner_id,created_event_id) REFERENCES events(tenant_id,partner_id,event_id)
);
CREATE INDEX onboarding_dispatch_history ON onboarding_dispatches(tenant_id,partner_id,actor_id,release_id,run_id);
ALTER TABLE onboarding_releases ENABLE ROW LEVEL SECURITY;ALTER TABLE onboarding_releases FORCE ROW LEVEL SECURITY;
ALTER TABLE onboarding_dispatches ENABLE ROW LEVEL SECURITY;ALTER TABLE onboarding_dispatches FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON onboarding_releases USING(tenant_id=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND partner_id=nullif(current_setting('freightctl.partner_id',true),'')::uuid AND actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid)
 WITH CHECK(tenant_id=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND partner_id=nullif(current_setting('freightctl.partner_id',true),'')::uuid AND actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid AND freightctl_onboarding_manager(tenant_id,partner_id));
CREATE POLICY scope ON onboarding_dispatches USING(tenant_id=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND partner_id=nullif(current_setting('freightctl.partner_id',true),'')::uuid AND actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid)
 WITH CHECK(tenant_id=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND partner_id=nullif(current_setting('freightctl.partner_id',true),'')::uuid AND actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid AND freightctl_onboarding_manager(tenant_id,partner_id));
REVOKE ALL ON onboarding_releases,onboarding_dispatches FROM PUBLIC;
GRANT SELECT,INSERT,UPDATE ON onboarding_releases TO freightctl_runtime;
GRANT SELECT,INSERT ON onboarding_dispatches TO freightctl_runtime;

CREATE FUNCTION freightctl_onboarding_release_current(t uuid,p uuid,a uuid,d jsonb) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT EXISTS(SELECT 1 FROM credentials c WHERE (c.tenant_id,c.partner_id,c.actor_id)=(t,p,a) AND c.revoked_at IS NULL AND (c.expires_at IS NULL OR c.expires_at>clock_timestamp()) AND c.authority_revision::text=d->>'authority_revision' AND c.namespace_root=d->>'namespace_root')
 AND EXISTS(SELECT 1 FROM onboarding_plans plan WHERE (plan.tenant_id,plan.partner_id,plan.plan_id,plan.version,plan.definition_hash)=(t,p,(d->'plan'->>'id')::uuid,(d->'plan'->>'version')::integer,d->'plan'->>'hash')
  AND NOT EXISTS(SELECT 1 FROM onboarding_plans newer WHERE (newer.tenant_id,newer.partner_id,newer.plan_id)=(plan.tenant_id,plan.partner_id,plan.plan_id) AND newer.version>plan.version)
  AND jsonb_array_length(plan.definition->'requirements')=jsonb_array_length(d->'proofs')
  AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(plan.definition->'requirements') req WHERE req->>'direction'<>'send' OR req->>'protocol'<>'sftp' OR req->>'required_receipt'='business' OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(d->'proofs') proof WHERE proof->>'requirement_id'=req->>'id')))
 AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(d->'proofs') proof WHERE NOT EXISTS(
  SELECT 1 FROM onboarding_tests test JOIN workflow_runs r ON (r.tenant_id,r.partner_id,r.actor_id,r.run_id)=(test.tenant_id,test.partner_id,test.actor_id,test.run_id)
  JOIN workflow_revisions w ON (w.tenant_id,w.partner_id,w.actor_id,w.workflow_id,w.version)=(r.tenant_id,r.partner_id,r.actor_id,r.workflow_id,r.workflow_version)
  JOIN workflow_steps step ON (step.tenant_id,step.partner_id,step.actor_id,step.run_id)=(r.tenant_id,r.partner_id,r.actor_id,r.run_id)
  JOIN delivery_intents delivery ON (delivery.tenant_id,delivery.partner_id,delivery.actor_id,delivery.delivery_id)=(step.tenant_id,step.partner_id,step.actor_id,step.delivery_id)
  WHERE (test.tenant_id,test.partner_id,test.actor_id,test.test_id,test.definition_hash)=(t,p,a,(proof->>'test_id')::uuid,proof->>'test_hash')
  AND test.definition->'plan'=d->'plan' AND test.definition->>'requirement_id'=proof->>'requirement_id' AND test.definition->>'storage_id'=d->>'storage_id' AND test.definition->>'authority_revision'=d->>'authority_revision' AND test.definition->>'namespace_root'=d->>'namespace_root'
  AND freightctl_onboarding_test_run_current(t,p,a,r.run_id,(d->>'authority_revision')::bigint,d->>'namespace_root')
  AND freightctl_file_available(t,p,r.file_id)
  AND r.state='succeeded' AND w.state='approved' AND w.definition_hash=r.workflow_hash AND w.revision::text=test.definition->>'workflow_revision' AND w.approval_authority=r.authority_revision
  AND delivery.delivery_id::text=proof->>'delivery_id' AND delivery.revision::text=proof->>'delivery_revision' AND delivery.state='succeeded'
  AND delivery.observation->>'code'='remote_file_integrity_observed' AND delivery.observation->>'business_acceptance'='unknown'
  AND delivery.observation->>'directory_power_loss_durability'='not established'
  AND (delivery.observation->>'file_fsync_acknowledged')::boolean IS DISTINCT FROM (delivery.observation->>'reconciled')::boolean
  AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(w.definition->'steps') planned LEFT JOIN pgp_keys k ON (k.tenant_id,k.partner_id,k.key_id,k.version)=(t,p,(planned->'encryption'->'key'->>'id')::uuid,(planned->'encryption'->'key'->>'version')::integer) WHERE planned ? 'encryption' AND (k.key_id IS NULL OR k.state<>'active' OR k.definition_hash IS DISTINCT FROM planned->'encryption'->'key'->>'hash' OR (k.valid_until IS NOT NULL AND k.valid_until<=clock_timestamp())))
 ))
$$;
CREATE FUNCTION freightctl_onboarding_release_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE e jsonb;d jsonb;proof jsonb;permissions text[];
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'onboarding releases cannot be deleted' USING ERRCODE='23514';END IF;
 d:=NEW.definition;
 SELECT payload INTO e FROM events WHERE (tenant_id,partner_id,actor_id,event_id,resource_id,kind)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.changed_event_id,NEW.release_id,'OnboardingReleaseChanged');
 IF e IS NULL OR e->>'id' IS DISTINCT FROM NEW.release_id::text OR e->>'author_id' IS DISTINCT FROM NEW.actor_id::text OR e->'definition' IS DISTINCT FROM d OR e->>'definition_hash' IS DISTINCT FROM NEW.definition_hash OR e->>'state' IS DISTINCT FROM NEW.state OR e->>'revision' IS DISTINCT FROM NEW.revision::text OR e->>'approved_revision' IS DISTINCT FROM NEW.approved_revision::text OR (e->>'created_at')::timestamptz IS DISTINCT FROM NEW.created_at OR e->'plan' IS DISTINCT FROM d->'plan' THEN RAISE EXCEPTION 'release requires exact immutable journal event' USING ERRCODE='23514';END IF;
 SELECT c.permissions INTO permissions FROM credentials c WHERE (c.tenant_id,c.partner_id,c.actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id) AND c.revoked_at IS NULL AND (c.expires_at IS NULL OR c.expires_at>clock_timestamp());
 IF NOT freightctl_onboarding_manager(NEW.tenant_id,NEW.partner_id) OR NOT coalesce(permissions @> ARRAY['connections_manage','read']::text[],false) THEN RAISE EXCEPTION 'release requires current onboarding authority' USING ERRCODE='42501';END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.state<>'proposed' OR NEW.revision<>1 OR NEW.approved_revision<>0 OR NOT permissions @> ARRAY['workflow_manage']::text[] THEN RAISE EXCEPTION 'release must begin as reviewed proposal' USING ERRCODE='23514';END IF;
  IF ARRAY(SELECT jsonb_object_keys(d) ORDER BY 1) IS DISTINCT FROM ARRAY['authority_revision','namespace_root','plan','profile','proofs','schema_version','storage_id']::text[] OR d->>'schema_version' IS DISTINCT FROM '1' OR d->>'profile' IS DISTINCT FROM 'sftp-outbound-production-v1' OR d->>'namespace_root' IS DISTINCT FROM '/' OR d->>'storage_id' IS DISTINCT FROM NEW.storage_id::text OR d->'plan' IS DISTINCT FROM jsonb_build_object('id',NEW.plan_id::text,'version',NEW.plan_version,'hash',NEW.plan_hash) OR jsonb_typeof(d->'proofs') IS DISTINCT FROM 'array' OR jsonb_array_length(d->'proofs') NOT BETWEEN 1 AND 64 THEN RAISE EXCEPTION 'invalid release definition' USING ERRCODE='23514';END IF;
  IF (SELECT count(DISTINCT q->>'requirement_id') FROM jsonb_array_elements(d->'proofs') q)<>jsonb_array_length(d->'proofs') OR (SELECT count(DISTINCT q->>'test_id') FROM jsonb_array_elements(d->'proofs') q)<>jsonb_array_length(d->'proofs') THEN RAISE EXCEPTION 'release must cover each requirement exactly once' USING ERRCODE='23514';END IF;
  FOR proof IN SELECT * FROM jsonb_array_elements(d->'proofs') LOOP
   IF ARRAY(SELECT jsonb_object_keys(proof) ORDER BY 1) IS DISTINCT FROM ARRAY['delivery_id','delivery_revision','receipt_hash','requirement_id','snapshot_hash','test_hash','test_id']::text[] OR coalesce(proof->>'receipt_hash','') !~ '^[a-f0-9]{64}$' OR coalesce(proof->>'snapshot_hash','') !~ '^[a-f0-9]{64}$' THEN RAISE EXCEPTION 'invalid release proof' USING ERRCODE='23514';END IF;
  END LOOP;
 ELSE
  IF (NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.release_id,NEW.plan_id,NEW.plan_version,NEW.plan_hash,NEW.definition,NEW.definition_hash,NEW.storage_id,NEW.created_at) IS DISTINCT FROM (OLD.tenant_id,OLD.partner_id,OLD.actor_id,OLD.release_id,OLD.plan_id,OLD.plan_version,OLD.plan_hash,OLD.definition,OLD.definition_hash,OLD.storage_id,OLD.created_at) OR NEW.revision<>OLD.revision+1 OR OLD.state='revoked' THEN RAISE EXCEPTION 'release definition is immutable and revision must advance' USING ERRCODE='23514';END IF;
  IF NOT ((OLD.state='proposed' AND NEW.state='approved') OR (OLD.state IN ('approved','suspended') AND NEW.state='active') OR (OLD.state='active' AND NEW.state='suspended') OR (NEW.state='revoked' AND OLD.state<>'revoked')) THEN RAISE EXCEPTION 'invalid release transition' USING ERRCODE='23514';END IF;
  IF NEW.state IN ('approved','revoked') AND NOT permissions @> ARRAY['workflow_approve']::text[] THEN RAISE EXCEPTION 'release requires approval permission' USING ERRCODE='42501';END IF;
  IF NEW.state IN ('active','suspended') AND NOT permissions @> ARRAY['workflow_execute','deliver']::text[] THEN RAISE EXCEPTION 'activation requires execution permission' USING ERRCODE='42501';END IF;
  IF NEW.approved_revision IS DISTINCT FROM (CASE WHEN NEW.state='approved' THEN NEW.revision ELSE OLD.approved_revision END) THEN RAISE EXCEPTION 'approval revision cannot be invented or rewritten' USING ERRCODE='23514';END IF;
 END IF;
 IF NEW.state IN ('proposed','approved','active') AND NOT freightctl_onboarding_release_current(NEW.tenant_id,NEW.partner_id,NEW.actor_id,d) THEN RAISE EXCEPTION 'release evidence or authority changed' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER onboarding_release_guard BEFORE INSERT OR UPDATE OR DELETE ON onboarding_releases FOR EACH ROW EXECUTE FUNCTION freightctl_onboarding_release_guard();
CREATE FUNCTION freightctl_onboarding_production_run_current(t uuid,p uuid,a uuid,r uuid,authority bigint,root text) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT NOT EXISTS(SELECT 1 FROM onboarding_dispatches x WHERE (x.tenant_id,x.partner_id,x.actor_id,x.run_id)=(t,p,a,r)) OR EXISTS(
 SELECT 1 FROM onboarding_dispatches x JOIN onboarding_releases release USING(tenant_id,partner_id,release_id)
 WHERE (x.tenant_id,x.partner_id,x.actor_id,x.run_id)=(t,p,a,r) AND release.actor_id=a AND release.state='active' AND release.revision=x.release_revision AND release.definition_hash=x.definition->'release'->>'hash'
 AND release.definition->>'authority_revision'=authority::text AND release.definition->>'namespace_root'=root AND freightctl_onboarding_release_current(t,p,a,release.definition))
$$;
CREATE FUNCTION freightctl_onboarding_run_current(t uuid,p uuid,a uuid,r uuid,authority bigint,root text) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT freightctl_onboarding_test_run_current(t,p,a,r,authority,root) AND freightctl_onboarding_production_run_current(t,p,a,r,authority,root)
$$;
CREATE FUNCTION freightctl_onboarding_dispatch_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE e jsonb;d jsonb;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'production dispatch lineage is immutable' USING ERRCODE='23514';END IF;
 d:=NEW.definition;
 SELECT payload INTO e FROM events WHERE (tenant_id,partner_id,actor_id,event_id,resource_id,kind)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.created_event_id,NEW.run_id,'OnboardingProductionQueued');
 IF e IS NULL OR e->>'id' IS DISTINCT FROM NEW.run_id::text OR e->>'author_id' IS DISTINCT FROM NEW.actor_id::text OR e->'definition' IS DISTINCT FROM d OR e->>'definition_hash' IS DISTINCT FROM NEW.definition_hash THEN RAISE EXCEPTION 'production dispatch requires exact journal record' USING ERRCODE='23514';END IF;
 IF ARRAY(SELECT jsonb_object_keys(d) ORDER BY 1) IS DISTINCT FROM ARRAY['authority_revision','effect','file','namespace_root','release','requirement_id','schema_version','storage_id','test_hash','test_id','workflow']::text[] OR d->>'schema_version' IS DISTINCT FROM '1' OR d->'release'->>'id' IS DISTINCT FROM NEW.release_id::text OR d->'release'->>'revision' IS DISTINCT FROM NEW.release_revision::text OR d->>'requirement_id' IS DISTINCT FROM NEW.requirement_id::text THEN RAISE EXCEPTION 'invalid production dispatch definition' USING ERRCODE='23514';END IF;
 IF NOT EXISTS(SELECT 1 FROM onboarding_releases release CROSS JOIN LATERAL jsonb_array_elements(release.definition->'proofs') proof JOIN onboarding_tests test ON (test.tenant_id,test.partner_id,test.actor_id,test.test_id)=(release.tenant_id,release.partner_id,release.actor_id,(proof->>'test_id')::uuid)
 JOIN workflow_runs r ON (r.tenant_id,r.partner_id,r.actor_id,r.run_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.run_id)
 JOIN workflow_steps step ON (step.tenant_id,step.partner_id,step.actor_id,step.run_id)=(r.tenant_id,r.partner_id,r.actor_id,r.run_id)
 JOIN delivery_intents intent ON (intent.tenant_id,intent.partner_id,intent.actor_id,intent.delivery_id)=(step.tenant_id,step.partner_id,step.actor_id,step.delivery_id)
 WHERE (release.tenant_id,release.partner_id,release.actor_id,release.release_id,release.revision,release.definition_hash,release.state)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.release_id,NEW.release_revision,d->'release'->>'hash','active')
 AND proof->>'requirement_id'=NEW.requirement_id::text AND test.test_id::text=d->>'test_id' AND test.definition_hash=d->>'test_hash' AND test.definition->'effect'=d->'effect' AND test.definition->'workflow'=d->'workflow'
 AND r.state='queued' AND r.revision=1 AND r.source=d->'file' AND r.storage_id::text=d->>'storage_id' AND r.namespace_root=d->>'namespace_root' AND r.authority_revision::text=d->>'authority_revision'
 AND jsonb_build_object('id',r.workflow_id::text,'version',r.workflow_version,'hash',r.workflow_hash)=d->'workflow' AND intent.state='queued' AND intent.attempts=0 AND intent.lease_owner IS NULL
 AND freightctl_onboarding_release_current(NEW.tenant_id,NEW.partner_id,NEW.actor_id,release.definition)) OR EXISTS(SELECT 1 FROM onboarding_tests test WHERE (test.tenant_id,test.partner_id,test.test_id)=(NEW.tenant_id,NEW.partner_id,NEW.run_id)) THEN RAISE EXCEPTION 'production dispatch requires exact active release before effects' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER onboarding_dispatch_guard BEFORE INSERT OR UPDATE OR DELETE ON onboarding_dispatches FOR EACH ROW EXECUTE FUNCTION freightctl_onboarding_dispatch_guard();
CREATE FUNCTION freightctl_onboarding_production_effect_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.definition ? 'workflow_binding' AND NEW.state IN ('staging','publishing','succeeded') AND NOT freightctl_onboarding_production_run_current(NEW.tenant_id,NEW.partner_id,NEW.actor_id,(NEW.definition->'workflow_binding'->>'run_id')::uuid,(NEW.definition->>'authority_revision')::bigint,NEW.definition->>'namespace_root') THEN RAISE EXCEPTION 'production activation changed' USING ERRCODE='23514';END IF;RETURN NEW;
END $$;
CREATE TRIGGER onboarding_production_effect_guard BEFORE INSERT OR UPDATE ON delivery_intents FOR EACH ROW EXECUTE FUNCTION freightctl_onboarding_production_effect_guard();
REVOKE ALL ON FUNCTION freightctl_onboarding_release_guard(),freightctl_onboarding_dispatch_guard(),freightctl_onboarding_production_effect_guard() FROM PUBLIC;
