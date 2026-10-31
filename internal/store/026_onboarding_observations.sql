-- Recovered receipts are separate immutable evidence. Original delivery/run
-- projections and every execution guard retain their original meanings.
CREATE TABLE onboarding_observations (
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,actor_id uuid NOT NULL,observation_id uuid NOT NULL,
 source_run_id uuid NOT NULL,source_delivery_id uuid NOT NULL,plan_id uuid NOT NULL,
 definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object' AND octet_length(definition::text)<=24576),
 definition_hash text NOT NULL CHECK(definition_hash ~ '^[0-9a-f]{64}$'),
 state text NOT NULL CHECK(state IN ('proposed','approved','running','succeeded','unconfirmed','blocked','expired','cancelled')),
 revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 4),worker_key text NOT NULL,
 lease_owner uuid,lease_until timestamptz,started_at timestamptz,completed_at timestamptz,
 result jsonb NOT NULL CHECK(jsonb_typeof(result)='object' AND octet_length(result::text)<=1024),
 created_at timestamptz NOT NULL,changed_event_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,observation_id),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,source_run_id) REFERENCES onboarding_dispatches(tenant_id,partner_id,run_id),
 FOREIGN KEY(tenant_id,partner_id,source_delivery_id) REFERENCES delivery_intents(tenant_id,partner_id,delivery_id),
 FOREIGN KEY(tenant_id,partner_id,changed_event_id) REFERENCES events(tenant_id,partner_id,event_id)
);
CREATE INDEX onboarding_observation_pending ON onboarding_observations(tenant_id,partner_id,actor_id,state,lease_until);
CREATE INDEX onboarding_observation_history ON onboarding_observations(tenant_id,partner_id,actor_id,plan_id,observation_id);
CREATE INDEX onboarding_observation_outcome ON onboarding_observations(tenant_id,partner_id,actor_id,source_run_id,completed_at DESC,observation_id DESC) WHERE state='succeeded';
ALTER TABLE onboarding_observations ENABLE ROW LEVEL SECURITY;ALTER TABLE onboarding_observations FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON onboarding_observations USING(tenant_id=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND partner_id=nullif(current_setting('freightctl.partner_id',true),'')::uuid AND actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid)
 WITH CHECK(tenant_id=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND partner_id=nullif(current_setting('freightctl.partner_id',true),'')::uuid AND actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid AND freightctl_onboarding_manager(tenant_id,partner_id));
REVOKE ALL ON onboarding_observations FROM PUBLIC;GRANT SELECT,INSERT,UPDATE ON onboarding_observations TO freightctl_runtime;

CREATE FUNCTION freightctl_onboarding_observation_current(t uuid,p uuid,a uuid,d jsonb) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT EXISTS(
 SELECT 1 FROM onboarding_dispatches original JOIN onboarding_releases release ON (release.tenant_id,release.partner_id,release.actor_id,release.release_id)=(original.tenant_id,original.partner_id,original.actor_id,original.release_id)
 JOIN workflow_runs r ON (r.tenant_id,r.partner_id,r.actor_id,r.run_id)=(original.tenant_id,original.partner_id,original.actor_id,original.run_id)
 JOIN workflow_steps step ON (step.tenant_id,step.partner_id,step.actor_id,step.run_id)=(r.tenant_id,r.partner_id,r.actor_id,r.run_id)
 JOIN delivery_intents intent ON (intent.tenant_id,intent.partner_id,intent.actor_id,intent.delivery_id)=(step.tenant_id,step.partner_id,step.actor_id,step.delivery_id)
 JOIN onboarding_probes probe ON (probe.tenant_id,probe.partner_id,probe.actor_id,probe.probe_id,probe.revision,probe.definition_hash,probe.state)=(t,p,a,(d->'probe'->>'id')::uuid,(d->'probe'->>'revision')::bigint,d->'probe'->>'hash','succeeded')
 JOIN connection_revisions conn ON (conn.tenant_id,conn.partner_id,conn.actor_id,conn.connection_id,conn.version,conn.definition_hash,conn.state)=(t,p,a,(probe.definition->'connection'->>'id')::uuid,(probe.definition->'connection'->>'version')::integer,probe.definition->'connection'->>'hash','active')
 JOIN files f ON (f.tenant_id,f.partner_id,f.file_id)=(t,p,(d->'authorized_file'->>'id')::uuid)
 JOIN onboarding_plans old_plan ON (old_plan.tenant_id,old_plan.partner_id,old_plan.plan_id,old_plan.version,old_plan.definition_hash)=(t,p,(release.definition->'plan'->>'id')::uuid,(release.definition->'plan'->>'version')::integer,release.definition->'plan'->>'hash')
 WHERE (original.tenant_id,original.partner_id,original.actor_id,original.run_id)=(t,p,a,(d->'source'->'dispatch'->>'id')::uuid)
 AND d->'source'->'dispatch'=jsonb_build_object('id',original.run_id::text,'author_id',original.actor_id::text,'definition',original.definition,'definition_hash',original.definition_hash,'created_event_id',original.created_event_id::text)
 AND d->'source'->'plan'=release.definition->'plan' AND old_plan.plan_id::text=probe.definition->'plan'->>'id' AND original.requirement_id::text=probe.definition->>'requirement_id'
 AND r.state IN ('queued','running','attention') AND r.revision::text=d->'source'->>'run_revision' AND r.source=original.definition->'file' AND r.storage_id::text=d->>'storage_id' AND r.namespace_root=d->>'namespace_root'
 AND intent.delivery_id::text=d->'source'->'delivery'->>'id' AND intent.revision::text=d->'source'->'delivery'->>'revision' AND intent.definition_hash=d->'source'->'delivery'->>'hash' AND intent.state=d->'source'->>'state' AND intent.attempts::text=d->'source'->>'attempts' AND intent.fence::text=d->'source'->>'fence'
 AND ((intent.state='ambiguous' AND intent.lease_owner IS NULL AND intent.lease_until IS NULL) OR (intent.state='publishing' AND intent.lease_owner IS NOT NULL AND intent.lease_until<=clock_timestamp()))
 AND intent.definition->'source'=r.source AND intent.definition->>'storage_id'=r.storage_id::text AND intent.definition->'workflow_binding'->>'connection_id'=step.connection_id::text AND step.connection_id=conn.connection_id
 AND d->'original_connection'=jsonb_build_object('id',step.connection_id::text,'version',step.connection_version,'hash',step.connection_hash)
 AND probe.definition=d->'observer' AND probe.completed_at IS NOT NULL AND probe.observation='{"code":"connectivity_verified","ssh_identity_and_authentication":true,"sftp_negotiated":true,"required_extensions":true,"directory_traversable":true}'::jsonb
 AND freightctl_onboarding_probe_current(t,p,a,probe.definition) AND probe.definition->>'authority_revision'=d->>'authority_revision'
 AND conn.definition->'destination'->>'address'=original.definition->'effect'->>'address' AND conn.definition->'destination'->>'user'=original.definition->'effect'->>'user' AND conn.definition->>'directory'=original.definition->'effect'->>'directory'
 AND d->'effect'=jsonb_build_object('address',conn.definition->'destination'->>'address','user',conn.definition->'destination'->>'user','directory',conn.definition->>'directory','path',rtrim(conn.definition->>'directory','/')||'/'||intent.delivery_id::text||'-'||(intent.definition->>'filename'),'host_fingerprint',conn.definition->'destination'->'host'->>'Fingerprint','key_fingerprint',conn.definition->'destination'->>'key_fingerprint')
 AND d->'authorized_file'=jsonb_build_object('id',f.file_id::text,'size_bytes',f.size_bytes,'sha256',f.sha256,'policy',f.policy,'accepted_event_id',f.accepted_event_id::text)
 AND f.sha256=r.source->>'sha256' AND f.size_bytes::text=r.source->>'size_bytes' AND freightctl_file_available(t,p,f.file_id)
 AND ((f.file_id=r.file_id AND d->>'source_recheck_id'='') OR EXISTS(SELECT 1 FROM file_rechecks recheck WHERE (recheck.tenant_id,recheck.partner_id,recheck.actor_id,recheck.recheck_id,recheck.source_file_id,recheck.new_file_id,recheck.state)=(t,p,a,nullif(d->>'source_recheck_id','')::uuid,r.file_id,f.file_id,'copied')))
 AND EXISTS(SELECT 1 FROM jsonb_array_elements(old_plan.definition->'requirements') req WHERE req->>'id'=original.requirement_id::text AND req->>'required_receipt'=d->>'required_receipt')
 AND ((NOT intent.definition ? 'encryption' AND NOT EXISTS(SELECT 1 FROM delivery_ciphertexts c WHERE (c.tenant_id,c.partner_id,c.actor_id,c.delivery_id)=(t,p,a,intent.delivery_id)) AND d->'wire'=jsonb_build_object('sha256',r.source->>'sha256','size_bytes',(r.source->>'size_bytes')::bigint,'ciphertext',NULL))
 OR EXISTS(SELECT 1 FROM delivery_ciphertexts c WHERE (c.tenant_id,c.partner_id,c.actor_id,c.delivery_id)=(t,p,a,intent.delivery_id) AND c.source_file_id=r.file_id AND c.source_sha256=r.source->>'sha256' AND c.definition_hash=intent.definition_hash AND c.storage_id=r.storage_id AND c.encryption=intent.definition->'encryption' AND c.proof->>'primary_fingerprint'=original.definition->'effect'->>'recipient_fingerprint' AND d->'wire'=jsonb_build_object('sha256',c.sha256,'size_bytes',c.size_bytes,'ciphertext',jsonb_build_object('object_id',c.object_id::text,'sha256',c.sha256,'size_bytes',c.size_bytes)))))
$$;

CREATE FUNCTION freightctl_onboarding_observation_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE e jsonb;d jsonb;o jsonb;permissions text[];
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'receipt observation history cannot be deleted' USING ERRCODE='23514';END IF;
 d:=NEW.definition;o:=NEW.result;
 SELECT payload INTO e FROM events WHERE (tenant_id,partner_id,actor_id,event_id,resource_id,kind)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.changed_event_id,NEW.observation_id,'OnboardingObservationChanged');
 IF e IS NULL OR e->>'id' IS DISTINCT FROM NEW.observation_id::text OR e->>'author_id' IS DISTINCT FROM NEW.actor_id::text OR e->>'source_run_id' IS DISTINCT FROM NEW.source_run_id::text OR e->'definition' IS DISTINCT FROM d OR e->>'definition_hash' IS DISTINCT FROM NEW.definition_hash OR e->>'state' IS DISTINCT FROM NEW.state OR e->>'revision' IS DISTINCT FROM NEW.revision::text OR e->>'worker_key' IS DISTINCT FROM NEW.worker_key OR e->>'lease_owner' IS DISTINCT FROM coalesce(NEW.lease_owner::text,'') OR (e->>'lease_until')::timestamptz IS DISTINCT FROM NEW.lease_until OR (e->>'started_at')::timestamptz IS DISTINCT FROM NEW.started_at OR (e->>'completed_at')::timestamptz IS DISTINCT FROM NEW.completed_at OR e->'result' IS DISTINCT FROM o OR (e->>'created_at')::timestamptz IS DISTINCT FROM NEW.created_at THEN RAISE EXCEPTION 'observation requires its exact immutable event' USING ERRCODE='23514';END IF;
 SELECT c.permissions INTO permissions FROM credentials c WHERE (c.tenant_id,c.partner_id,c.actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id) AND c.revoked_at IS NULL AND (c.expires_at IS NULL OR c.expires_at>clock_timestamp()) AND c.namespace_root='/';
 IF NOT freightctl_onboarding_manager(NEW.tenant_id,NEW.partner_id) OR NOT coalesce(permissions @> ARRAY['connections_manage','read']::text[],false) THEN RAISE EXCEPTION 'observation requires current scoped authority' USING ERRCODE='42501';END IF;
 IF ARRAY(SELECT jsonb_object_keys(d) ORDER BY 1) IS DISTINCT FROM ARRAY['authority_revision','authorized_file','effect','namespace_root','observer','original_connection','probe','profile','required_receipt','schema_version','source','source_recheck_id','storage_id','wire']::text[] OR d->>'schema_version' IS DISTINCT FROM '1' OR d->>'profile' IS DISTINCT FROM 'sftp-published-observation-v1' OR d->>'namespace_root' IS DISTINCT FROM '/' OR coalesce(d->>'required_receipt','') NOT IN ('transport','integrity','business') OR d->'source'->'dispatch'->>'id' IS DISTINCT FROM NEW.source_run_id::text OR d->'source'->'delivery'->>'id' IS DISTINCT FROM NEW.source_delivery_id::text OR d->'observer'->'plan'->>'id' IS DISTINCT FROM NEW.plan_id::text OR ARRAY(SELECT jsonb_object_keys(d->'source') ORDER BY 1) IS DISTINCT FROM ARRAY['attempts','delivery','dispatch','fence','plan','run_revision','state']::text[] OR ARRAY(SELECT jsonb_object_keys(d->'probe') ORDER BY 1) IS DISTINCT FROM ARRAY['hash','id','revision']::text[] THEN RAISE EXCEPTION 'invalid observation definition' USING ERRCODE='23514';END IF;
 IF NEW.state IN ('proposed','approved','running','succeeded') AND NOT freightctl_onboarding_observation_current(NEW.tenant_id,NEW.partner_id,NEW.actor_id,d) THEN RAISE EXCEPTION 'observation source or current observer changed' USING ERRCODE='23514';END IF;
 IF ARRAY(SELECT jsonb_object_keys(o) ORDER BY 1) IS DISTINCT FROM ARRAY['business_acceptance','code','directory_power_loss_durability','file_fsync_acknowledged','integrity_confirmed','reconciled','sha256','size_bytes']::text[] OR o->>'business_acceptance' IS DISTINCT FROM 'unknown' OR o->>'directory_power_loss_durability' IS DISTINCT FROM 'not established' OR o->'file_fsync_acknowledged' IS DISTINCT FROM 'false'::jsonb THEN RAISE EXCEPTION 'invalid receipt observation result' USING ERRCODE='23514';END IF;
 IF NEW.state='succeeded' THEN
  IF o->>'code' IS DISTINCT FROM 'remote_file_integrity_observed' OR o->'integrity_confirmed' IS DISTINCT FROM 'true'::jsonb OR o->'reconciled' IS DISTINCT FROM 'true'::jsonb OR o->>'sha256' IS DISTINCT FROM d->'wire'->>'sha256' OR o->'size_bytes' IS DISTINCT FROM d->'wire'->'size_bytes' THEN RAISE EXCEPTION 'receipt requires exact wire integrity observation' USING ERRCODE='23514';END IF;
 ELSIF o->'integrity_confirmed' IS DISTINCT FROM 'false'::jsonb OR o->'reconciled' IS DISTINCT FROM 'false'::jsonb OR o->>'sha256' IS DISTINCT FROM '' OR o->'size_bytes' IS DISTINCT FROM '0'::jsonb OR o->>'code' IS DISTINCT FROM (CASE NEW.state WHEN 'proposed' THEN 'awaiting_review' WHEN 'approved' THEN 'approved' WHEN 'running' THEN 'observing' WHEN 'unconfirmed' THEN 'remote_postcondition_not_confirmed' WHEN 'blocked' THEN 'binding_changed' WHEN 'expired' THEN 'lease_expired' WHEN 'cancelled' THEN 'cancelled' END) THEN RAISE EXCEPTION 'unconfirmed observation cannot invent a receipt' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.state<>'proposed' OR NEW.revision<>1 OR NEW.worker_key<>'' OR NEW.lease_owner IS NOT NULL OR NEW.lease_until IS NOT NULL OR NEW.started_at IS NOT NULL OR NEW.completed_at IS NOT NULL OR NOT permissions @> ARRAY['workflow_manage']::text[] THEN RAISE EXCEPTION 'observation must start as a reviewed proposal' USING ERRCODE='23514';END IF;
 ELSE
  IF (NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.observation_id,NEW.source_run_id,NEW.source_delivery_id,NEW.plan_id,NEW.definition,NEW.definition_hash,NEW.created_at) IS DISTINCT FROM (OLD.tenant_id,OLD.partner_id,OLD.actor_id,OLD.observation_id,OLD.source_run_id,OLD.source_delivery_id,OLD.plan_id,OLD.definition,OLD.definition_hash,OLD.created_at) OR NEW.revision<>OLD.revision+1 OR OLD.state NOT IN ('proposed','approved','running') THEN RAISE EXCEPTION 'observation definition and terminal outcomes are immutable' USING ERRCODE='23514';END IF;
  IF OLD.state='proposed' AND NEW.state='approved' THEN
   IF NOT permissions @> ARRAY['workflow_approve']::text[] OR NEW.worker_key<>'' OR NEW.lease_owner IS NOT NULL OR NEW.lease_until IS NOT NULL OR NEW.started_at IS NOT NULL OR NEW.completed_at IS NOT NULL THEN RAISE EXCEPTION 'separate exact observation approval required' USING ERRCODE='23514';END IF;
  ELSIF OLD.state IN ('proposed','approved') AND NEW.state='cancelled' THEN
   IF NOT permissions @> ARRAY['workflow_manage']::text[] OR NEW.worker_key<>'' OR NEW.lease_owner IS NOT NULL OR NEW.lease_until IS NOT NULL OR NEW.started_at IS NOT NULL OR NEW.completed_at IS NULL THEN RAISE EXCEPTION 'invalid observation cancellation' USING ERRCODE='23514';END IF;
  ELSIF OLD.state='approved' AND NEW.state IN ('running','blocked') THEN
   IF NOT permissions @> ARRAY['workflow_execute']::text[] OR NEW.worker_key !~ '^[A-Za-z0-9._:-]{1,128}$' THEN RAISE EXCEPTION 'observation work requires current execution permission and key' USING ERRCODE='23514';END IF;
   IF NEW.state='running' THEN
    IF NEW.lease_owner IS NULL OR NEW.started_at IS NULL OR NEW.lease_until IS DISTINCT FROM NEW.started_at+interval '30 seconds' OR NEW.lease_until<=clock_timestamp() OR NEW.completed_at IS NOT NULL THEN RAISE EXCEPTION 'invalid observation lease' USING ERRCODE='23514';END IF;
   ELSIF NEW.lease_owner IS NOT NULL OR NEW.lease_until IS NOT NULL OR NEW.started_at IS NOT NULL OR NEW.completed_at IS NULL THEN RAISE EXCEPTION 'invalid blocked observation' USING ERRCODE='23514';END IF;
  ELSIF OLD.state='running' AND NEW.state IN ('succeeded','unconfirmed','blocked','expired') THEN
   IF NOT permissions @> ARRAY['workflow_execute']::text[] OR (NEW.worker_key,NEW.lease_owner,NEW.lease_until,NEW.started_at) IS DISTINCT FROM (OLD.worker_key,OLD.lease_owner,OLD.lease_until,OLD.started_at) OR NEW.completed_at IS NULL THEN RAISE EXCEPTION 'observation requires the exact worker fence' USING ERRCODE='23514';END IF;
   IF (NEW.state='expired' AND OLD.lease_until>clock_timestamp()) OR (NEW.state<>'expired' AND OLD.lease_until<=clock_timestamp()) THEN RAISE EXCEPTION 'observation lease boundary changed' USING ERRCODE='23514';END IF;
  ELSE RAISE EXCEPTION 'invalid observation transition' USING ERRCODE='23514';END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER onboarding_observation_guard BEFORE INSERT OR UPDATE OR DELETE ON onboarding_observations FOR EACH ROW EXECUTE FUNCTION freightctl_onboarding_observation_guard();
REVOKE ALL ON FUNCTION freightctl_onboarding_observation_guard() FROM PUBLIC;
