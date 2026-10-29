CREATE TABLE onboarding_probes (
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,actor_id uuid NOT NULL,probe_id uuid NOT NULL,
 plan_id uuid NOT NULL,plan_version integer NOT NULL,requirement_id uuid NOT NULL,
 connection_id uuid NOT NULL,connection_version integer NOT NULL,
 definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object' AND octet_length(definition::text)<=4096),
 definition_hash text NOT NULL CHECK(definition_hash ~ '^[0-9a-f]{64}$'),
 state text NOT NULL CHECK(state IN ('queued','running','succeeded','failed','blocked','expired')),
 revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 3),worker_key text NOT NULL,
 lease_owner uuid,lease_until timestamptz,started_at timestamptz,completed_at timestamptz,
 observation jsonb NOT NULL CHECK(jsonb_typeof(observation)='object' AND octet_length(observation::text)<=1024),
 created_at timestamptz NOT NULL,changed_event_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,probe_id),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,plan_id,plan_version) REFERENCES onboarding_plans(tenant_id,partner_id,plan_id,version),
 FOREIGN KEY(tenant_id,partner_id,connection_id,connection_version) REFERENCES connection_revisions(tenant_id,partner_id,connection_id,version),
 FOREIGN KEY(tenant_id,partner_id,changed_event_id) REFERENCES events(tenant_id,partner_id,event_id)
);
CREATE INDEX onboarding_probes_pending ON onboarding_probes(tenant_id,partner_id,actor_id,state,lease_until);
ALTER TABLE onboarding_probes ENABLE ROW LEVEL SECURITY;
ALTER TABLE onboarding_probes FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON onboarding_probes USING(
 tenant_id=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND partner_id=nullif(current_setting('freightctl.partner_id',true),'')::uuid
 AND actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid AND freightctl_onboarding_manager(tenant_id,partner_id)
 AND EXISTS(SELECT 1 FROM credentials c WHERE (c.tenant_id,c.partner_id,c.actor_id)=(onboarding_probes.tenant_id,onboarding_probes.partner_id,onboarding_probes.actor_id) AND c.permissions @> ARRAY['connections_manage']::text[]))
 WITH CHECK(tenant_id=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND partner_id=nullif(current_setting('freightctl.partner_id',true),'')::uuid
 AND actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid AND freightctl_onboarding_manager(tenant_id,partner_id)
 AND EXISTS(SELECT 1 FROM credentials c WHERE (c.tenant_id,c.partner_id,c.actor_id)=(onboarding_probes.tenant_id,onboarding_probes.partner_id,onboarding_probes.actor_id) AND c.permissions @> ARRAY['connections_manage']::text[]));
REVOKE ALL ON onboarding_probes FROM PUBLIC;
GRANT SELECT,INSERT,UPDATE ON onboarding_probes TO freightctl_runtime;
CREATE FUNCTION freightctl_onboarding_probe_current(t uuid,p uuid,a uuid,d jsonb) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT EXISTS(SELECT 1 FROM credentials c WHERE (c.tenant_id,c.partner_id,c.actor_id)=(t,p,a) AND c.authority_revision=(d->>'authority_revision')::bigint)
 AND EXISTS(SELECT 1 FROM onboarding_plans plan WHERE (plan.tenant_id,plan.partner_id,plan.plan_id,plan.version,plan.definition_hash)=(t,p,(d->'plan'->>'id')::uuid,(d->'plan'->>'version')::integer,d->'plan'->>'hash')
  AND NOT EXISTS(SELECT 1 FROM onboarding_plans newer WHERE (newer.tenant_id,newer.partner_id,newer.plan_id)=(plan.tenant_id,plan.partner_id,plan.plan_id) AND newer.version>plan.version)
  AND EXISTS(SELECT 1 FROM jsonb_array_elements(plan.definition->'requirements') r WHERE r->>'id'=d->>'requirement_id' AND r->>'protocol'='sftp' AND r->>'direction'='send'))
 AND EXISTS(SELECT 1 FROM connection_revisions c WHERE (c.tenant_id,c.partner_id,c.actor_id,c.connection_id,c.version,c.definition_hash,c.state)=(t,p,a,(d->'connection'->>'id')::uuid,(d->'connection'->>'version')::integer,d->'connection'->>'hash','active'))
$$;
CREATE FUNCTION freightctl_onboarding_probe_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE e events;d jsonb;o jsonb;k text;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'onboarding probes retain their history' USING ERRCODE='23514';END IF;
 SELECT * INTO e FROM events WHERE (tenant_id,partner_id,event_id,actor_id,resource_id,kind)=(NEW.tenant_id,NEW.partner_id,NEW.changed_event_id,NEW.actor_id,NEW.probe_id,'OnboardingProbeChanged');
 IF e.payload->>'author_id' IS DISTINCT FROM NEW.actor_id::text THEN RAISE EXCEPTION 'probe requires its exact author' USING ERRCODE='23514';END IF;
 IF e.payload->>'id' IS DISTINCT FROM NEW.probe_id::text OR e.payload->'definition' IS DISTINCT FROM NEW.definition OR e.payload->>'definition_hash' IS DISTINCT FROM NEW.definition_hash OR e.payload->>'state' IS DISTINCT FROM NEW.state OR e.payload->>'revision' IS DISTINCT FROM NEW.revision::text OR e.payload->>'worker_key' IS DISTINCT FROM NEW.worker_key OR e.payload->>'lease_owner' IS DISTINCT FROM coalesce(NEW.lease_owner::text,'') OR (e.payload->>'lease_until')::timestamptz IS DISTINCT FROM NEW.lease_until OR (e.payload->>'started_at')::timestamptz IS DISTINCT FROM NEW.started_at OR (e.payload->>'completed_at')::timestamptz IS DISTINCT FROM NEW.completed_at OR e.payload->'observation' IS DISTINCT FROM NEW.observation OR (e.payload->>'created_at')::timestamptz IS DISTINCT FROM NEW.created_at THEN RAISE EXCEPTION 'probe requires its exact event' USING ERRCODE='23514';END IF;
 d:=NEW.definition;o:=NEW.observation;
 IF NEW.state IN ('running','succeeded') AND NOT freightctl_onboarding_probe_current(NEW.tenant_id,NEW.partner_id,NEW.actor_id,d) THEN RAISE EXCEPTION 'probe requires current bindings' USING ERRCODE='23514';END IF;
 IF ARRAY(SELECT jsonb_object_keys(d) ORDER BY 1) IS DISTINCT FROM ARRAY['authority_revision','connection','plan','profile','requirement_id','schema_version']::text[] OR d->>'schema_version' IS DISTINCT FROM '1' OR d->>'profile' IS DISTINCT FROM 'sftp-readonly-v1' OR d->'plan'->>'id' IS DISTINCT FROM NEW.plan_id::text OR d->'plan'->>'version' IS DISTINCT FROM NEW.plan_version::text OR d->'connection'->>'id' IS DISTINCT FROM NEW.connection_id::text OR d->'connection'->>'version' IS DISTINCT FROM NEW.connection_version::text OR d->>'requirement_id' IS DISTINCT FROM NEW.requirement_id::text OR coalesce((d->>'authority_revision')::bigint,0)<1 THEN RAISE EXCEPTION 'invalid probe definition' USING ERRCODE='23514';END IF;
 FOREACH k IN ARRAY ARRAY['plan','connection'] LOOP
  IF jsonb_typeof(d->k) IS DISTINCT FROM 'object' OR ARRAY(SELECT jsonb_object_keys(d->k) ORDER BY 1) IS DISTINCT FROM ARRAY['hash','id','version']::text[] OR coalesce(d->k->>'hash','') !~ '^[0-9a-f]{64}$' THEN RAISE EXCEPTION 'invalid probe binding' USING ERRCODE='23514';END IF;
 END LOOP;
 IF ARRAY(SELECT jsonb_object_keys(o) ORDER BY 1) IS DISTINCT FROM ARRAY['code','directory_traversable','required_extensions','sftp_negotiated','ssh_identity_and_authentication']::text[] OR coalesce(o->>'code','') NOT IN ('awaiting_worker','probing','connectivity_verified','connection_failed','required_extensions_missing','directory_unavailable','binding_changed','lease_expired','probe_deadline_exceeded') THEN RAISE EXCEPTION 'invalid probe observation' USING ERRCODE='23514';END IF;
 FOREACH k IN ARRAY ARRAY['directory_traversable','required_extensions','sftp_negotiated','ssh_identity_and_authentication'] LOOP
  IF jsonb_typeof(o->k) IS DISTINCT FROM 'boolean' THEN RAISE EXCEPTION 'invalid probe check flag' USING ERRCODE='23514';END IF;
 END LOOP;
 IF (o->>'ssh_identity_and_authentication')::boolean IS DISTINCT FROM (o->>'sftp_negotiated')::boolean OR ((o->>'required_extensions')::boolean AND NOT (o->>'sftp_negotiated')::boolean) OR ((o->>'directory_traversable')::boolean AND NOT (o->>'required_extensions')::boolean)
 OR (o->>'code' IN ('awaiting_worker','probing','binding_changed','lease_expired','connection_failed') AND o IS DISTINCT FROM jsonb_build_object('code',o->>'code','ssh_identity_and_authentication',false,'sftp_negotiated',false,'required_extensions',false,'directory_traversable',false)) THEN RAISE EXCEPTION 'probe checks must follow the recorded profile' USING ERRCODE='23514';END IF;
 IF NEW.state='succeeded' AND (o->>'code'<>'connectivity_verified' OR NOT ((o->>'directory_traversable')::boolean AND (o->>'required_extensions')::boolean AND (o->>'sftp_negotiated')::boolean AND (o->>'ssh_identity_and_authentication')::boolean)) OR (NEW.state<>'succeeded' AND o->>'code'='connectivity_verified') THEN RAISE EXCEPTION 'probe success requires all checks' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.state<>'queued' OR NEW.revision<>1 OR NEW.worker_key<>'' OR NEW.lease_owner IS NOT NULL OR NEW.lease_until IS NOT NULL OR NEW.started_at IS NOT NULL OR NEW.completed_at IS NOT NULL OR o IS DISTINCT FROM '{"code":"awaiting_worker","ssh_identity_and_authentication":false,"sftp_negotiated":false,"required_extensions":false,"directory_traversable":false}'::jsonb
   OR NOT EXISTS(SELECT 1 FROM credentials c WHERE (c.tenant_id,c.partner_id,c.actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id) AND c.authority_revision=(d->>'authority_revision')::bigint)
   OR NOT EXISTS(SELECT 1 FROM onboarding_plans p WHERE (p.tenant_id,p.partner_id,p.plan_id,p.version,p.definition_hash)=(NEW.tenant_id,NEW.partner_id,NEW.plan_id,NEW.plan_version,d->'plan'->>'hash') AND NOT EXISTS(SELECT 1 FROM onboarding_plans newer WHERE (newer.tenant_id,newer.partner_id,newer.plan_id)=(p.tenant_id,p.partner_id,p.plan_id) AND newer.version>p.version) AND EXISTS(SELECT 1 FROM jsonb_array_elements(p.definition->'requirements') r WHERE r->>'id'=NEW.requirement_id::text AND r->>'protocol'='sftp' AND r->>'direction'='send'))
   OR NOT EXISTS(SELECT 1 FROM connection_revisions c WHERE (c.tenant_id,c.partner_id,c.actor_id,c.connection_id,c.version,c.definition_hash,c.state)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.connection_id,NEW.connection_version,d->'connection'->>'hash','active')) THEN RAISE EXCEPTION 'probe intent requires current reviewed bindings' USING ERRCODE='23514';END IF;
 ELSE
  IF (NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.probe_id,NEW.plan_id,NEW.plan_version,NEW.requirement_id,NEW.connection_id,NEW.connection_version,NEW.definition,NEW.definition_hash,NEW.created_at) IS DISTINCT FROM (OLD.tenant_id,OLD.partner_id,OLD.actor_id,OLD.probe_id,OLD.plan_id,OLD.plan_version,OLD.requirement_id,OLD.connection_id,OLD.connection_version,OLD.definition,OLD.definition_hash,OLD.created_at) OR NEW.revision<>OLD.revision+1 OR OLD.state NOT IN ('queued','running') THEN RAISE EXCEPTION 'probe definition and terminal results are immutable' USING ERRCODE='23514';END IF;
  IF OLD.state='queued' THEN
   IF NEW.worker_key !~ '^[A-Za-z0-9._:-]{1,128}$' THEN RAISE EXCEPTION 'probe work requires an operation key' USING ERRCODE='23514';END IF;
   IF NEW.state='running' THEN
    IF NEW.lease_owner IS NULL OR NEW.started_at IS NULL OR NEW.lease_until IS DISTINCT FROM NEW.started_at+interval '20 seconds' OR NEW.lease_until<=clock_timestamp() OR NEW.completed_at IS NOT NULL OR o IS DISTINCT FROM '{"code":"probing","ssh_identity_and_authentication":false,"sftp_negotiated":false,"required_extensions":false,"directory_traversable":false}'::jsonb THEN RAISE EXCEPTION 'invalid probe lease' USING ERRCODE='23514';END IF;
   ELSIF NEW.state<>'blocked' OR NEW.lease_owner IS NOT NULL OR NEW.lease_until IS NOT NULL OR NEW.started_at IS NOT NULL OR o->>'code'<>'binding_changed' OR NEW.completed_at IS NULL THEN RAISE EXCEPTION 'invalid queued probe transition' USING ERRCODE='23514';END IF;
  ELSE
   IF (NEW.worker_key,NEW.lease_owner,NEW.lease_until,NEW.started_at) IS DISTINCT FROM (OLD.worker_key,OLD.lease_owner,OLD.lease_until,OLD.started_at) OR NEW.completed_at IS NULL OR NEW.state NOT IN ('succeeded','failed','blocked','expired') THEN RAISE EXCEPTION 'probe result requires its exact fence' USING ERRCODE='23514';END IF;
   IF NEW.state='expired' THEN
    IF OLD.lease_until>clock_timestamp() OR o->>'code'<>'lease_expired' THEN RAISE EXCEPTION 'live probe cannot expire' USING ERRCODE='23514';END IF;
   ELSIF OLD.lease_until<=clock_timestamp() THEN RAISE EXCEPTION 'expired probe worker cannot complete' USING ERRCODE='23514';END IF;
  END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER onboarding_probe_guard BEFORE INSERT OR UPDATE OR DELETE ON onboarding_probes FOR EACH ROW EXECUTE FUNCTION freightctl_onboarding_probe_guard();
REVOKE ALL ON FUNCTION freightctl_onboarding_probe_guard() FROM PUBLIC;
