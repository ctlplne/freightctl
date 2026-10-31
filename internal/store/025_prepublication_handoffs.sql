-- Only a complete, bounded immutable transition history can establish that
-- this sender never crossed its committed publication boundary. Remote partial
-- files and old ciphertext remain retained; no remote absence is inferred.
CREATE INDEX delivery_transition_history ON events(tenant_id,partner_id,actor_id,resource_id,((payload->>'revision')::bigint),event_id) WHERE kind='DeliveryTransitioned';

CREATE FUNCTION freightctl_handoff_prepublication_proof(t uuid,p uuid,a uuid,i uuid,base bigint,completed boolean) RETURNS jsonb LANGUAGE sql STABLE AS $$
 WITH intent AS MATERIALIZED (
  SELECT * FROM delivery_intents WHERE (tenant_id,partner_id,actor_id,delivery_id)=(t,p,a,i)
   AND attempts BETWEEN 1 AND 8 AND fence=attempts AND (
    (NOT completed AND revision=base AND ((state IN ('retry','blocked') AND lease_owner IS NULL AND lease_until IS NULL) OR (state='staging' AND lease_owner IS NOT NULL AND lease_until<=clock_timestamp())))
    OR (completed AND revision=base+1 AND state='cancelled' AND observation->>'code'='onboarding_handoff' AND lease_owner IS NULL AND lease_until IS NULL))
 ), history AS MATERIALIZED (
  SELECT e.event_id,e.payload,(e.payload->>'revision')::bigint AS revision FROM events e CROSS JOIN intent i0
   WHERE (e.tenant_id,e.partner_id,e.actor_id,e.resource_id,e.kind)=(t,p,a,i,'DeliveryTransitioned')
    AND (NOT completed OR e.event_id<>i0.changed_event_id)
   ORDER BY (e.payload->>'revision')::bigint,e.event_id LIMIT 257
 ), summary AS (
  SELECT count(*) AS n,count(DISTINCT h.revision) AS distinct_n,min(h.revision) AS first,max(h.revision) AS last,
   bool_and(coalesce(h.payload->>'state' IN ('draft','queued','staging','retry','blocked') AND payload->>'id'=i::text AND payload->>'file_id'=i0.file_id::text AND payload->'definition'=i0.definition AND payload->>'definition_hash'=i0.definition_hash,false)) AS before_publication,
   encode(sha256(convert_to(string_agg(event_id::text||':'||payload::text,E'\n' ORDER BY h.revision,event_id),'UTF8')),'hex') AS history_hash
  FROM history h CROSS JOIN intent i0
 ), tail AS (SELECT * FROM history WHERE revision=base)
 SELECT jsonb_build_object('transitions',s.n,'history_hash',s.history_hash,'last_event_id',tail.event_id::text,'ciphertext',
  (SELECT jsonb_build_object('object_id',c.object_id::text,'sha256',c.sha256,'size_bytes',c.size_bytes) FROM delivery_ciphertexts c WHERE (c.tenant_id,c.partner_id,c.actor_id,c.delivery_id)=(t,p,a,i)))
 FROM summary s CROSS JOIN intent i0 CROSS JOIN tail
 WHERE base BETWEEN 3 AND 256 AND s.n=base AND s.distinct_n=base AND s.first=1 AND s.last=base AND s.before_publication
  AND tail.payload->>'state' IN ('staging','retry','blocked') AND tail.payload->>'attempts'=i0.attempts::text AND tail.payload->>'fence'=i0.fence::text
  AND ((tail.payload->>'state' IN ('retry','blocked') AND tail.payload->>'lease_owner'='' AND tail.payload->>'lease_until' IS NULL)
   OR (tail.payload->>'state'='staging' AND (tail.payload->>'lease_until')::timestamptz<=clock_timestamp()))
  AND (completed OR tail.event_id=i0.changed_event_id)
$$;

CREATE FUNCTION freightctl_handoff_source_eligible(t uuid,p uuid,a uuid,d jsonb,completed boolean) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT EXISTS(SELECT 1 FROM delivery_intents i WHERE (i.tenant_id,i.partner_id,i.actor_id,i.delivery_id)=(t,p,a,(d->'source'->'delivery'->>'id')::uuid)
  AND i.attempts::text=d->'source'->>'attempts' AND i.fence::text=d->'source'->>'fence'
  AND CASE d->>'profile'
   WHEN 'untouched-production-handoff-v1' THEN NOT d ? 'prepublication_proof' AND d->'source'->>'state'='queued' AND i.attempts=0 AND i.fence=0 AND i.lease_owner IS NULL AND i.lease_until IS NULL
    AND NOT EXISTS(SELECT 1 FROM delivery_ciphertexts c WHERE (c.tenant_id,c.partner_id,c.delivery_id)=(t,p,i.delivery_id))
   WHEN 'prepublication-production-handoff-v1' THEN d->'source'->>'state' IN ('staging','retry','blocked')
    AND d->'prepublication_proof'=freightctl_handoff_prepublication_proof(t,p,a,i.delivery_id,(d->'source'->'delivery'->>'revision')::bigint,completed)
    AND EXISTS(SELECT 1 FROM events e WHERE (e.tenant_id,e.partner_id,e.actor_id,e.resource_id,e.event_id,e.kind)=(t,p,a,i.delivery_id,(d->'prepublication_proof'->>'last_event_id')::uuid,'DeliveryTransitioned') AND e.payload->>'state'=d->'source'->>'state')
   ELSE false END)
$$;

CREATE OR REPLACE FUNCTION freightctl_onboarding_handoff_current(t uuid,p uuid,a uuid,d jsonb,completed boolean) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT EXISTS(
 SELECT 1 FROM onboarding_dispatches original JOIN onboarding_releases old_release ON (old_release.tenant_id,old_release.partner_id,old_release.actor_id,old_release.release_id)=(original.tenant_id,original.partner_id,original.actor_id,original.release_id)
 JOIN workflow_runs r ON (r.tenant_id,r.partner_id,r.actor_id,r.run_id)=(original.tenant_id,original.partner_id,original.actor_id,original.run_id)
 JOIN workflow_steps step ON (step.tenant_id,step.partner_id,step.actor_id,step.run_id)=(r.tenant_id,r.partner_id,r.actor_id,r.run_id)
 JOIN delivery_intents intent ON (intent.tenant_id,intent.partner_id,intent.actor_id,intent.delivery_id)=(step.tenant_id,step.partner_id,step.actor_id,step.delivery_id)
 JOIN onboarding_releases target ON (target.tenant_id,target.partner_id,target.actor_id,target.release_id,target.revision,target.definition_hash,target.state)=(t,p,a,(d->'target'->'release'->>'id')::uuid,(d->'target'->'release'->>'revision')::bigint,d->'target'->'release'->>'hash','active')
 CROSS JOIN LATERAL jsonb_array_elements(target.definition->'proofs') proof
 JOIN onboarding_tests test ON (test.tenant_id,test.partner_id,test.actor_id,test.test_id)=(target.tenant_id,target.partner_id,target.actor_id,(proof->>'test_id')::uuid)
 JOIN files f ON (f.tenant_id,f.partner_id,f.file_id)=(t,p,(d->'target'->'file'->>'id')::uuid)
 WHERE (original.tenant_id,original.partner_id,original.actor_id,original.run_id)=(t,p,a,(d->'source'->'dispatch'->>'id')::uuid)
 AND d->'source'->'dispatch'=jsonb_build_object('id',original.run_id::text,'author_id',original.actor_id::text,'definition',original.definition,'definition_hash',original.definition_hash,'created_event_id',original.created_event_id::text)
 AND d->'source'->'plan'=old_release.definition->'plan' AND d->'source'->'plan'=target.definition->'plan'
 AND r.source=original.definition->'file' AND original.definition->>'requirement_id'=d->'target'->>'requirement_id' AND r.storage_id::text=d->'target'->>'storage_id' AND r.namespace_root=d->'target'->>'namespace_root'
 AND ((NOT completed AND r.state IN ('queued','running','attention') AND r.revision::text=d->'source'->>'run_revision' AND intent.state=d->'source'->>'state' AND intent.revision::text=d->'source'->'delivery'->>'revision') OR (completed AND r.state='cancelled' AND r.reason='onboarding_handoff' AND r.revision=(d->'source'->>'run_revision')::bigint+1 AND intent.state='cancelled' AND intent.revision=(d->'source'->'delivery'->>'revision')::bigint+1))
 AND intent.delivery_id::text=d->'source'->'delivery'->>'id' AND intent.definition_hash=d->'source'->'delivery'->>'hash'
 AND freightctl_handoff_source_eligible(t,p,a,d,completed)
 AND jsonb_build_object('id',f.file_id::text,'size_bytes',f.size_bytes,'sha256',f.sha256,'policy',f.policy,'accepted_event_id',f.accepted_event_id::text)=d->'target'->'file'
 AND f.sha256=original.definition->'file'->>'sha256' AND f.size_bytes::text=original.definition->'file'->>'size_bytes'
 AND ((d->'target'->'file'=original.definition->'file' AND d->>'source_recheck_id'='') OR EXISTS(SELECT 1 FROM file_rechecks recheck WHERE (recheck.tenant_id,recheck.partner_id,recheck.actor_id,recheck.recheck_id,recheck.source_file_id,recheck.new_file_id,recheck.state)=(t,p,a,nullif(d->>'source_recheck_id','')::uuid,r.file_id,f.file_id,'copied')))
 AND proof->>'requirement_id'=d->'target'->>'requirement_id' AND test.test_id::text=d->'target'->>'test_id' AND test.definition_hash=d->'target'->>'test_hash' AND test.definition->'workflow'=d->'target'->'workflow' AND test.definition->'effect'=d->'target'->'effect'
 AND test.definition->>'step_id'=step.step_id AND original.definition->'workflow'->>'id'=d->'target'->'workflow'->>'id'
 AND original.definition->'effect'->>'address'=d->'target'->'effect'->>'address' AND original.definition->'effect'->>'user'=d->'target'->'effect'->>'user' AND original.definition->'effect'->>'directory'=d->'target'->'effect'->>'directory' AND original.definition->'effect'->>'filename'=d->'target'->'effect'->>'filename'
 AND ((original.definition->'effect' ? 'encryption')=(d->'target'->'effect' ? 'encryption')) AND original.definition->'effect'->'encryption'->>'profile' IS NOT DISTINCT FROM d->'target'->'effect'->'encryption'->>'profile'
 AND (original.definition->'release' IS DISTINCT FROM d->'target'->'release' OR original.definition->'file' IS DISTINCT FROM d->'target'->'file')
 AND freightctl_onboarding_release_current(t,p,a,target.definition) AND freightctl_file_available(t,p,f.file_id))
$$;
CREATE OR REPLACE FUNCTION freightctl_onboarding_handoff_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE e jsonb;d jsonb;permissions text[];
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'handoff history cannot be deleted' USING ERRCODE='23514';END IF;
 d:=NEW.definition;
 SELECT payload INTO e FROM events WHERE (tenant_id,partner_id,actor_id,event_id,resource_id,kind)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.changed_event_id,NEW.handoff_id,'OnboardingHandoffChanged');
 IF e IS NULL OR e->>'id' IS DISTINCT FROM NEW.handoff_id::text OR e->>'author_id' IS DISTINCT FROM NEW.actor_id::text OR e->>'source_run_id' IS DISTINCT FROM NEW.source_run_id::text OR e->'target_release' IS DISTINCT FROM d->'target'->'release' OR e->'definition' IS DISTINCT FROM d OR e->>'definition_hash' IS DISTINCT FROM NEW.definition_hash OR e->>'state' IS DISTINCT FROM NEW.state OR e->>'revision' IS DISTINCT FROM NEW.revision::text OR coalesce(e->>'replacement_run_id','') IS DISTINCT FROM coalesce(NEW.replacement_run_id::text,'') OR (e->>'created_at')::timestamptz IS DISTINCT FROM NEW.created_at THEN RAISE EXCEPTION 'handoff requires exact immutable journal event' USING ERRCODE='23514';END IF;
 SELECT c.permissions INTO permissions FROM credentials c WHERE (c.tenant_id,c.partner_id,c.actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id) AND c.revoked_at IS NULL AND (c.expires_at IS NULL OR c.expires_at>clock_timestamp());
 IF NOT freightctl_onboarding_manager(NEW.tenant_id,NEW.partner_id) OR NOT coalesce(permissions @> ARRAY['connections_manage','read']::text[],false) THEN RAISE EXCEPTION 'handoff requires current onboarding authority' USING ERRCODE='42501';END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.state<>'proposed' OR NEW.revision<>1 OR NOT permissions @> ARRAY['workflow_manage']::text[] THEN RAISE EXCEPTION 'handoff must start as reviewed proposal' USING ERRCODE='23514';END IF;
  IF ARRAY(SELECT jsonb_object_keys(d) ORDER BY 1) IS DISTINCT FROM (CASE d->>'profile' WHEN 'untouched-production-handoff-v1' THEN ARRAY['profile','schema_version','source','source_recheck_id','target','target_hash']::text[] WHEN 'prepublication-production-handoff-v1' THEN ARRAY['prepublication_proof','profile','schema_version','source','source_recheck_id','target','target_hash']::text[] END) OR d->>'schema_version' IS DISTINCT FROM '1' OR coalesce(d->>'profile','') NOT IN ('untouched-production-handoff-v1','prepublication-production-handoff-v1') OR coalesce(d->>'target_hash','') !~ '^[a-f0-9]{64}$' OR d->'source'->'dispatch'->>'id' IS DISTINCT FROM NEW.source_run_id::text OR d->'source'->'delivery'->>'id' IS DISTINCT FROM NEW.source_delivery_id::text OR d->'source'->'plan'->>'id' IS DISTINCT FROM NEW.plan_id::text OR d->'source'->'plan'->>'version' IS DISTINCT FROM NEW.plan_version::text THEN RAISE EXCEPTION 'invalid handoff definition' USING ERRCODE='23514';END IF;
  IF ARRAY(SELECT jsonb_object_keys(d->'source') ORDER BY 1) IS DISTINCT FROM ARRAY['attempts','delivery','dispatch','fence','plan','run_revision','state']::text[] OR ARRAY(SELECT jsonb_object_keys(d->'source'->'delivery') ORDER BY 1) IS DISTINCT FROM ARRAY['hash','id','revision']::text[] OR ARRAY(SELECT jsonb_object_keys(d->'target') ORDER BY 1) IS DISTINCT FROM ARRAY['authority_revision','effect','file','namespace_root','release','requirement_id','schema_version','storage_id','test_hash','test_id','workflow']::text[] OR ARRAY(SELECT jsonb_object_keys(d->'target'->'release') ORDER BY 1) IS DISTINCT FROM ARRAY['hash','id','revision']::text[] THEN RAISE EXCEPTION 'invalid handoff source/target shape' USING ERRCODE='23514';END IF;
 ELSE
  IF (NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.handoff_id,NEW.source_run_id,NEW.source_delivery_id,NEW.plan_id,NEW.plan_version,NEW.definition,NEW.definition_hash,NEW.created_at) IS DISTINCT FROM (OLD.tenant_id,OLD.partner_id,OLD.actor_id,OLD.handoff_id,OLD.source_run_id,OLD.source_delivery_id,OLD.plan_id,OLD.plan_version,OLD.definition,OLD.definition_hash,OLD.created_at) OR NEW.revision<>OLD.revision+1 OR NOT ((OLD.state='proposed' AND NEW.state IN ('approved','cancelled')) OR (OLD.state='approved' AND NEW.state IN ('cancelled','completed'))) THEN RAISE EXCEPTION 'invalid immutable handoff transition' USING ERRCODE='23514';END IF;
  IF NEW.state='approved' AND NOT permissions @> ARRAY['workflow_approve']::text[] THEN RAISE EXCEPTION 'handoff approval permission required' USING ERRCODE='42501';END IF;
  IF NEW.state='completed' AND NOT permissions @> ARRAY['workflow_execute','deliver']::text[] THEN RAISE EXCEPTION 'handoff execution permission required' USING ERRCODE='42501';END IF;
  IF NEW.state='cancelled' AND NOT permissions @> ARRAY['workflow_manage']::text[] THEN RAISE EXCEPTION 'handoff management permission required' USING ERRCODE='42501';END IF;
 END IF;
 IF NEW.state<>'cancelled' AND NOT freightctl_onboarding_handoff_current(NEW.tenant_id,NEW.partner_id,NEW.actor_id,d,NEW.state='completed') THEN RAISE EXCEPTION 'handoff requires exact selected source proof and current target' USING ERRCODE='23514';END IF;
 IF NEW.state='completed' AND NOT EXISTS(SELECT 1 FROM onboarding_dispatches replacement JOIN workflow_runs run ON (run.tenant_id,run.partner_id,run.actor_id,run.run_id)=(replacement.tenant_id,replacement.partner_id,replacement.actor_id,replacement.run_id) JOIN workflow_steps step ON (step.tenant_id,step.partner_id,step.run_id)=(run.tenant_id,run.partner_id,run.run_id) JOIN delivery_intents intent ON (intent.tenant_id,intent.partner_id,intent.delivery_id)=(step.tenant_id,step.partner_id,step.delivery_id) WHERE (replacement.tenant_id,replacement.partner_id,replacement.actor_id,replacement.run_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.replacement_run_id) AND replacement.definition=d->'target' AND replacement.definition_hash=d->>'target_hash' AND run.state='queued' AND run.revision=1 AND intent.state='queued' AND intent.attempts=0 AND intent.fence=0 AND intent.lease_owner IS NULL) THEN RAISE EXCEPTION 'handoff must queue its exact successor atomically' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;

-- Extra cancellation transitions require the existing deferred completed-handoff
-- guard and the full pre-publication proof. Ordinary cancellation is unchanged.
CREATE OR REPLACE FUNCTION freightctl_delivery_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE k text; p jsonb; valid boolean:=false;
BEGIN
 SELECT kind,payload INTO k,p FROM events WHERE (tenant_id,partner_id,event_id)=(NEW.tenant_id,NEW.partner_id,NEW.changed_event_id) AND actor_id=NEW.actor_id AND resource_id=NEW.delivery_id;
 IF k IS DISTINCT FROM 'DeliveryTransitioned' OR p->>'file_id' IS DISTINCT FROM NEW.file_id::text OR
  p->'definition' IS DISTINCT FROM NEW.definition OR p->>'definition_hash' IS DISTINCT FROM NEW.definition_hash OR
  p->>'state' IS DISTINCT FROM NEW.state OR p->>'revision' IS DISTINCT FROM NEW.revision::text OR
  p->>'fence' IS DISTINCT FROM NEW.fence::text OR p->>'attempts' IS DISTINCT FROM NEW.attempts::text OR
  p->>'lease_owner' IS DISTINCT FROM coalesce(NEW.lease_owner::text,'') OR
  (p->>'lease_until')::timestamptz IS DISTINCT FROM NEW.lease_until OR
  (p->>'next_at')::timestamptz IS DISTINCT FROM NEW.next_at OR p->'observation' IS DISTINCT FROM NEW.observation THEN
  RAISE EXCEPTION 'delivery requires its exact event' USING ERRCODE='23514';
 END IF;
 IF TG_OP='INSERT' THEN
  valid:=NEW.state='draft' AND NEW.revision=1 AND NEW.fence=0 AND NEW.attempts=0;
 ELSE
  IF (NEW.tenant_id,NEW.partner_id,NEW.delivery_id,NEW.actor_id,NEW.file_id,NEW.definition,NEW.definition_hash) IS DISTINCT FROM (OLD.tenant_id,OLD.partner_id,OLD.delivery_id,OLD.actor_id,OLD.file_id,OLD.definition,OLD.definition_hash) OR NEW.revision<>OLD.revision+1 THEN
   RAISE EXCEPTION 'delivery definition is immutable' USING ERRCODE='23514';
  END IF;
  IF NEW.state='staging' AND (OLD.state IN ('queued','retry') OR (OLD.state='staging' AND OLD.lease_until<=clock_timestamp())) THEN
   valid:=NEW.fence=OLD.fence+1 AND NEW.attempts=OLD.attempts+1 AND OLD.attempts<8 AND OLD.next_at<=clock_timestamp() AND NEW.lease_until>clock_timestamp() AND NEW.lease_until<=clock_timestamp()+interval '31 seconds';
  ELSIF OLD.state IN ('staging','publishing') AND NEW.state IN ('staging','publishing') THEN
   valid:=OLD.lease_until>clock_timestamp() AND NEW.lease_owner=OLD.lease_owner AND NEW.lease_until>=OLD.lease_until AND NEW.lease_until<=clock_timestamp()+interval '31 seconds' AND NEW.fence=OLD.fence AND NEW.attempts=OLD.attempts AND (NEW.state=OLD.state OR (OLD.state='staging' AND NEW.state='publishing'));
  ELSE
   valid:=NEW.fence=OLD.fence AND NEW.attempts=OLD.attempts AND (
    (OLD.state='draft' AND NEW.state='queued') OR
    (OLD.state IN ('draft','queued','retry','ambiguous') AND NEW.state='cancelled') OR
    (OLD.state IN ('blocked','staging') AND NEW.state='cancelled' AND NEW.observation->>'code'='onboarding_handoff' AND (OLD.state='blocked' OR OLD.lease_until<=clock_timestamp())) OR
    (OLD.state='staging' AND NEW.state IN ('retry','blocked') AND OLD.lease_until>clock_timestamp()) OR
    (OLD.state='publishing' AND NEW.state='succeeded' AND OLD.lease_until>clock_timestamp()) OR
    (OLD.state='publishing' AND NEW.state='ambiguous') OR
    (OLD.state='ambiguous' AND NEW.state='succeeded') OR
    (OLD.state IN ('queued','retry','staging') AND NEW.state='blocked'));
  END IF;
 END IF;
 IF NOT coalesce(valid,false) THEN RAISE EXCEPTION 'invalid delivery state or fence' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
