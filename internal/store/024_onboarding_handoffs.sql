CREATE TABLE onboarding_handoffs (
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,actor_id uuid NOT NULL,handoff_id uuid NOT NULL,
 source_run_id uuid NOT NULL,source_delivery_id uuid NOT NULL,plan_id uuid NOT NULL,plan_version integer NOT NULL,
 definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object' AND octet_length(definition::text)<=24576),
 definition_hash text NOT NULL CHECK(definition_hash ~ '^[0-9a-f]{64}$'),
 state text NOT NULL CHECK(state IN ('proposed','approved','cancelled','completed')),revision bigint NOT NULL CHECK(revision>0),replacement_run_id uuid,
 created_at timestamptz NOT NULL,changed_event_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,handoff_id),CHECK((state='completed')=(replacement_run_id IS NOT NULL)),CHECK(source_run_id IS DISTINCT FROM replacement_run_id),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,source_run_id) REFERENCES onboarding_dispatches(tenant_id,partner_id,run_id),
 FOREIGN KEY(tenant_id,partner_id,source_delivery_id) REFERENCES delivery_intents(tenant_id,partner_id,delivery_id),
 FOREIGN KEY(tenant_id,partner_id,plan_id,plan_version) REFERENCES onboarding_plans(tenant_id,partner_id,plan_id,version),
 FOREIGN KEY(tenant_id,partner_id,replacement_run_id) REFERENCES onboarding_dispatches(tenant_id,partner_id,run_id),
 FOREIGN KEY(tenant_id,partner_id,changed_event_id) REFERENCES events(tenant_id,partner_id,event_id)
);
CREATE UNIQUE INDEX onboarding_one_handoff_successor ON onboarding_handoffs(tenant_id,partner_id,source_run_id) WHERE state='completed';
CREATE INDEX onboarding_handoff_history ON onboarding_handoffs(tenant_id,partner_id,actor_id,plan_id,handoff_id);
ALTER TABLE onboarding_handoffs ENABLE ROW LEVEL SECURITY;ALTER TABLE onboarding_handoffs FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON onboarding_handoffs USING(tenant_id=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND partner_id=nullif(current_setting('freightctl.partner_id',true),'')::uuid AND actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid)
 WITH CHECK(tenant_id=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND partner_id=nullif(current_setting('freightctl.partner_id',true),'')::uuid AND actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid AND freightctl_onboarding_manager(tenant_id,partner_id));
REVOKE ALL ON onboarding_handoffs FROM PUBLIC;GRANT SELECT,INSERT,UPDATE ON onboarding_handoffs TO freightctl_runtime;

CREATE FUNCTION freightctl_onboarding_handoff_current(t uuid,p uuid,a uuid,d jsonb,completed boolean) RETURNS boolean LANGUAGE sql STABLE AS $$
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
 AND ((NOT completed AND r.state IN ('queued','running','attention') AND r.revision::text=d->'source'->>'run_revision' AND intent.state='queued' AND intent.revision::text=d->'source'->'delivery'->>'revision') OR (completed AND r.state='cancelled' AND r.reason='onboarding_handoff' AND r.revision=(d->'source'->>'run_revision')::bigint+1 AND intent.state='cancelled' AND intent.revision=(d->'source'->'delivery'->>'revision')::bigint+1))
 AND intent.delivery_id::text=d->'source'->'delivery'->>'id' AND intent.definition_hash=d->'source'->'delivery'->>'hash' AND intent.attempts=0 AND intent.fence=0 AND intent.lease_owner IS NULL AND intent.lease_until IS NULL
 AND d->'source'->>'state'='queued' AND d->'source'->>'attempts'='0' AND d->'source'->>'fence'='0'
 AND NOT EXISTS(SELECT 1 FROM delivery_ciphertexts cipher WHERE (cipher.tenant_id,cipher.partner_id,cipher.delivery_id)=(intent.tenant_id,intent.partner_id,intent.delivery_id))
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
CREATE FUNCTION freightctl_onboarding_handoff_guard() RETURNS trigger LANGUAGE plpgsql AS $$
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
  IF ARRAY(SELECT jsonb_object_keys(d) ORDER BY 1) IS DISTINCT FROM ARRAY['profile','schema_version','source','source_recheck_id','target','target_hash']::text[] OR d->>'schema_version' IS DISTINCT FROM '1' OR d->>'profile' IS DISTINCT FROM 'untouched-production-handoff-v1' OR coalesce(d->>'target_hash','') !~ '^[a-f0-9]{64}$' OR d->'source'->'dispatch'->>'id' IS DISTINCT FROM NEW.source_run_id::text OR d->'source'->'delivery'->>'id' IS DISTINCT FROM NEW.source_delivery_id::text OR d->'source'->'plan'->>'id' IS DISTINCT FROM NEW.plan_id::text OR d->'source'->'plan'->>'version' IS DISTINCT FROM NEW.plan_version::text THEN RAISE EXCEPTION 'invalid handoff definition' USING ERRCODE='23514';END IF;
  IF ARRAY(SELECT jsonb_object_keys(d->'source') ORDER BY 1) IS DISTINCT FROM ARRAY['attempts','delivery','dispatch','fence','plan','run_revision','state']::text[] OR ARRAY(SELECT jsonb_object_keys(d->'source'->'delivery') ORDER BY 1) IS DISTINCT FROM ARRAY['hash','id','revision']::text[] OR ARRAY(SELECT jsonb_object_keys(d->'target') ORDER BY 1) IS DISTINCT FROM ARRAY['authority_revision','effect','file','namespace_root','release','requirement_id','schema_version','storage_id','test_hash','test_id','workflow']::text[] OR ARRAY(SELECT jsonb_object_keys(d->'target'->'release') ORDER BY 1) IS DISTINCT FROM ARRAY['hash','id','revision']::text[] THEN RAISE EXCEPTION 'invalid handoff source/target shape' USING ERRCODE='23514';END IF;
 ELSE
  IF (NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.handoff_id,NEW.source_run_id,NEW.source_delivery_id,NEW.plan_id,NEW.plan_version,NEW.definition,NEW.definition_hash,NEW.created_at) IS DISTINCT FROM (OLD.tenant_id,OLD.partner_id,OLD.actor_id,OLD.handoff_id,OLD.source_run_id,OLD.source_delivery_id,OLD.plan_id,OLD.plan_version,OLD.definition,OLD.definition_hash,OLD.created_at) OR NEW.revision<>OLD.revision+1 OR NOT ((OLD.state='proposed' AND NEW.state IN ('approved','cancelled')) OR (OLD.state='approved' AND NEW.state IN ('cancelled','completed'))) THEN RAISE EXCEPTION 'invalid immutable handoff transition' USING ERRCODE='23514';END IF;
  IF NEW.state='approved' AND NOT permissions @> ARRAY['workflow_approve']::text[] THEN RAISE EXCEPTION 'handoff approval permission required' USING ERRCODE='42501';END IF;
  IF NEW.state='completed' AND NOT permissions @> ARRAY['workflow_execute','deliver']::text[] THEN RAISE EXCEPTION 'handoff execution permission required' USING ERRCODE='42501';END IF;
  IF NEW.state='cancelled' AND NOT permissions @> ARRAY['workflow_manage']::text[] THEN RAISE EXCEPTION 'handoff management permission required' USING ERRCODE='42501';END IF;
 END IF;
 IF NEW.state<>'cancelled' AND NOT freightctl_onboarding_handoff_current(NEW.tenant_id,NEW.partner_id,NEW.actor_id,d,NEW.state='completed') THEN RAISE EXCEPTION 'handoff requires untouched source and exact current target' USING ERRCODE='23514';END IF;
 IF NEW.state='completed' AND NOT EXISTS(SELECT 1 FROM onboarding_dispatches replacement JOIN workflow_runs run ON (run.tenant_id,run.partner_id,run.actor_id,run.run_id)=(replacement.tenant_id,replacement.partner_id,replacement.actor_id,replacement.run_id) JOIN workflow_steps step ON (step.tenant_id,step.partner_id,step.run_id)=(run.tenant_id,run.partner_id,run.run_id) JOIN delivery_intents intent ON (intent.tenant_id,intent.partner_id,intent.delivery_id)=(step.tenant_id,step.partner_id,step.delivery_id) WHERE (replacement.tenant_id,replacement.partner_id,replacement.actor_id,replacement.run_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.replacement_run_id) AND replacement.definition=d->'target' AND replacement.definition_hash=d->>'target_hash' AND run.state='queued' AND run.revision=1 AND intent.state='queued' AND intent.attempts=0 AND intent.fence=0 AND intent.lease_owner IS NULL) THEN RAISE EXCEPTION 'handoff must queue its exact successor atomically' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER onboarding_handoff_guard BEFORE INSERT OR UPDATE OR DELETE ON onboarding_handoffs FOR EACH ROW EXECUTE FUNCTION freightctl_onboarding_handoff_guard();
-- A caller cannot label a cancellation as a handoff without committing the
-- approved completed link and exact separately queued successor with it.
CREATE FUNCTION freightctl_onboarding_handoff_cancellation_complete() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_TABLE_NAME='delivery_intents' THEN
  IF NEW.state='cancelled' AND NEW.observation->>'code'='onboarding_handoff' AND NOT EXISTS(SELECT 1 FROM onboarding_handoffs h WHERE (h.tenant_id,h.partner_id,h.actor_id,h.handoff_id,h.source_delivery_id,h.state)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,(NEW.observation->>'handoff_id')::uuid,NEW.delivery_id,'completed')) THEN RAISE EXCEPTION 'handoff cancellation requires atomic completed successor' USING ERRCODE='23514';END IF;
 ELSE
  IF NEW.state='cancelled' AND NEW.reason='onboarding_handoff' AND NOT EXISTS(SELECT 1 FROM onboarding_handoffs h WHERE (h.tenant_id,h.partner_id,h.actor_id,h.source_run_id,h.state)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.run_id,'completed')) THEN RAISE EXCEPTION 'handoff run cancellation requires atomic completed successor' USING ERRCODE='23514';END IF;
 END IF;RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER handoff_cancelled_delivery_complete AFTER INSERT OR UPDATE ON delivery_intents DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION freightctl_onboarding_handoff_cancellation_complete();
CREATE CONSTRAINT TRIGGER handoff_cancelled_run_complete AFTER INSERT OR UPDATE ON workflow_runs DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION freightctl_onboarding_handoff_cancellation_complete();
REVOKE ALL ON FUNCTION freightctl_onboarding_handoff_guard(),freightctl_onboarding_handoff_cancellation_complete() FROM PUBLIC;
