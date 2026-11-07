-- Runtime credentials stay read-only. Account commands already serialize on
-- this partner-scoped advisory key before authenticating or taking other locks.
-- Raw SQL guards try the matching shared fence and fail40001 instead of waiting
-- while holding a later workflow/review lock. No credential UPDATE grant exists.
CREATE FUNCTION freightctl_authority_read_lock(t uuid,p uuid) RETURNS void LANGUAGE plpgsql VOLATILE AS $$
BEGIN
 IF t IS DISTINCT FROM nullif(current_setting('freightctl.tenant_id',true),'')::uuid OR p IS DISTINCT FROM nullif(current_setting('freightctl.partner_id',true),'')::uuid OR nullif(current_setting('freightctl.actor_id',true),'') IS NULL
 THEN RAISE EXCEPTION 'authority fence requires exact authenticated scope' USING ERRCODE='42501';END IF;
 IF NOT pg_try_advisory_xact_lock_shared(hashtextextended(t::text||':'||p::text||':accounts',0))
 THEN RAISE EXCEPTION 'authority changed or account command in progress;retry exact operation' USING ERRCODE='40001';END IF;
END $$;
REVOKE ALL ON FUNCTION freightctl_authority_read_lock(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION freightctl_authority_read_lock(uuid,uuid) TO freightctl_runtime;

CREATE OR REPLACE FUNCTION freightctl_processing_review_current(t uuid,p uuid,a uuid,w uuid,v integer,h text) RETURNS boolean LANGUAGE plpgsql VOLATILE AS $$
DECLARE r processing_workflow_reviews;
BEGIN
 IF t IS NULL OR p IS NULL OR a IS NULL OR t IS DISTINCT FROM nullif(current_setting('freightctl.tenant_id',true),'')::uuid OR p IS DISTINCT FROM nullif(current_setting('freightctl.partner_id',true),'')::uuid OR a IS DISTINCT FROM nullif(current_setting('freightctl.actor_id',true),'')::uuid THEN RETURN false;END IF;
 PERFORM freightctl_authority_read_lock(t,p);
 IF NOT EXISTS(SELECT 1 FROM credentials c WHERE (c.tenant_id,c.partner_id,c.actor_id)=(t,p,a) AND c.permissions && ARRAY['workflow_manage','workflow_approve','workflow_execute']::text[] AND c.revoked_at IS NULL AND (c.expires_at IS NULL OR c.expires_at>clock_timestamp())) THEN RETURN false;END IF;
 SELECT * INTO r FROM processing_workflow_reviews WHERE (tenant_id,partner_id,actor_id,workflow_id,workflow_version)=(t,p,a,w,v) AND adopted_revision>0 FOR SHARE;
 IF NOT FOUND THEN RETURN true;END IF;
 -- The account fence holds both credential revisions through this transaction;
 -- it neither authenticates the reviewer nor grants access to files.

 RETURN r.state='adopted' AND r.definition->'workflow'->>'hash'=h AND r.expires_at>clock_timestamp() AND freightctl_processing_review_participants(t,p,r.definition);
END $$;

CREATE OR REPLACE FUNCTION freightctl_processing_output_binding_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE e jsonb;b jsonb;i intake_policies;producer credentials;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'processing output producer bindings are immutable' USING ERRCODE='23514';END IF;
 PERFORM freightctl_authority_read_lock(NEW.tenant_id,NEW.partner_id);
 b:=NEW.binding;
 SELECT payload INTO e FROM events WHERE (tenant_id,partner_id,event_id,actor_id,resource_id,kind)=(NEW.tenant_id,NEW.partner_id,NEW.event_id,NEW.actor_id,NEW.policy_id,'ProcessingOutputPolicyBound');
 IF e IS NULL OR e->'binding' IS DISTINCT FROM b OR e->>'binding_hash' IS DISTINCT FROM NEW.binding_hash OR NOT freightctl_processing_output_admin(NEW.tenant_id,NEW.partner_id) OR NEW.actor_id IS DISTINCT FROM nullif(current_setting('freightctl.actor_id',true),'')::uuid THEN RAISE EXCEPTION 'output binding requires exact administrator journal record' USING ERRCODE='42501';END IF;
 IF ARRAY(SELECT jsonb_object_keys(b) ORDER BY 1) IS DISTINCT FROM ARRAY['policy_hash','policy_id','policy_version','producer','profile','publisher_id']::text[] OR b->>'profile' IS DISTINCT FROM 'producer-processing-output-policy-v1' OR b->>'policy_id' IS DISTINCT FROM NEW.policy_id::text OR b->>'policy_version' IS DISTINCT FROM NEW.policy_version::text OR b->>'publisher_id' IS DISTINCT FROM NEW.actor_id::text OR b->'producer'->>'actor_id' IS DISTINCT FROM NEW.producer_id::text OR b->'producer'->>'tenant_id' IS DISTINCT FROM NEW.tenant_id::text OR b->'producer'->>'partner_id' IS DISTINCT FROM NEW.partner_id::text THEN RAISE EXCEPTION 'invalid exact output contract producer binding' USING ERRCODE='23514';END IF;
 IF jsonb_typeof(b->'producer') IS DISTINCT FROM 'object' OR ARRAY(SELECT jsonb_object_keys(b->'producer') ORDER BY 1) IS DISTINCT FROM ARRAY['actor_id','authority_revision','partner_id','root_policy_digest','tenant_id']::text[] THEN RAISE EXCEPTION 'invalid producer snapshot shape' USING ERRCODE='23514';END IF;
 SELECT * INTO i FROM intake_policies WHERE (tenant_id,partner_id,policy_id,version)=(NEW.tenant_id,NEW.partner_id,NEW.policy_id,NEW.policy_version);
 SELECT * INTO producer FROM credentials WHERE (tenant_id,partner_id,actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.producer_id);
 IF i.policy_id IS NULL OR i.state<>'output_active' OR i.revision<>1 OR i.actor_id<>NEW.actor_id OR i.definition_hash IS DISTINCT FROM b->>'policy_hash' OR producer.actor_id IS NULL OR producer.authority_revision::text IS DISTINCT FROM b->'producer'->>'authority_revision' OR encode(sha256(convert_to(producer.namespace_root,'UTF8')),'hex') IS DISTINCT FROM b->'producer'->>'root_policy_digest' OR NOT producer.permissions @> ARRAY['read','write','check_run','workflow_execute']::text[] OR producer.revoked_at IS NOT NULL OR producer.expires_at<=clock_timestamp() THEN RAISE EXCEPTION 'output binding requires current exact contract and producer authority' USING ERRCODE='42501';END IF;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION freightctl_processing_proposal_participants(t uuid,p uuid,d jsonb) RETURNS boolean LANGUAGE plpgsql VOLATILE AS $$
BEGIN
 IF t IS NULL OR p IS NULL OR nullif(current_setting('freightctl.actor_id',true),'') IS NULL OR t IS DISTINCT FROM nullif(current_setting('freightctl.tenant_id',true),'')::uuid OR p IS DISTINCT FROM nullif(current_setting('freightctl.partner_id',true),'')::uuid THEN RETURN false;END IF;
 PERFORM freightctl_authority_read_lock(t,p);
 RETURN EXISTS(SELECT 1 FROM credentials a JOIN credentials e ON (e.tenant_id,e.partner_id,e.actor_id)=(a.tenant_id,a.partner_id,(d->'executor'->>'actor_id')::uuid)
 WHERE (a.tenant_id,a.partner_id,a.actor_id)=(t,p,(d->'author'->>'actor_id')::uuid) AND a.actor_id<>e.actor_id
 AND d->'author'->>'tenant_id'=t::text AND d->'author'->>'partner_id'=p::text AND d->'executor'->>'tenant_id'=t::text AND d->'executor'->>'partner_id'=p::text
 AND a.authority_revision::text=d->'author'->>'authority_revision' AND e.authority_revision::text=d->'executor'->>'authority_revision'
 AND encode(sha256(convert_to(a.namespace_root,'UTF8')),'hex')=d->'author'->>'root_policy_digest' AND encode(sha256(convert_to(e.namespace_root,'UTF8')),'hex')=d->'executor'->>'root_policy_digest'
 AND a.permissions @> ARRAY['workflow_manage']::text[] AND e.permissions @> ARRAY['workflow_manage','read','write','check_run','workflow_execute']::text[]
 AND a.revoked_at IS NULL AND e.revoked_at IS NULL AND (a.expires_at IS NULL OR a.expires_at>clock_timestamp()) AND (e.expires_at IS NULL OR e.expires_at>clock_timestamp()));
END $$;
