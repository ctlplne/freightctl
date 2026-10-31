-- Explicit partner policy and a separately disclosed review package. Existing
-- private plans/tests/releases are never made readable by the assigned reviewer.
CREATE TABLE onboarding_approval_policies(
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,revision bigint NOT NULL CHECK(revision>0),
 mode text NOT NULL CHECK(mode IN ('author','independent')),actor_id uuid NOT NULL,event_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,revision),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,event_id) REFERENCES events(tenant_id,partner_id,event_id)
);
CREATE TABLE onboarding_approval_reviews(
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,actor_id uuid NOT NULL,review_id uuid NOT NULL,reviewer_id uuid NOT NULL,release_id uuid NOT NULL,
 definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object' AND octet_length(definition::text)<=32768),
 definition_hash text NOT NULL CHECK(definition_hash ~ '^[0-9a-f]{64}$'),
 state text NOT NULL CHECK(state IN ('pending','approved','rejected','withdrawn')),revision bigint NOT NULL CHECK(revision>0),
 created_at timestamptz NOT NULL,changed_event_id uuid NOT NULL,policy_revision bigint NOT NULL CHECK(policy_revision>0),
 PRIMARY KEY(tenant_id,partner_id,review_id),CHECK(actor_id<>reviewer_id),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,reviewer_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,release_id) REFERENCES onboarding_releases(tenant_id,partner_id,release_id),
 FOREIGN KEY(tenant_id,partner_id,policy_revision) REFERENCES onboarding_approval_policies(tenant_id,partner_id,revision),
 FOREIGN KEY(tenant_id,partner_id,changed_event_id) REFERENCES events(tenant_id,partner_id,event_id)
);
CREATE UNIQUE INDEX onboarding_one_open_review ON onboarding_approval_reviews(tenant_id,partner_id,release_id) WHERE state IN ('pending','approved');
CREATE INDEX onboarding_review_author_history ON onboarding_approval_reviews(tenant_id,partner_id,actor_id,review_id);
CREATE INDEX onboarding_review_assignee_history ON onboarding_approval_reviews(tenant_id,partner_id,reviewer_id,review_id);
ALTER TABLE onboarding_approval_policies ENABLE ROW LEVEL SECURITY;ALTER TABLE onboarding_approval_policies FORCE ROW LEVEL SECURITY;
ALTER TABLE onboarding_approval_reviews ENABLE ROW LEVEL SECURITY;ALTER TABLE onboarding_approval_reviews FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON onboarding_approval_policies USING(tenant_id=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND partner_id=nullif(current_setting('freightctl.partner_id',true),'')::uuid)
 WITH CHECK(tenant_id=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND partner_id=nullif(current_setting('freightctl.partner_id',true),'')::uuid AND freightctl_onboarding_manager(tenant_id,partner_id));
CREATE FUNCTION freightctl_onboarding_review_reader(t uuid,p uuid,a uuid,r uuid) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT t=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND p=nullif(current_setting('freightctl.partner_id',true),'')::uuid
 AND EXISTS(SELECT 1 FROM credentials c WHERE (c.tenant_id,c.partner_id,c.actor_id)=(t,p,nullif(current_setting('freightctl.actor_id',true),'')::uuid)
 AND c.namespace_root='/' AND c.revoked_at IS NULL AND (c.expires_at IS NULL OR c.expires_at>clock_timestamp())
 AND ((c.actor_id=a AND c.permissions @> ARRAY['workflow_manage']::text[]) OR (c.actor_id=r AND c.permissions @> ARRAY['workflow_approve','inspect']::text[])))
$$;
CREATE POLICY scope ON onboarding_approval_reviews USING(freightctl_onboarding_review_reader(tenant_id,partner_id,actor_id,reviewer_id)) WITH CHECK(freightctl_onboarding_review_reader(tenant_id,partner_id,actor_id,reviewer_id));
REVOKE ALL ON onboarding_approval_policies,onboarding_approval_reviews FROM PUBLIC;
GRANT SELECT,INSERT ON onboarding_approval_policies TO freightctl_runtime;
GRANT SELECT,INSERT,UPDATE ON onboarding_approval_reviews TO freightctl_runtime;
CREATE FUNCTION freightctl_onboarding_policy_binding(t uuid,p uuid) RETURNS jsonb LANGUAGE sql STABLE AS $$
 SELECT coalesce((SELECT jsonb_build_object('revision',revision,'mode',mode) FROM onboarding_approval_policies WHERE tenant_id=t AND partner_id=p ORDER BY revision DESC LIMIT 1),'{"revision":0,"mode":"author"}'::jsonb)
$$;
CREATE FUNCTION freightctl_onboarding_policy_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE e jsonb;n bigint;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'approval policy history is immutable' USING ERRCODE='23514';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id::text||':'||NEW.partner_id::text||':accounts',0));
 PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id::text||':'||NEW.partner_id::text||':onboarding-approval-policy',0));
 SELECT coalesce(max(revision),0)+1 INTO n FROM onboarding_approval_policies WHERE tenant_id=NEW.tenant_id AND partner_id=NEW.partner_id;
 SELECT payload INTO e FROM events WHERE (tenant_id,partner_id,event_id,actor_id,resource_id,kind)=(NEW.tenant_id,NEW.partner_id,NEW.event_id,NEW.actor_id,NEW.partner_id,'OnboardingApprovalPolicyChanged');
 IF NOT freightctl_onboarding_manager(NEW.tenant_id,NEW.partner_id) OR NEW.actor_id IS DISTINCT FROM nullif(current_setting('freightctl.actor_id',true),'')::uuid THEN RAISE EXCEPTION 'policy requires current partner administrator' USING ERRCODE='42501';END IF;
 IF NEW.revision<>n OR e IS NULL OR e->>'revision' IS DISTINCT FROM NEW.revision::text OR e->>'mode' IS DISTINCT FROM NEW.mode OR e->>'author_id' IS DISTINCT FROM NEW.actor_id::text THEN RAISE EXCEPTION 'policy requires exact journal revision' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER onboarding_policy_guard BEFORE INSERT OR UPDATE OR DELETE ON onboarding_approval_policies FOR EACH ROW EXECUTE FUNCTION freightctl_onboarding_policy_guard();
CREATE FUNCTION freightctl_onboarding_review_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE e jsonb;d jsonb;a uuid;expected jsonb;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'approval reviews cannot be deleted' USING ERRCODE='23514';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id::text||':'||NEW.partner_id::text||':accounts',0));
 IF TG_OP='UPDATE' THEN PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id::text||':'||NEW.partner_id::text||':onboarding-approval-policy',0));END IF;
 a:=nullif(current_setting('freightctl.actor_id',true),'')::uuid;d:=NEW.definition;
 SELECT payload INTO e FROM events WHERE (tenant_id,partner_id,event_id,actor_id,resource_id,kind)=(NEW.tenant_id,NEW.partner_id,NEW.changed_event_id,a,NEW.review_id,'OnboardingApprovalReviewChanged');
 IF e IS NULL OR e->>'id' IS DISTINCT FROM NEW.review_id::text OR e->>'author_id' IS DISTINCT FROM NEW.actor_id::text OR e->>'reviewer_id' IS DISTINCT FROM NEW.reviewer_id::text OR e->'definition' IS DISTINCT FROM d OR e->>'definition_hash' IS DISTINCT FROM NEW.definition_hash OR e->>'state' IS DISTINCT FROM NEW.state OR e->>'revision' IS DISTINCT FROM NEW.revision::text OR (e->>'created_at')::timestamptz IS DISTINCT FROM NEW.created_at THEN RAISE EXCEPTION 'review requires exact immutable journal record' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN
  IF a<>NEW.actor_id OR NOT freightctl_onboarding_manager(NEW.tenant_id,NEW.partner_id) OR NEW.state<>'pending' OR NEW.revision<>1 THEN RAISE EXCEPTION 'review starts with owner proposal' USING ERRCODE='23514';END IF;
  IF ARRAY(SELECT jsonb_object_keys(d) ORDER BY 1) IS DISTINCT FROM ARRAY['author_id','effects','policy','release','release_hash','release_id','release_revision','reviewer_authority_revision','reviewer_id','schema_version']::text[] OR d->>'schema_version' IS DISTINCT FROM '1' OR d->>'author_id' IS DISTINCT FROM NEW.actor_id::text OR d->>'reviewer_id' IS DISTINCT FROM NEW.reviewer_id::text OR d->>'release_id' IS DISTINCT FROM NEW.release_id::text OR d->>'release_revision' IS DISTINCT FROM '1' OR d->'policy' IS DISTINCT FROM freightctl_onboarding_policy_binding(NEW.tenant_id,NEW.partner_id) OR d->'policy'->>'mode' IS DISTINCT FROM 'independent' OR d->'policy'->>'revision' IS DISTINCT FROM NEW.policy_revision::text THEN RAISE EXCEPTION 'invalid exact review binding' USING ERRCODE='23514';END IF;
  IF NOT EXISTS(SELECT 1 FROM credentials c WHERE (c.tenant_id,c.partner_id,c.actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.reviewer_id) AND c.namespace_root='/' AND c.revoked_at IS NULL AND (c.expires_at IS NULL OR c.expires_at>clock_timestamp()) AND c.authority_revision::text=d->>'reviewer_authority_revision' AND c.permissions @> ARRAY['workflow_approve','inspect']::text[]) THEN RAISE EXCEPTION 'assigned reviewer lacks current authority' USING ERRCODE='42501';END IF;
  IF NOT EXISTS(SELECT 1 FROM onboarding_releases r WHERE (r.tenant_id,r.partner_id,r.actor_id,r.release_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.release_id) AND r.state='proposed' AND r.revision=1 AND r.definition=d->'release' AND r.definition_hash=d->>'release_hash' AND r.definition->'approval_policy'=d->'policy' AND freightctl_onboarding_release_current(r.tenant_id,r.partner_id,r.actor_id,r.definition)) THEN RAISE EXCEPTION 'review requires exact proposed current release' USING ERRCODE='23514';END IF;
  SELECT jsonb_agg(jsonb_build_object('requirement_id',test.definition->>'requirement_id','file',test.definition->'file','effect',test.definition->'effect') ORDER BY proof.ordinality) INTO expected FROM jsonb_array_elements(d->'release'->'proofs') WITH ORDINALITY proof(value,ordinality) JOIN onboarding_tests test ON (test.tenant_id,test.partner_id,test.actor_id,test.test_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,(proof.value->>'test_id')::uuid);
  IF d->'effects' IS DISTINCT FROM expected THEN RAISE EXCEPTION 'review effects must equal recorded test evidence' USING ERRCODE='23514';END IF;
 ELSE
  IF (NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.review_id,NEW.reviewer_id,NEW.release_id,NEW.definition,NEW.definition_hash,NEW.created_at,NEW.policy_revision) IS DISTINCT FROM (OLD.tenant_id,OLD.partner_id,OLD.actor_id,OLD.review_id,OLD.reviewer_id,OLD.release_id,OLD.definition,OLD.definition_hash,OLD.created_at,OLD.policy_revision) OR NEW.revision<>OLD.revision+1 THEN RAISE EXCEPTION 'review identity is immutable' USING ERRCODE='23514';END IF;
  IF NEW.state='withdrawn' AND OLD.state IN ('pending','approved') THEN
   IF a<>NEW.actor_id THEN RAISE EXCEPTION 'only author can withdraw review' USING ERRCODE='42501';END IF;
  ELSIF NEW.state IN ('approved','rejected') AND OLD.state='pending' THEN
   IF a<>NEW.reviewer_id OR a=NEW.actor_id OR d->'policy' IS DISTINCT FROM freightctl_onboarding_policy_binding(NEW.tenant_id,NEW.partner_id) OR NOT EXISTS(SELECT 1 FROM credentials c WHERE (c.tenant_id,c.partner_id,c.actor_id)=(NEW.tenant_id,NEW.partner_id,a) AND c.authority_revision::text=d->>'reviewer_authority_revision' AND c.permissions @> ARRAY['workflow_approve','inspect']::text[] AND c.namespace_root='/' AND c.revoked_at IS NULL AND (c.expires_at IS NULL OR c.expires_at>clock_timestamp())) THEN RAISE EXCEPTION 'approval requires exact current independent reviewer' USING ERRCODE='42501';END IF;
   IF NOT EXISTS(SELECT 1 FROM credentials c WHERE (c.tenant_id,c.partner_id,c.actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id) AND c.authority_revision::text=d->'release'->>'authority_revision' AND c.revoked_at IS NULL AND (c.expires_at IS NULL OR c.expires_at>clock_timestamp())) THEN RAISE EXCEPTION 'release author authority changed' USING ERRCODE='42501';END IF;
  ELSE RAISE EXCEPTION 'invalid review transition' USING ERRCODE='23514';END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER onboarding_review_guard BEFORE INSERT OR UPDATE OR DELETE ON onboarding_approval_reviews FOR EACH ROW EXECUTE FUNCTION freightctl_onboarding_review_guard();
-- Current checks take a shared partner lock before reading policy and approvals.
-- Policy/decision mutations take the exclusive lock before reading target rows.
CREATE FUNCTION freightctl_onboarding_approval_current(t uuid,p uuid,a uuid,r uuid) RETURNS boolean LANGUAGE plpgsql VOLATILE AS $$
DECLARE d jsonb;policy jsonb;
BEGIN
 PERFORM pg_advisory_xact_lock_shared(hashtextextended(t::text||':'||p::text||':onboarding-approval-policy',0));
 policy:=freightctl_onboarding_policy_binding(t,p);
 SELECT definition INTO d FROM onboarding_releases WHERE (tenant_id,partner_id,actor_id,release_id)=(t,p,a,r);
 IF d IS NULL OR coalesce(d->'approval_policy','{"revision":0,"mode":"author"}'::jsonb) IS DISTINCT FROM policy THEN RETURN false;END IF;
 IF policy->>'mode'='author' THEN RETURN true;END IF;
 RETURN EXISTS(SELECT 1 FROM onboarding_approval_reviews review JOIN credentials c ON (c.tenant_id,c.partner_id,c.actor_id)=(review.tenant_id,review.partner_id,review.reviewer_id)
 WHERE (review.tenant_id,review.partner_id,review.actor_id,review.release_id)=(t,p,a,r) AND review.state='approved' AND review.definition->'policy'=policy AND review.definition->'release'=d
 AND c.authority_revision::text=review.definition->>'reviewer_authority_revision' AND c.namespace_root='/' AND c.permissions @> ARRAY['workflow_approve','inspect']::text[] AND c.revoked_at IS NULL AND (c.expires_at IS NULL OR c.expires_at>clock_timestamp()));
END $$;
ALTER FUNCTION freightctl_onboarding_release_current(uuid,uuid,uuid,jsonb) RENAME TO freightctl_onboarding_release_proofs_current;
CREATE FUNCTION freightctl_onboarding_release_current(t uuid,p uuid,a uuid,d jsonb) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT freightctl_onboarding_release_proofs_current(t,p,a,d) AND coalesce(d->'approval_policy','{"revision":0,"mode":"author"}'::jsonb)=freightctl_onboarding_policy_binding(t,p)
$$;

CREATE OR REPLACE FUNCTION freightctl_onboarding_release_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE e jsonb;d jsonb;proof jsonb;permissions text[];
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'onboarding releases cannot be deleted' USING ERRCODE='23514';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended(NEW.tenant_id::text||':'||NEW.partner_id::text||':onboarding-approval-policy',0));
 d:=NEW.definition;
 SELECT payload INTO e FROM events WHERE (tenant_id,partner_id,actor_id,event_id,resource_id,kind)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.changed_event_id,NEW.release_id,'OnboardingReleaseChanged');
 IF e IS NULL OR e->>'id' IS DISTINCT FROM NEW.release_id::text OR e->>'author_id' IS DISTINCT FROM NEW.actor_id::text OR e->'definition' IS DISTINCT FROM d OR e->>'definition_hash' IS DISTINCT FROM NEW.definition_hash OR e->>'state' IS DISTINCT FROM NEW.state OR e->>'revision' IS DISTINCT FROM NEW.revision::text OR e->>'approved_revision' IS DISTINCT FROM NEW.approved_revision::text OR (e->>'created_at')::timestamptz IS DISTINCT FROM NEW.created_at OR e->'plan' IS DISTINCT FROM d->'plan' THEN RAISE EXCEPTION 'release requires exact immutable journal event' USING ERRCODE='23514';END IF;
 SELECT c.permissions INTO permissions FROM credentials c WHERE (c.tenant_id,c.partner_id,c.actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id) AND c.revoked_at IS NULL AND (c.expires_at IS NULL OR c.expires_at>clock_timestamp());
 IF NOT freightctl_onboarding_manager(NEW.tenant_id,NEW.partner_id) OR NOT coalesce(permissions @> ARRAY['connections_manage','read']::text[],false) THEN RAISE EXCEPTION 'release requires current onboarding authority' USING ERRCODE='42501';END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.state<>'proposed' OR NEW.revision<>1 OR NEW.approved_revision<>0 OR NOT permissions @> ARRAY['workflow_manage']::text[] THEN RAISE EXCEPTION 'release must begin as reviewed proposal' USING ERRCODE='23514';END IF;
  IF ARRAY(SELECT jsonb_object_keys(d-'approval_policy') ORDER BY 1) IS DISTINCT FROM ARRAY['authority_revision','namespace_root','plan','profile','proofs','schema_version','storage_id']::text[] OR d->>'schema_version' IS DISTINCT FROM '1' OR d->>'profile' IS DISTINCT FROM 'sftp-outbound-production-v1' OR d->>'namespace_root' IS DISTINCT FROM '/' OR d->>'storage_id' IS DISTINCT FROM NEW.storage_id::text OR d->'plan' IS DISTINCT FROM jsonb_build_object('id',NEW.plan_id::text,'version',NEW.plan_version,'hash',NEW.plan_hash) OR jsonb_typeof(d->'proofs') IS DISTINCT FROM 'array' OR jsonb_array_length(d->'proofs') NOT BETWEEN 1 AND 64 THEN RAISE EXCEPTION 'invalid release definition' USING ERRCODE='23514';END IF;
  IF (SELECT count(DISTINCT q->>'requirement_id') FROM jsonb_array_elements(d->'proofs') q)<>jsonb_array_length(d->'proofs') OR (SELECT count(DISTINCT q->>'test_id') FROM jsonb_array_elements(d->'proofs') q)<>jsonb_array_length(d->'proofs') THEN RAISE EXCEPTION 'release must cover each requirement exactly once' USING ERRCODE='23514';END IF;
  FOR proof IN SELECT * FROM jsonb_array_elements(d->'proofs') LOOP
   IF ARRAY(SELECT jsonb_object_keys(proof) ORDER BY 1) IS DISTINCT FROM ARRAY['delivery_id','delivery_revision','receipt_hash','requirement_id','snapshot_hash','test_hash','test_id']::text[] OR coalesce(proof->>'receipt_hash','') !~ '^[a-f0-9]{64}$' OR coalesce(proof->>'snapshot_hash','') !~ '^[a-f0-9]{64}$' THEN RAISE EXCEPTION 'invalid release proof' USING ERRCODE='23514';END IF;
  END LOOP;
 ELSE
  IF (NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.release_id,NEW.plan_id,NEW.plan_version,NEW.plan_hash,NEW.definition,NEW.definition_hash,NEW.storage_id,NEW.created_at) IS DISTINCT FROM (OLD.tenant_id,OLD.partner_id,OLD.actor_id,OLD.release_id,OLD.plan_id,OLD.plan_version,OLD.plan_hash,OLD.definition,OLD.definition_hash,OLD.storage_id,OLD.created_at) OR NEW.revision<>OLD.revision+1 OR OLD.state='revoked' THEN RAISE EXCEPTION 'release definition is immutable and revision must advance' USING ERRCODE='23514';END IF;
  IF NOT ((OLD.state='proposed' AND NEW.state='approved') OR (OLD.state IN ('approved','suspended') AND NEW.state='active') OR (OLD.state='active' AND NEW.state='suspended') OR (NEW.state='revoked' AND OLD.state<>'revoked')) THEN RAISE EXCEPTION 'invalid release transition' USING ERRCODE='23514';END IF;
  IF ((NEW.state='approved' AND coalesce(d->'approval_policy'->>'mode','author')='author') OR NEW.state='revoked') AND NOT permissions @> ARRAY['workflow_approve']::text[] THEN RAISE EXCEPTION 'release requires approval permission' USING ERRCODE='42501';END IF;
  IF NEW.state IN ('active','suspended') AND NOT permissions @> ARRAY['workflow_execute','deliver']::text[] THEN RAISE EXCEPTION 'activation requires execution permission' USING ERRCODE='42501';END IF;
  IF NEW.approved_revision IS DISTINCT FROM (CASE WHEN NEW.state='approved' THEN NEW.revision ELSE OLD.approved_revision END) THEN RAISE EXCEPTION 'approval revision cannot be invented or rewritten' USING ERRCODE='23514';END IF;
 END IF;
 IF NEW.state IN ('proposed','approved','active') AND NOT freightctl_onboarding_release_current(NEW.tenant_id,NEW.partner_id,NEW.actor_id,d) THEN RAISE EXCEPTION 'release evidence or authority changed' USING ERRCODE='23514';END IF;
 IF NEW.state='approved' AND d->'approval_policy'->>'mode'='independent' AND NOT permissions @> ARRAY['workflow_manage']::text[] THEN RAISE EXCEPTION 'recording independent approval requires management permission' USING ERRCODE='42501';END IF;
 IF NEW.state IN ('approved','active') AND NOT freightctl_onboarding_approval_current(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.release_id) THEN RAISE EXCEPTION 'current independent approval required' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION freightctl_onboarding_production_run_current(t uuid,p uuid,a uuid,r uuid,authority bigint,root text) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT NOT EXISTS(SELECT 1 FROM onboarding_dispatches x WHERE (x.tenant_id,x.partner_id,x.actor_id,x.run_id)=(t,p,a,r)) OR EXISTS(
 SELECT 1 FROM onboarding_dispatches x JOIN onboarding_releases release USING(tenant_id,partner_id,release_id)
 WHERE (x.tenant_id,x.partner_id,x.actor_id,x.run_id)=(t,p,a,r) AND release.actor_id=a AND release.state='active' AND release.revision=x.release_revision AND release.definition_hash=x.definition->'release'->>'hash'
 AND release.definition->>'authority_revision'=authority::text AND release.definition->>'namespace_root'=root AND freightctl_onboarding_release_current(t,p,a,release.definition) AND freightctl_onboarding_approval_current(t,p,a,release.release_id))
$$;

CREATE FUNCTION freightctl_onboarding_dispatch_approval_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT freightctl_onboarding_approval_current(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.release_id) THEN RAISE EXCEPTION 'dispatch requires current independent approval' USING ERRCODE='23514';END IF;RETURN NEW;
END $$;
CREATE TRIGGER onboarding_dispatch_approval_guard BEFORE INSERT ON onboarding_dispatches FOR EACH ROW EXECUTE FUNCTION freightctl_onboarding_dispatch_approval_guard();
CREATE FUNCTION freightctl_onboarding_approval_event_complete() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (NEW.kind='OnboardingApprovalPolicyChanged' AND NOT EXISTS(SELECT 1 FROM onboarding_approval_policies WHERE (tenant_id,partner_id,event_id)=(NEW.tenant_id,NEW.partner_id,NEW.event_id))) OR (NEW.kind='OnboardingApprovalReviewChanged' AND NOT EXISTS(SELECT 1 FROM onboarding_approval_reviews WHERE (tenant_id,partner_id,changed_event_id)=(NEW.tenant_id,NEW.partner_id,NEW.event_id))) THEN RAISE EXCEPTION 'approval event requires complete projection' USING ERRCODE='23514';END IF;RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER onboarding_approval_event_complete AFTER INSERT ON events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN(NEW.kind IN ('OnboardingApprovalPolicyChanged','OnboardingApprovalReviewChanged')) EXECUTE FUNCTION freightctl_onboarding_approval_event_complete();
REVOKE ALL ON FUNCTION freightctl_onboarding_policy_guard(),freightctl_onboarding_review_guard(),freightctl_onboarding_dispatch_approval_guard(),freightctl_onboarding_approval_event_complete() FROM PUBLIC;

-- Account mutations join the policy lock after their existing account lock.
-- Read-only production status must not acquire a writer's account lock: an
-- observer must remain able to see staged work while its transaction is open.
CREATE FUNCTION freightctl_onboarding_authority_lock() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id::text||':'||NEW.partner_id::text||':onboarding-approval-policy',0));
 RETURN NEW;
END $$;
CREATE TRIGGER onboarding_authority_lock BEFORE UPDATE ON credentials FOR EACH ROW EXECUTE FUNCTION freightctl_onboarding_authority_lock();
REVOKE ALL ON FUNCTION freightctl_onboarding_authority_lock() FROM PUBLIC;
