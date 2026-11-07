-- An explicit definition-only disclosure to one independent reviewer. Workflow
-- configurations, files, runs and processing intents retain actor-private RLS.
CREATE TABLE processing_workflow_reviews(
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,actor_id uuid NOT NULL,reviewer_id uuid NOT NULL,review_id uuid NOT NULL,
 workflow_id uuid NOT NULL,workflow_version integer NOT NULL,
 definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object' AND octet_length(definition::text)<=65536),
 definition_hash text NOT NULL CHECK(definition_hash ~ '^[0-9a-f]{64}$'),
 state text NOT NULL CHECK(state IN ('pending','approved','rejected','adopted','withdrawn')),
 revision bigint NOT NULL CHECK(revision>0),adopted_revision bigint NOT NULL CHECK(adopted_revision>=0 AND adopted_revision<=revision),
 created_at timestamptz NOT NULL,expires_at timestamptz NOT NULL,changed_event_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,review_id),CHECK(actor_id<>reviewer_id),
 CHECK((state='adopted') IS NOT TRUE OR adopted_revision>0),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,reviewer_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,workflow_id,workflow_version) REFERENCES workflow_revisions(tenant_id,partner_id,workflow_id,version),
 FOREIGN KEY(tenant_id,partner_id,changed_event_id) REFERENCES events(tenant_id,partner_id,event_id)
);
CREATE UNIQUE INDEX processing_review_open ON processing_workflow_reviews(tenant_id,partner_id,actor_id,workflow_id,workflow_version) WHERE state IN ('pending','approved','adopted');
-- This permanent marker survives withdrawal: there is no fallback to self-approval.
CREATE UNIQUE INDEX processing_review_adopted ON processing_workflow_reviews(tenant_id,partner_id,actor_id,workflow_id,workflow_version) WHERE adopted_revision>0;
CREATE INDEX processing_review_inbox ON processing_workflow_reviews(tenant_id,partner_id,reviewer_id,review_id);
ALTER TABLE processing_workflow_reviews ENABLE ROW LEVEL SECURITY;
ALTER TABLE processing_workflow_reviews FORCE ROW LEVEL SECURITY;
CREATE FUNCTION freightctl_processing_review_reader(t uuid,p uuid,a uuid,r uuid) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT t=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND p=nullif(current_setting('freightctl.partner_id',true),'')::uuid
 AND EXISTS(SELECT 1 FROM credentials c WHERE (c.tenant_id,c.partner_id,c.actor_id)=(t,p,nullif(current_setting('freightctl.actor_id',true),'')::uuid)
 AND c.revoked_at IS NULL AND (c.expires_at IS NULL OR c.expires_at>clock_timestamp())
 AND ((c.actor_id=a AND c.permissions && ARRAY['workflow_manage','workflow_approve','workflow_execute']::text[])
 OR (c.actor_id=r AND c.permissions @> ARRAY['inspect','workflow_approve']::text[])))
$$;
CREATE POLICY scope ON processing_workflow_reviews USING(freightctl_processing_review_reader(tenant_id,partner_id,actor_id,reviewer_id)) WITH CHECK(freightctl_processing_review_reader(tenant_id,partner_id,actor_id,reviewer_id));
REVOKE ALL ON processing_workflow_reviews FROM PUBLIC;
GRANT SELECT,INSERT,UPDATE ON processing_workflow_reviews TO freightctl_runtime;

CREATE FUNCTION freightctl_processing_review_participants(t uuid,p uuid,d jsonb) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT EXISTS(SELECT 1 FROM credentials a JOIN credentials r ON (r.tenant_id,r.partner_id,r.actor_id)=(a.tenant_id,a.partner_id,(d->'reviewer'->>'actor_id')::uuid)
 WHERE (a.tenant_id,a.partner_id,a.actor_id)=(t,p,(d->'author'->>'actor_id')::uuid) AND a.actor_id<>r.actor_id
 AND a.authority_revision::text=d->'author'->>'authority_revision' AND r.authority_revision::text=d->'reviewer'->>'authority_revision'
 AND encode(sha256(convert_to(a.namespace_root,'UTF8')),'hex')=d->'author'->>'namespace_root_digest'
 AND encode(sha256(convert_to(r.namespace_root,'UTF8')),'hex')=d->'reviewer'->>'namespace_root_digest'
 AND a.permissions @> ARRAY['workflow_manage']::text[] AND r.permissions @> ARRAY['inspect','workflow_approve']::text[]
 AND a.revoked_at IS NULL AND r.revoked_at IS NULL
 AND (a.expires_at IS NULL OR a.expires_at>clock_timestamp()) AND (r.expires_at IS NULL OR r.expires_at>clock_timestamp()))
$$;
CREATE FUNCTION freightctl_processing_review_current(t uuid,p uuid,a uuid,w uuid,v integer,h text) RETURNS boolean LANGUAGE plpgsql VOLATILE AS $$
DECLARE r processing_workflow_reviews;
BEGIN
 IF t IS DISTINCT FROM nullif(current_setting('freightctl.tenant_id',true),'')::uuid OR p IS DISTINCT FROM nullif(current_setting('freightctl.partner_id',true),'')::uuid OR a IS DISTINCT FROM nullif(current_setting('freightctl.actor_id',true),'')::uuid
 OR NOT EXISTS(SELECT 1 FROM credentials c WHERE (c.tenant_id,c.partner_id,c.actor_id)=(t,p,a) AND c.permissions && ARRAY['workflow_manage','workflow_approve','workflow_execute']::text[] AND c.revoked_at IS NULL AND (c.expires_at IS NULL OR c.expires_at>clock_timestamp())) THEN RETURN false;END IF;
 SELECT * INTO r FROM processing_workflow_reviews WHERE (tenant_id,partner_id,actor_id,workflow_id,workflow_version)=(t,p,a,w,v) AND adopted_revision>0 FOR SHARE;
 IF NOT FOUND THEN RETURN true;END IF;
 -- Hold both credential revisions through the consequential transaction. This
 -- does not authenticate or act as the reviewer and grants no file access.
 PERFORM 1 FROM credentials WHERE tenant_id=t AND partner_id=p AND actor_id IN (a,r.reviewer_id) ORDER BY actor_id FOR SHARE;
 RETURN r.state='adopted' AND r.definition->'workflow'->>'hash'=h AND r.expires_at>clock_timestamp() AND freightctl_processing_review_participants(t,p,r.definition);
END $$;
REVOKE ALL ON FUNCTION freightctl_processing_review_reader(uuid,uuid,uuid,uuid),freightctl_processing_review_participants(uuid,uuid,jsonb),freightctl_processing_review_current(uuid,uuid,uuid,uuid,integer,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION freightctl_processing_review_reader(uuid,uuid,uuid,uuid),freightctl_processing_review_participants(uuid,uuid,jsonb),freightctl_processing_review_current(uuid,uuid,uuid,uuid,integer,text) TO freightctl_runtime;

CREATE FUNCTION freightctl_processing_review_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE e jsonb;d jsonb;a uuid;w workflow_revisions;n bigint;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'processing reviews and adopted markers are immutable history' USING ERRCODE='23514';END IF;
 a:=nullif(current_setting('freightctl.actor_id',true),'')::uuid;d:=NEW.definition;
 SELECT payload INTO e FROM events WHERE (tenant_id,partner_id,event_id,actor_id,resource_id,kind)=(NEW.tenant_id,NEW.partner_id,NEW.changed_event_id,a,NEW.review_id,'ProcessingWorkflowReviewChanged');
 IF e IS NULL OR e->>'id' IS DISTINCT FROM NEW.review_id::text OR e->'definition' IS DISTINCT FROM d OR e->>'definition_hash' IS DISTINCT FROM NEW.definition_hash OR e->>'state' IS DISTINCT FROM NEW.state OR e->>'revision' IS DISTINCT FROM NEW.revision::text OR e->>'adopted_revision' IS DISTINCT FROM NEW.adopted_revision::text OR (e->>'created_at')::timestamptz IS DISTINCT FROM NEW.created_at THEN RAISE EXCEPTION 'processing review requires its exact actor journal record' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN
  PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id::text||':'||NEW.partner_id::text||':'||NEW.actor_id::text||':processing-reviews',0));
  SELECT count(*) INTO n FROM processing_workflow_reviews WHERE (tenant_id,partner_id,actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id) AND state IN ('pending','approved') AND expires_at>clock_timestamp();
  IF n>=128 THEN RAISE EXCEPTION 'processing review admission full' USING ERRCODE='23514';END IF;
  IF a<>NEW.actor_id OR NEW.state<>'pending' OR NEW.revision<>1 OR NEW.adopted_revision<>0 OR NEW.created_at>clock_timestamp() OR NEW.expires_at<=clock_timestamp() OR NEW.expires_at>NEW.created_at+interval '30 days' OR NOT freightctl_processing_review_participants(NEW.tenant_id,NEW.partner_id,d) THEN RAISE EXCEPTION 'processing review needs current independent participants and bounded lifetime' USING ERRCODE='42501';END IF;
  IF ARRAY(SELECT jsonb_object_keys(d) ORDER BY 1) IS DISTINCT FROM ARRAY['author','definition','expires_at','profile','reviewer','workflow','workflow_revision']::text[] OR d->>'profile' IS DISTINCT FROM 'independent-processing-workflow-review-v1'
  OR d->'author'->>'actor_id' IS DISTINCT FROM NEW.actor_id::text OR d->'reviewer'->>'actor_id' IS DISTINCT FROM NEW.reviewer_id::text
  OR d->'workflow'->>'id' IS DISTINCT FROM NEW.workflow_id::text OR d->'workflow'->>'version' IS DISTINCT FROM NEW.workflow_version::text OR (d->>'expires_at')::timestamptz IS DISTINCT FROM NEW.expires_at THEN RAISE EXCEPTION 'processing review binding changed' USING ERRCODE='23514';END IF;
  SELECT * INTO w FROM workflow_revisions WHERE (tenant_id,partner_id,actor_id,workflow_id,version)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.workflow_id,NEW.workflow_version) FOR SHARE;
  IF w.workflow_id IS NULL OR w.state<>'draft' OR w.revision::text IS DISTINCT FROM d->>'workflow_revision' OR w.definition_hash IS DISTINCT FROM d->'workflow'->>'hash' OR w.definition IS DISTINCT FROM d->'definition' OR w.definition->>'schema_version' IS DISTINCT FROM '3' OR w.definition->'processing'->>'kind' IS DISTINCT FROM 'records.project' OR w.definition->'steps' IS DISTINCT FROM '[]'::jsonb OR w.definition ? 'source' OR w.definition ? 'program' THEN RAISE EXCEPTION 'processing review must disclose one exact owned typed draft only' USING ERRCODE='23514';END IF;
 ELSE
  IF (NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.reviewer_id,NEW.review_id,NEW.workflow_id,NEW.workflow_version,NEW.definition,NEW.definition_hash,NEW.created_at,NEW.expires_at) IS DISTINCT FROM (OLD.tenant_id,OLD.partner_id,OLD.actor_id,OLD.reviewer_id,OLD.review_id,OLD.workflow_id,OLD.workflow_version,OLD.definition,OLD.definition_hash,OLD.created_at,OLD.expires_at) OR NEW.revision<>OLD.revision+1 THEN RAISE EXCEPTION 'processing review meaning is immutable' USING ERRCODE='23514';END IF;
  IF NEW.state='withdrawn' AND OLD.state IN ('pending','approved','adopted') THEN
   IF NEW.adopted_revision<>OLD.adopted_revision OR NOT ((a=NEW.actor_id AND EXISTS(SELECT 1 FROM credentials c WHERE (c.tenant_id,c.partner_id,c.actor_id)=(NEW.tenant_id,NEW.partner_id,a) AND 'workflow_manage'=ANY(c.permissions))) OR (a=NEW.reviewer_id AND EXISTS(SELECT 1 FROM credentials c WHERE (c.tenant_id,c.partner_id,c.actor_id)=(NEW.tenant_id,NEW.partner_id,a) AND c.permissions @> ARRAY['inspect','workflow_approve']::text[]))) THEN RAISE EXCEPTION 'withdrawal requires named owner or reviewer and preserves adoption' USING ERRCODE='42501';END IF;
  ELSIF NEW.state IN ('approved','rejected') AND OLD.state='pending' THEN
   IF a<>NEW.reviewer_id OR NEW.adopted_revision<>0 OR NEW.expires_at<=clock_timestamp() OR NOT freightctl_processing_review_participants(NEW.tenant_id,NEW.partner_id,d) THEN RAISE EXCEPTION 'decision requires exact current independent reviewer' USING ERRCODE='42501';END IF;
  ELSIF NEW.state='adopted' AND OLD.state='approved' THEN
   SELECT * INTO w FROM workflow_revisions WHERE (tenant_id,partner_id,actor_id,workflow_id,version)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.workflow_id,NEW.workflow_version) FOR UPDATE;
   IF a<>NEW.actor_id OR OLD.adopted_revision<>0 OR NEW.adopted_revision<>NEW.revision OR NEW.expires_at<=clock_timestamp() OR NOT freightctl_processing_review_participants(NEW.tenant_id,NEW.partner_id,d) OR w.workflow_id IS NULL OR w.state<>'draft' OR w.revision::text IS DISTINCT FROM d->>'workflow_revision' OR w.definition_hash IS DISTINCT FROM d->'workflow'->>'hash' OR w.definition IS DISTINCT FROM d->'definition' THEN RAISE EXCEPTION 'adoption requires current exact approved review and original draft' USING ERRCODE='42501';END IF;
  ELSE RAISE EXCEPTION 'invalid processing review transition' USING ERRCODE='23514';END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER processing_review_guard BEFORE INSERT OR UPDATE OR DELETE ON processing_workflow_reviews FOR EACH ROW EXECUTE FUNCTION freightctl_processing_review_guard();

CREATE FUNCTION freightctl_processing_review_membership() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_TABLE_NAME='events' THEN
  IF NOT EXISTS(SELECT 1 FROM processing_workflow_reviews r WHERE (r.tenant_id,r.partner_id,r.review_id,r.changed_event_id)=(NEW.tenant_id,NEW.partner_id,NEW.resource_id,NEW.event_id)) THEN RAISE EXCEPTION 'review event requires its exact projection' USING ERRCODE='23514';END IF;
 ELSIF NEW.adopted_revision>0 AND NEW.state='adopted' THEN
  IF NOT EXISTS(SELECT 1 FROM workflow_revisions w WHERE (w.tenant_id,w.partner_id,w.actor_id,w.workflow_id,w.version,w.definition_hash,w.state)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.workflow_id,NEW.workflow_version,NEW.definition->'workflow'->>'hash','approved') AND w.revision=(NEW.definition->>'workflow_revision')::bigint+1 AND w.approval_authority=(NEW.definition->'author'->>'authority_revision')::bigint) THEN RAISE EXCEPTION 'adoption and exact workflow approval must commit together' USING ERRCODE='23514';END IF;
 END IF;RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER processing_review_event_complete AFTER INSERT ON events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN(NEW.kind='ProcessingWorkflowReviewChanged') EXECUTE FUNCTION freightctl_processing_review_membership();
CREATE CONSTRAINT TRIGGER processing_review_adoption_complete AFTER INSERT OR UPDATE ON processing_workflow_reviews DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION freightctl_processing_review_membership();

CREATE FUNCTION freightctl_processing_review_effect_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE w uuid;v integer;h text;b jsonb;current_actor uuid;
BEGIN
 current_actor:=nullif(current_setting('freightctl.actor_id',true),'')::uuid;
 IF TG_TABLE_NAME='workflow_revisions' THEN
  IF NEW.definition->>'schema_version'<>'3' OR NEW.state<>'approved' THEN RETURN NEW;END IF;
  w:=NEW.workflow_id;v:=NEW.version;h:=NEW.definition_hash;
  IF TG_OP='UPDATE' AND OLD.state='draft' AND NOT EXISTS(SELECT 1 FROM processing_workflow_reviews r WHERE (r.tenant_id,r.partner_id,r.actor_id,r.workflow_id,r.workflow_version)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,w,v) AND r.adopted_revision>0)
  AND NOT EXISTS(SELECT 1 FROM credentials c WHERE (c.tenant_id,c.partner_id,c.actor_id)=(NEW.tenant_id,NEW.partner_id,current_actor) AND c.actor_id=NEW.actor_id AND c.authority_revision=NEW.approval_authority AND 'workflow_approve'=ANY(c.permissions) AND c.revoked_at IS NULL AND (c.expires_at IS NULL OR c.expires_at>clock_timestamp())) THEN RAISE EXCEPTION 'processing approval requires ordinary approval permission or exact independent adoption' USING ERRCODE='42501';END IF;
 ELSIF TG_TABLE_NAME='workflow_runs' THEN
  IF NEW.state NOT IN ('queued','running','succeeded') THEN RETURN NEW;END IF;
  IF NOT EXISTS(SELECT 1 FROM workflow_revisions c WHERE (c.tenant_id,c.partner_id,c.actor_id,c.workflow_id,c.version)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.workflow_id,NEW.workflow_version) AND c.definition->>'schema_version'='3') THEN RETURN NEW;END IF;
  w:=NEW.workflow_id;v:=NEW.workflow_version;h:=NEW.workflow_hash;
 ELSE
  IF NEW.definition->>'schema_version'<>'2' OR NOT (NEW.definition ? 'workflow') OR NEW.state IN ('cancelled','failed') THEN RETURN NEW;END IF;
  b:=NEW.definition->'workflow';w:=(b->>'workflow_id')::uuid;v:=(b->>'workflow_version')::integer;h:=b->>'workflow_hash';
 END IF;
 IF NOT freightctl_processing_review_current(NEW.tenant_id,NEW.partner_id,NEW.actor_id,w,v,h) THEN RAISE EXCEPTION 'independent processing approval expired,withdrawn or authority changed' USING ERRCODE='42501';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER processing_review_configuration_gate BEFORE INSERT OR UPDATE ON workflow_revisions FOR EACH ROW EXECUTE FUNCTION freightctl_processing_review_effect_guard();
CREATE TRIGGER processing_review_run_gate BEFORE INSERT OR UPDATE ON workflow_runs FOR EACH ROW EXECUTE FUNCTION freightctl_processing_review_effect_guard();
CREATE TRIGGER processing_review_projection_gate BEFORE INSERT OR UPDATE ON record_projections FOR EACH ROW EXECUTE FUNCTION freightctl_processing_review_effect_guard();
REVOKE ALL ON FUNCTION freightctl_processing_review_guard(),freightctl_processing_review_membership(),freightctl_processing_review_effect_guard() FROM PUBLIC;
