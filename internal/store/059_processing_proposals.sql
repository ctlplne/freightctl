-- Third-party definition authorship transfers no byte,approval or effect grant.
-- The named executor records an owned draft through the ordinary workflow seam.
CREATE TABLE processing_workflow_proposals(
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,actor_id uuid NOT NULL,executor_id uuid NOT NULL,proposal_id uuid NOT NULL,
 definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object' AND octet_length(definition::text)<=65536),
 definition_hash text NOT NULL CHECK(definition_hash ~ '^[0-9a-f]{64}$'),
 state text NOT NULL CHECK(state IN ('pending','adopted','rejected','withdrawn')),revision bigint NOT NULL CHECK(revision>0),
 adopted_workflow_id uuid,adopted_workflow_version integer,adopted_workflow_hash text,
 created_at timestamptz NOT NULL,expires_at timestamptz NOT NULL,changed_event_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,proposal_id),CHECK(actor_id<>executor_id),
 CHECK((state='adopted')=(adopted_workflow_id IS NOT NULL)),
 CHECK((adopted_workflow_id IS NULL AND adopted_workflow_version IS NULL AND adopted_workflow_hash IS NULL)
 OR (adopted_workflow_id IS NOT NULL AND adopted_workflow_version IS NOT NULL AND adopted_workflow_hash IS NOT NULL AND adopted_workflow_version>0 AND adopted_workflow_hash ~ '^[0-9a-f]{64}$')),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,executor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,adopted_workflow_id,adopted_workflow_version) REFERENCES workflow_revisions(tenant_id,partner_id,workflow_id,version),
 FOREIGN KEY(tenant_id,partner_id,changed_event_id) REFERENCES events(tenant_id,partner_id,event_id)
);
CREATE INDEX processing_proposal_inbox ON processing_workflow_proposals(tenant_id,partner_id,executor_id,proposal_id);
ALTER TABLE processing_workflow_proposals ENABLE ROW LEVEL SECURITY;
ALTER TABLE processing_workflow_proposals FORCE ROW LEVEL SECURITY;
CREATE FUNCTION freightctl_processing_proposal_reader(t uuid,p uuid,a uuid,e uuid) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT coalesce(t=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND p=nullif(current_setting('freightctl.partner_id',true),'')::uuid
 AND EXISTS(SELECT 1 FROM credentials c WHERE (c.tenant_id,c.partner_id,c.actor_id)=(t,p,nullif(current_setting('freightctl.actor_id',true),'')::uuid)
 AND c.actor_id IN (a,e) AND 'workflow_manage'=ANY(c.permissions) AND c.revoked_at IS NULL AND (c.expires_at IS NULL OR c.expires_at>clock_timestamp())),false)
$$;
CREATE POLICY scope ON processing_workflow_proposals USING(freightctl_processing_proposal_reader(tenant_id,partner_id,actor_id,executor_id)) WITH CHECK(freightctl_processing_proposal_reader(tenant_id,partner_id,actor_id,executor_id));
REVOKE ALL ON processing_workflow_proposals FROM PUBLIC;
GRANT SELECT,INSERT,UPDATE ON processing_workflow_proposals TO freightctl_runtime;

CREATE FUNCTION freightctl_processing_proposal_participants(t uuid,p uuid,d jsonb) RETURNS boolean LANGUAGE plpgsql VOLATILE AS $$
BEGIN
 IF t IS DISTINCT FROM nullif(current_setting('freightctl.tenant_id',true),'')::uuid OR p IS DISTINCT FROM nullif(current_setting('freightctl.partner_id',true),'')::uuid THEN RETURN false;END IF;
 PERFORM 1 FROM credentials WHERE tenant_id=t AND partner_id=p AND actor_id IN ((d->'author'->>'actor_id')::uuid,(d->'executor'->>'actor_id')::uuid) ORDER BY actor_id FOR SHARE;
 RETURN EXISTS(SELECT 1 FROM credentials a JOIN credentials e ON (e.tenant_id,e.partner_id,e.actor_id)=(a.tenant_id,a.partner_id,(d->'executor'->>'actor_id')::uuid)
 WHERE (a.tenant_id,a.partner_id,a.actor_id)=(t,p,(d->'author'->>'actor_id')::uuid) AND a.actor_id<>e.actor_id
 AND d->'author'->>'tenant_id'=t::text AND d->'author'->>'partner_id'=p::text AND d->'executor'->>'tenant_id'=t::text AND d->'executor'->>'partner_id'=p::text
 AND a.authority_revision::text=d->'author'->>'authority_revision' AND e.authority_revision::text=d->'executor'->>'authority_revision'
 AND encode(sha256(convert_to(a.namespace_root,'UTF8')),'hex')=d->'author'->>'root_policy_digest' AND encode(sha256(convert_to(e.namespace_root,'UTF8')),'hex')=d->'executor'->>'root_policy_digest'
 AND a.permissions @> ARRAY['workflow_manage']::text[] AND e.permissions @> ARRAY['workflow_manage','read','write','check_run','workflow_execute']::text[]
 AND a.revoked_at IS NULL AND e.revoked_at IS NULL AND (a.expires_at IS NULL OR a.expires_at>clock_timestamp()) AND (e.expires_at IS NULL OR e.expires_at>clock_timestamp()));
END $$;
REVOKE ALL ON FUNCTION freightctl_processing_proposal_reader(uuid,uuid,uuid,uuid),freightctl_processing_proposal_participants(uuid,uuid,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION freightctl_processing_proposal_reader(uuid,uuid,uuid,uuid),freightctl_processing_proposal_participants(uuid,uuid,jsonb) TO freightctl_runtime;

CREATE FUNCTION freightctl_processing_proposal_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE a uuid;e jsonb;d jsonb;party jsonb;c credentials;expected jsonb;n bigint;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'processing proposals retain immutable history' USING ERRCODE='23514';END IF;
 a:=nullif(current_setting('freightctl.actor_id',true),'')::uuid;d:=NEW.definition;
 SELECT * INTO c FROM credentials WHERE (tenant_id,partner_id,actor_id)=(NEW.tenant_id,NEW.partner_id,a);
 IF c.actor_id IS NULL OR c.revoked_at IS NOT NULL OR c.expires_at<=clock_timestamp() OR NOT c.permissions @> ARRAY['workflow_manage']::text[] OR a NOT IN (NEW.actor_id,NEW.executor_id)
 THEN RAISE EXCEPTION 'proposal requires named current workflow management authority' USING ERRCODE='42501';END IF;
 party:=CASE WHEN a=NEW.actor_id THEN d->'author' ELSE d->'executor' END;
 IF party->>'actor_id' IS DISTINCT FROM a::text OR party->>'tenant_id' IS DISTINCT FROM NEW.tenant_id::text OR party->>'partner_id' IS DISTINCT FROM NEW.partner_id::text
 OR party->>'authority_revision' IS DISTINCT FROM c.authority_revision::text OR party->>'root_policy_digest' IS DISTINCT FROM encode(sha256(convert_to(c.namespace_root,'UTF8')),'hex')
 THEN RAISE EXCEPTION 'proposal participant context changed' USING ERRCODE='23514';END IF;
 SELECT payload INTO e FROM events WHERE (tenant_id,partner_id,event_id,actor_id,resource_id,kind)=(NEW.tenant_id,NEW.partner_id,NEW.changed_event_id,a,NEW.proposal_id,'ProcessingWorkflowProposalChanged');
 expected:=jsonb_build_object('id',NEW.proposal_id::text,'definition',d,'definition_hash',NEW.definition_hash,'state',NEW.state,'revision',NEW.revision);
 IF NEW.adopted_workflow_id IS NOT NULL THEN expected:=expected||jsonb_build_object('adopted_workflow',jsonb_build_object('id',NEW.adopted_workflow_id::text,'version',NEW.adopted_workflow_version,'hash',NEW.adopted_workflow_hash));END IF;
 IF e IS NULL OR e-'created_at' IS DISTINCT FROM expected OR (e->>'created_at')::timestamptz IS DISTINCT FROM NEW.created_at
 THEN RAISE EXCEPTION 'proposal requires its exact immutable event' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN
  PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id::text||':'||NEW.partner_id::text||':processing-proposals:'||NEW.actor_id::text,0));
  SELECT count(*) INTO n FROM processing_workflow_proposals WHERE (tenant_id,partner_id,actor_id,state)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,'pending') AND expires_at>clock_timestamp();
  IF a<>NEW.actor_id OR NEW.state<>'pending' OR NEW.revision<>1 OR NEW.adopted_workflow_id IS NOT NULL OR n>=16
  OR ARRAY(SELECT jsonb_object_keys(d) ORDER BY 1) IS DISTINCT FROM ARRAY['author','definition','executor','expires_at','profile','workflow_definition_hash']::text[]
  OR d->>'profile' IS DISTINCT FROM 'processing-workflow-proposal-v1' OR d->>'workflow_definition_hash' !~ '^[0-9a-f]{64}$'
  OR d->'author'->>'actor_id' IS DISTINCT FROM NEW.actor_id::text OR d->'executor'->>'actor_id' IS DISTINCT FROM NEW.executor_id::text
  OR (d->>'expires_at')::timestamptz IS DISTINCT FROM NEW.expires_at OR NEW.expires_at<=clock_timestamp() OR NEW.expires_at>NEW.created_at+interval '30 days'
  OR freightctl_processing_proposal_participants(NEW.tenant_id,NEW.partner_id,d) IS DISTINCT FROM true
  OR ARRAY(SELECT jsonb_object_keys(d->'definition') ORDER BY 1) IS DISTINCT FROM ARRAY['name','processing','schema_version','steps']::text[]
  OR d->'definition'->>'schema_version' IS DISTINCT FROM '3' OR d->'definition'->'steps' IS DISTINCT FROM '[]'::jsonb
  OR d->'definition'->'processing'->>'kind' IS DISTINCT FROM 'records.project' OR d->'definition'->'processing'->'definition'->>'engine' IS DISTINCT FROM 'freightctl-record-projection-v1'
  THEN RAISE EXCEPTION 'proposal requires bounded typed rules and exact independent participants' USING ERRCODE='23514';END IF;
 ELSE
  IF (NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.executor_id,NEW.proposal_id,NEW.definition,NEW.definition_hash,NEW.created_at,NEW.expires_at) IS DISTINCT FROM (OLD.tenant_id,OLD.partner_id,OLD.actor_id,OLD.executor_id,OLD.proposal_id,OLD.definition,OLD.definition_hash,OLD.created_at,OLD.expires_at)
  OR OLD.state<>'pending' OR NEW.revision<>OLD.revision+1 OR NOT ((NEW.state='withdrawn' AND a=NEW.actor_id AND NEW.adopted_workflow_id IS NULL) OR (NEW.state='rejected' AND a=NEW.executor_id AND NEW.adopted_workflow_id IS NULL) OR (NEW.state='adopted' AND a=NEW.executor_id AND NEW.adopted_workflow_id IS NOT NULL))
  THEN RAISE EXCEPTION 'proposal transition cannot change rules,participants or terminal history' USING ERRCODE='23514';END IF;
  IF NEW.state='adopted' AND (NEW.expires_at<=clock_timestamp() OR freightctl_processing_proposal_participants(NEW.tenant_id,NEW.partner_id,d) IS DISTINCT FROM true OR NEW.adopted_workflow_hash IS DISTINCT FROM d->>'workflow_definition_hash')
  THEN RAISE EXCEPTION 'adoption requires current unexpired proposal and complete task hash' USING ERRCODE='23514';END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER processing_proposal_guard BEFORE INSERT OR UPDATE OR DELETE ON processing_workflow_proposals FOR EACH ROW EXECUTE FUNCTION freightctl_processing_proposal_guard();

CREATE FUNCTION freightctl_processing_proposal_complete() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.state='adopted' AND NOT EXISTS(SELECT 1 FROM workflow_revisions w WHERE (w.tenant_id,w.partner_id,w.actor_id,w.workflow_id,w.version,w.definition_hash,w.state,w.revision,w.approval_authority)=(NEW.tenant_id,NEW.partner_id,NEW.executor_id,NEW.adopted_workflow_id,NEW.adopted_workflow_version,NEW.adopted_workflow_hash,'draft',1,0) AND w.definition=NEW.definition->'definition')
 THEN RAISE EXCEPTION 'proposal adoption must commit an exact executor-owned unapproved draft' USING ERRCODE='23514';END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER processing_proposal_complete AFTER INSERT OR UPDATE ON processing_workflow_proposals DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION freightctl_processing_proposal_complete();
CREATE FUNCTION freightctl_processing_proposal_event_complete() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.kind='ProcessingWorkflowProposalChanged' AND NOT EXISTS(SELECT 1 FROM processing_workflow_proposals p WHERE (p.tenant_id,p.partner_id,p.proposal_id,p.changed_event_id)=(NEW.tenant_id,NEW.partner_id,NEW.resource_id,NEW.event_id))
 THEN RAISE EXCEPTION 'proposal event must commit its exact read model' USING ERRCODE='23514';END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER processing_proposal_event_complete AFTER INSERT ON events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION freightctl_processing_proposal_event_complete();
REVOKE ALL ON FUNCTION freightctl_processing_proposal_guard(),freightctl_processing_proposal_complete(),freightctl_processing_proposal_event_complete() FROM PUBLIC;
