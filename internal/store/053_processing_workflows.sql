-- One approved processing task creates a separate held artifact, never delivery.
CREATE TABLE workflow_processing (
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,actor_id uuid NOT NULL,
 run_id uuid NOT NULL,projection_id uuid NOT NULL,definition_hash text NOT NULL CHECK(definition_hash ~ '^[0-9a-f]{64}$'),created_event_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,run_id),UNIQUE(tenant_id,partner_id,projection_id),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,run_id) REFERENCES workflow_runs(tenant_id,partner_id,run_id),
 FOREIGN KEY(tenant_id,partner_id,projection_id) REFERENCES record_projections(tenant_id,partner_id,projection_id),
 FOREIGN KEY(tenant_id,partner_id,created_event_id) REFERENCES events(tenant_id,partner_id,event_id)
);
ALTER TABLE workflow_processing ENABLE ROW LEVEL SECURITY;
ALTER TABLE workflow_processing FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON workflow_processing USING(tenant_id=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND partner_id=nullif(current_setting('freightctl.partner_id',true),'')::uuid AND actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND partner_id=nullif(current_setting('freightctl.partner_id',true),'')::uuid AND actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid);
GRANT SELECT,INSERT ON workflow_processing TO freightctl_runtime;

CREATE FUNCTION freightctl_processing_current(t uuid,p uuid,a uuid,d jsonb,live boolean) RETURNS void LANGUAGE plpgsql AS $$
DECLARE w workflow_revisions;r workflow_runs;c credentials;b jsonb;task jsonb;context jsonb;
BEGIN
 b:=d->'workflow';context:=d->'plan'->'context';
 SELECT * INTO w FROM workflow_revisions WHERE (tenant_id,partner_id,actor_id,workflow_id,version)=(t,p,a,(b->>'workflow_id')::uuid,(b->>'workflow_version')::integer);
 IF live THEN
  PERFORM 1 FROM workflow_revisions WHERE (tenant_id,partner_id,workflow_id,version)=(t,p,w.workflow_id,w.version) FOR SHARE;
  -- Re-read after acquiring the lock; a concurrent revocation must be observed.
  SELECT * INTO w FROM workflow_revisions WHERE (tenant_id,partner_id,actor_id,workflow_id,version)=(t,p,a,(b->>'workflow_id')::uuid,(b->>'workflow_version')::integer);
 END IF;
 SELECT * INTO r FROM workflow_runs WHERE (tenant_id,partner_id,actor_id,run_id)=(t,p,a,(b->>'run_id')::uuid);
 SELECT * INTO c FROM credentials WHERE (tenant_id,partner_id,actor_id)=(t,p,a);
 task:=w.definition->'processing';
 IF d->>'schema_version' IS DISTINCT FROM '2' OR d->'plan'->>'profile' IS DISTINCT FROM 'scoped-record-projection-v1'
 OR w.workflow_id IS NULL OR r.run_id IS NULL OR c.actor_id IS NULL
 OR a IS DISTINCT FROM nullif(current_setting('freightctl.actor_id',true),'')::uuid
 OR c.revoked_at IS NOT NULL OR c.expires_at<=clock_timestamp()
 OR NOT c.permissions @> ARRAY['read','write','check_run','workflow_execute']::text[]
 OR c.namespace_root IS DISTINCT FROM context->>'namespace_root' OR c.authority_revision::text IS DISTINCT FROM context->>'authority_revision'
 OR w.definition->>'schema_version' IS DISTINCT FROM '3' OR task->>'kind' IS DISTINCT FROM 'records.project'
 OR w.definition_hash IS DISTINCT FROM b->>'workflow_hash' OR w.approval_authority<>c.authority_revision
 OR task->>'id' IS DISTINCT FROM b->>'step_id' OR task->'definition' IS DISTINCT FROM d->'plan'->'projection'
 OR task->'output_policy' IS DISTINCT FROM context->'policy' OR task->>'reason' IS DISTINCT FROM context->>'reason'
 OR coalesce(task->>'target_path','') IS DISTINCT FROM coalesce(context->'target'->'command'->>'path','')
 OR (r.workflow_id,r.workflow_version,r.workflow_hash) IS DISTINCT FROM (w.workflow_id,w.version,w.definition_hash)
 OR r.file_id::text IS DISTINCT FROM context->'source'->'file'->>'id' OR r.source IS DISTINCT FROM context->'source'->'file'
 OR r.namespace_root IS DISTINCT FROM c.namespace_root OR r.authority_revision<>c.authority_revision
 OR r.storage_id::text IS DISTINCT FROM context->>'storage_id'
 OR (live AND (w.state<>'approved' OR r.state='cancelled'))
 THEN RAISE EXCEPTION 'processing requires exact approved task,run,source and current scope' USING ERRCODE='23514'; END IF;
END $$;
REVOKE ALL ON FUNCTION freightctl_processing_current(uuid,uuid,uuid,jsonb,boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION freightctl_processing_current(uuid,uuid,uuid,jsonb,boolean) TO freightctl_runtime;

CREATE FUNCTION freightctl_processing_binding_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE e jsonb;p record_projections;r workflow_runs;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'processing bindings are immutable' USING ERRCODE='23514'; END IF;
 SELECT payload INTO e FROM events WHERE (tenant_id,partner_id,actor_id,event_id,resource_id,kind)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.created_event_id,NEW.run_id,'WorkflowProcessingBound');
 SELECT * INTO p FROM record_projections WHERE (tenant_id,partner_id,actor_id,projection_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.projection_id);
 SELECT * INTO r FROM workflow_runs WHERE (tenant_id,partner_id,actor_id,run_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.run_id);
 IF e IS DISTINCT FROM jsonb_build_object('run_id',NEW.run_id::text,'projection_id',NEW.projection_id::text,'definition_hash',NEW.definition_hash)
 OR p.projection_id IS NULL OR r.run_id IS NULL OR p.definition_hash<>NEW.definition_hash
 OR p.definition->'workflow'->>'run_id' IS DISTINCT FROM NEW.run_id::text
 OR p.state<>'approved' OR p.revision<>1 OR p.attempts<>0 OR r.state<>'queued' OR r.revision<>1
 THEN RAISE EXCEPTION 'processing binding requires exact initial run,intent and event' USING ERRCODE='23514'; END IF;
 PERFORM freightctl_processing_current(NEW.tenant_id,NEW.partner_id,NEW.actor_id,p.definition,true);
 RETURN NEW;
END $$;
CREATE TRIGGER processing_binding_guard BEFORE INSERT OR UPDATE OR DELETE ON workflow_processing FOR EACH ROW EXECUTE FUNCTION freightctl_processing_binding_guard();

CREATE FUNCTION freightctl_processing_membership_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.definition->>'schema_version'='2' THEN
  IF NOT EXISTS(SELECT 1 FROM workflow_processing b WHERE (b.tenant_id,b.partner_id,b.actor_id,b.projection_id,b.definition_hash)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.projection_id,NEW.definition_hash) AND b.run_id::text=NEW.definition->'workflow'->>'run_id')
  THEN RAISE EXCEPTION 'workflow processing intent must bind atomically to its run' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER processing_membership AFTER INSERT OR UPDATE ON record_projections DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION freightctl_processing_membership_guard();

-- Legacy workflows remain root-only. Schema3 binds the actor's exact root.
ALTER TABLE workflow_runs DROP CONSTRAINT workflow_runs_namespace_root_check;
ALTER TABLE workflow_runs ADD CONSTRAINT workflow_runs_namespace_root_check CHECK(namespace_root LIKE '/%' AND octet_length(namespace_root)<=4096);
REVOKE ALL ON FUNCTION freightctl_processing_binding_guard(),freightctl_processing_membership_guard() FROM PUBLIC;

CREATE OR REPLACE FUNCTION freightctl_projection_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE e jsonb; valid boolean:=false;
BEGIN
 IF freightctl_projection_actor_current(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.definition->'plan') IS DISTINCT FROM true THEN RAISE EXCEPTION 'projection actor profile or namespace changed' USING ERRCODE='23514'; END IF;
 IF NEW.definition->>'schema_version'='1' AND NEW.definition->'plan'->>'profile'='scoped-record-projection-v1' AND NOT EXISTS(SELECT 1 FROM credentials c WHERE (c.tenant_id,c.partner_id,c.actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id) AND CASE WHEN NEW.state IN ('proposed','cancelled') THEN 'workflow_manage' WHEN NEW.state='approved' THEN 'workflow_approve' ELSE 'workflow_execute' END=ANY(c.permissions)) THEN RAISE EXCEPTION 'scoped projection action requires its workflow grant' USING ERRCODE='23514'; END IF;
 SELECT payload INTO e FROM events WHERE (tenant_id,partner_id,event_id,actor_id,resource_id,kind)=(NEW.tenant_id,NEW.partner_id,NEW.changed_event_id,NEW.actor_id,NEW.projection_id,'RecordProjectionChanged');
 IF NOT (e ? 'lease_until') OR (e->>'lease_until')::timestamptz IS DISTINCT FROM NEW.lease_until OR e-'lease_until' IS DISTINCT FROM jsonb_build_object('id',NEW.projection_id::text,'source_file_id',NEW.source_file_id::text,'definition',NEW.definition,'definition_hash',NEW.definition_hash,'state',NEW.state,'revision',NEW.revision,'attempts',NEW.attempts,'worker_id',coalesce(NEW.worker_id::text,''),'new_file_id',coalesce(NEW.new_file_id::text,''),'result',NEW.result)
 THEN RAISE EXCEPTION 'projection requires its exact immutable event' USING ERRCODE='23514'; END IF;
 IF NEW.definition->>'schema_version' NOT IN ('1','2') OR ((NEW.definition->>'schema_version'='2') IS DISTINCT FROM (NEW.definition ? 'workflow')) OR jsonb_typeof(NEW.definition->'staging_slots') IS DISTINCT FROM 'array' OR jsonb_array_length(NEW.definition->'staging_slots') IS DISTINCT FROM 3
 THEN RAISE EXCEPTION 'projection requires three preapproved slots' USING ERRCODE='23514'; END IF;
 IF TG_OP='INSERT' THEN
  PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id::text||':'||NEW.partner_id::text||':'||NEW.actor_id::text||':record-projections',0));
  valid:=((NEW.definition->>'schema_version'='1' AND NEW.state='proposed') OR (NEW.definition->>'schema_version'='2' AND NEW.state='approved')) AND NEW.revision=1 AND NEW.attempts=0;
  IF (SELECT count(*) FROM record_projections WHERE actor_id=NEW.actor_id AND state IN ('proposed','approved','running','failed'))>=16 THEN RAISE EXCEPTION 'projection queue saturated' USING ERRCODE='23514'; END IF;
 ELSE
  IF (NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.projection_id,NEW.source_file_id,NEW.definition,NEW.definition_hash) IS DISTINCT FROM (OLD.tenant_id,OLD.partner_id,OLD.actor_id,OLD.projection_id,OLD.source_file_id,OLD.definition,OLD.definition_hash) OR NEW.revision<>OLD.revision+1 THEN RAISE EXCEPTION 'projection definition immutable' USING ERRCODE='23514'; END IF;
  IF NEW.state='approved' THEN valid:=OLD.state='proposed' AND NEW.attempts=0;
  ELSIF NEW.state='running' THEN valid:=(OLD.state IN ('approved','failed') OR (OLD.state='running' AND OLD.lease_until<=clock_timestamp())) AND NEW.attempts=OLD.attempts+1 AND NEW.worker_id IS NOT NULL AND NEW.lease_until>clock_timestamp() AND NEW.lease_until<=clock_timestamp()+interval '71 seconds';
  ELSIF NEW.state='cancelled' THEN valid:=(OLD.state IN ('proposed','approved','failed') OR (OLD.state='running' AND OLD.lease_until<=clock_timestamp())) AND NEW.attempts=OLD.attempts;
  ELSIF NEW.state IN ('failed','completed') THEN valid:=OLD.state='running' AND OLD.lease_until>clock_timestamp() AND NEW.attempts=OLD.attempts AND NEW.result->'attempt' IS NOT DISTINCT FROM jsonb_build_object('projection_id',OLD.projection_id::text,'attempt',OLD.attempts,'worker_id',OLD.worker_id::text);
  END IF;
 END IF;
 IF valid IS DISTINCT FROM true THEN RAISE EXCEPTION 'invalid or unfenced projection transition' USING ERRCODE='23514'; END IF;
 IF NEW.definition->>'schema_version'='2' THEN PERFORM freightctl_processing_current(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.definition,NEW.state NOT IN ('cancelled','failed')); END IF;
 IF NEW.state NOT IN ('cancelled','failed') THEN PERFORM freightctl_projection_current(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.source_file_id,NEW.definition->'plan'); END IF;
 IF NEW.state='completed' THEN
  IF NEW.result->>'kind' IS DISTINCT FROM 'record_projection_output' OR NEW.result->>'acceptance' IS DISTINCT FROM 'durable-held-pending-checks-and-release'
  OR NOT EXISTS(SELECT 1 FROM record_projection_slots s JOIN files f ON (f.tenant_id,f.partner_id,f.file_id)=(s.tenant_id,s.partner_id,s.file_id)
   JOIN file_checks c ON (c.tenant_id,c.partner_id,c.file_id)=(f.tenant_id,f.partner_id,f.file_id)
   WHERE (s.tenant_id,s.partner_id,s.projection_id,s.file_id)=(NEW.tenant_id,NEW.partner_id,NEW.projection_id,NEW.new_file_id)
   AND NEW.result->'file'=jsonb_build_object('id',f.file_id::text,'size_bytes',f.size_bytes,'sha256',f.sha256,'policy',f.policy,'accepted_event_id',f.accepted_event_id::text)
   AND c.state='held' AND c.attempts=0 AND c.report='{}'::jsonb AND c.report_hash=''
   AND c.policy_hash=NEW.definition->'plan'->'context'->'policy'->>'hash'
   AND c.binding->>'storage_id'=NEW.definition->'plan'->'context'->>'storage_id'
   AND c.binding->>'namespace_root'=NEW.definition->'plan'->'context'->>'namespace_root'
   AND c.binding->>'authority_revision'=NEW.definition->'plan'->'context'->>'authority_revision'
   AND c.binding->'target' IS NOT DISTINCT FROM CASE WHEN NEW.definition->'plan'->'context' ? 'target' THEN NEW.definition->'plan'->'context'->'target'->'command'||jsonb_build_object('file_id',f.file_id::text) ELSE 'null'::jsonb END
   AND NOT EXISTS(SELECT 1 FROM file_signatures sig WHERE (sig.tenant_id,sig.partner_id,sig.file_id)=(f.tenant_id,f.partner_id,f.file_id)))
  THEN RAISE EXCEPTION 'projection completion requires atomic fresh held output' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION freightctl_run_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE p jsonb;d jsonb;facts jsonb;expected jsonb;
BEGIN
 SELECT payload INTO p FROM events WHERE (tenant_id,partner_id,event_id)=(NEW.tenant_id,NEW.partner_id,NEW.changed_event_id) AND actor_id=NEW.actor_id AND resource_id=NEW.run_id AND kind='WorkflowRunChanged';
 IF p IS NULL OR p->>'id' IS DISTINCT FROM NEW.run_id::text OR p->>'workflow_id' IS DISTINCT FROM NEW.workflow_id::text OR p->>'workflow_version' IS DISTINCT FROM NEW.workflow_version::text OR p->>'workflow_hash' IS DISTINCT FROM NEW.workflow_hash OR p->>'file_id' IS DISTINCT FROM NEW.file_id::text OR p->'source' IS DISTINCT FROM NEW.source OR p->>'storage_id' IS DISTINCT FROM NEW.storage_id::text OR p->>'namespace_root' IS DISTINCT FROM NEW.namespace_root OR p->>'authority_revision' IS DISTINCT FROM NEW.authority_revision::text OR p->>'state' IS DISTINCT FROM NEW.state OR p->>'reason' IS DISTINCT FROM NEW.reason OR p->>'revision' IS DISTINCT FROM NEW.revision::text THEN
  RAISE EXCEPTION 'workflow run requires its exact event' USING ERRCODE='23514';END IF;
 IF NEW.execution_plan IS DISTINCT FROM p->'execution_plan' OR coalesce(NEW.execution_plan_hash,'') IS DISTINCT FROM coalesce(p->>'execution_plan_hash','') THEN RAISE EXCEPTION 'run plan requires its exact journal record' USING ERRCODE='23514';END IF;
 IF coalesce(NEW.routing_authorization_id::text,'') IS DISTINCT FROM coalesce(p->>'routing_authorization_id','') THEN RAISE EXCEPTION 'routing reference needs its exact journal record' USING ERRCODE='23514';END IF;
 IF TG_OP='UPDATE' AND NEW.routing_authorization_id IS DISTINCT FROM OLD.routing_authorization_id THEN RAISE EXCEPTION 'run routing authorization is immutable' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN
  SELECT definition INTO d FROM workflow_revisions WHERE (tenant_id,partner_id,actor_id,workflow_id,version)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.workflow_id,NEW.workflow_version);
  IF d ? 'source' THEN
   IF NOT (NEW.routing_authorization_id IS NULL AND freightctl_collection_handoff_run_matches(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.run_id,NEW.workflow_id,NEW.workflow_version,NEW.workflow_hash,NEW.file_id,NEW.execution_plan_hash,false)) AND NOT EXISTS(SELECT 1 FROM workflow_collection_inputs i WHERE (i.tenant_id,i.partner_id,i.actor_id,i.workflow_id,i.file_id,i.state)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.workflow_id,NEW.file_id,'accepted') AND i.run_id IS NULL AND freightctl_collection_routing_run_matches(NEW.tenant_id,NEW.partner_id,NEW.actor_id,i.first_job_id,NEW.routing_authorization_id,NEW.workflow_id,NEW.workflow_version,NEW.workflow_hash,NEW.file_id,NEW.execution_plan_hash)) THEN RAISE EXCEPTION 'run needs original captured input and effective routing decision' USING ERRCODE='23514';END IF;
  ELSIF NEW.routing_authorization_id IS NOT NULL THEN RAISE EXCEPTION 'routing authorization cannot attach to an unrelated file' USING ERRCODE='23514';END IF;
  IF d->>'schema_version'<>'3' AND NEW.namespace_root<>'/' THEN RAISE EXCEPTION 'legacy run requires root namespace' USING ERRCODE='23514'; END IF;
  IF d->>'schema_version'='1' THEN
   IF NEW.execution_plan IS NOT NULL OR NEW.execution_plan_hash IS NOT NULL OR NEW.state='kept_local' THEN RAISE EXCEPTION 'legacy run cannot acquire a new plan' USING ERRCODE='23514';END IF;
  ELSIF d->>'schema_version'='2' THEN
   facts:=freightctl_program_run_facts(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.workflow_id,NEW.workflow_version,NEW.workflow_hash,NEW.file_id);
   expected:=freightctl_program_compile(d,facts);
   IF expected IS NULL OR NEW.execution_plan IS DISTINCT FROM expected OR NEW.execution_plan_hash IS DISTINCT FROM encode(sha256(convert_to(freightctl_program_wire(expected),'UTF8')),'hex') OR ((NEW.state='kept_local') IS DISTINCT FROM (expected ? 'local_reason')) THEN RAISE EXCEPTION 'run requires exact independently compiled program and authoritative facts' USING ERRCODE='23514';END IF;
  ELSIF d->>'schema_version'='3' THEN
   IF NEW.execution_plan IS NOT NULL OR NEW.execution_plan_hash IS NOT NULL OR NEW.state<>'queued'
   OR jsonb_array_length(d->'steps') IS DISTINCT FROM 0 OR d ? 'source' OR d ? 'program'
   OR d->'processing'->>'kind' IS DISTINCT FROM 'records.project'
   OR NOT EXISTS(SELECT 1 FROM credentials c WHERE (c.tenant_id,c.partner_id,c.actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id)
    AND c.actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid AND c.revoked_at IS NULL AND (c.expires_at IS NULL OR c.expires_at>clock_timestamp())
    AND c.namespace_root=NEW.namespace_root AND c.authority_revision=NEW.authority_revision AND c.permissions @> ARRAY['read','write','check_run','workflow_execute']::text[])
   THEN RAISE EXCEPTION 'processing run requires exact scoped task authority and no delivery plan' USING ERRCODE='23514'; END IF;
  ELSE RAISE EXCEPTION 'unsupported workflow execution schema' USING ERRCODE='23514';END IF;
  IF NEW.state NOT IN ('queued','kept_local') OR NEW.revision<>1 OR NOT EXISTS(SELECT 1 FROM workflow_revisions w WHERE (w.tenant_id,w.partner_id,w.workflow_id,w.version,w.actor_id,w.definition_hash,w.state,w.approval_authority)=(NEW.tenant_id,NEW.partner_id,NEW.workflow_id,NEW.workflow_version,NEW.actor_id,NEW.workflow_hash,'approved',NEW.authority_revision)) OR NOT EXISTS(SELECT 1 FROM files f WHERE (f.tenant_id,f.partner_id,f.file_id)=(NEW.tenant_id,NEW.partner_id,NEW.file_id) AND NEW.source=jsonb_build_object('id',f.file_id::text,'size_bytes',f.size_bytes,'sha256',f.sha256,'policy',f.policy,'accepted_event_id',f.accepted_event_id::text)) THEN
   RAISE EXCEPTION 'run requires exact approved workflow and accepted source' USING ERRCODE='23514';END IF;
 ELSE
  IF (NEW.execution_plan,NEW.execution_plan_hash) IS DISTINCT FROM (OLD.execution_plan,OLD.execution_plan_hash) OR NEW.state='kept_local' THEN RAISE EXCEPTION 'execution plan and local disposition are immutable' USING ERRCODE='23514';END IF;
  IF (NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.run_id,NEW.workflow_id,NEW.workflow_version,NEW.workflow_hash,NEW.file_id,NEW.source,NEW.storage_id,NEW.namespace_root,NEW.authority_revision) IS DISTINCT FROM (OLD.tenant_id,OLD.partner_id,OLD.actor_id,OLD.run_id,OLD.workflow_id,OLD.workflow_version,OLD.workflow_hash,OLD.file_id,OLD.source,OLD.storage_id,OLD.namespace_root,OLD.authority_revision) OR OLD.state IN ('succeeded','cancelled','kept_local') OR NEW.state='queued' OR NEW.revision<>OLD.revision+1 THEN
   RAISE EXCEPTION 'invalid workflow run transition' USING ERRCODE='23514';END IF;
  SELECT definition INTO d FROM workflow_revisions WHERE (tenant_id,partner_id,actor_id,workflow_id,version)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.workflow_id,NEW.workflow_version);
  IF d->>'schema_version'='3' THEN
   IF NEW.state='succeeded' AND NOT EXISTS(SELECT 1 FROM workflow_processing b JOIN record_projections rp USING(tenant_id,partner_id,projection_id)
    JOIN file_checks c ON (c.tenant_id,c.partner_id,c.actor_id,c.file_id)=(rp.tenant_id,rp.partner_id,rp.actor_id,rp.new_file_id)
    JOIN file_releases f ON (f.tenant_id,f.partner_id,f.actor_id,f.file_id,f.policy_id,f.policy_version,f.policy_hash,f.report_hash)=(c.tenant_id,c.partner_id,c.actor_id,c.file_id,c.policy_id,c.policy_version,c.policy_hash,c.report_hash)
    WHERE (b.tenant_id,b.partner_id,b.actor_id,b.run_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.run_id)
    AND rp.state='completed' AND rp.definition_hash=b.definition_hash AND c.state='released' AND freightctl_file_available(c.tenant_id,c.partner_id,c.file_id))
   THEN RAISE EXCEPTION 'processing success requires fresh separately released output' USING ERRCODE='23514'; END IF;
   IF NEW.state='cancelled' AND EXISTS(SELECT 1 FROM workflow_processing b JOIN record_projections rp USING(tenant_id,partner_id,projection_id) WHERE (b.tenant_id,b.partner_id,b.actor_id,b.run_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.run_id) AND rp.state NOT IN ('completed','cancelled'))
   THEN RAISE EXCEPTION 'processing cancellation must retire its intent atomically' USING ERRCODE='23514'; END IF;
  END IF;
  IF NEW.state='succeeded' AND EXISTS(SELECT 1 FROM workflow_steps s JOIN delivery_intents d USING(tenant_id,partner_id,delivery_id) WHERE (s.tenant_id,s.partner_id,s.run_id)=(NEW.tenant_id,NEW.partner_id,NEW.run_id) AND d.state<>'succeeded') THEN RAISE EXCEPTION 'run success requires every exact intent receipt' USING ERRCODE='23514';END IF;
 END IF;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION freightctl_workflow_run_complete() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE d jsonb;
BEGIN
 SELECT definition INTO d FROM workflow_revisions WHERE (tenant_id,partner_id,actor_id,workflow_id,version)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.workflow_id,NEW.workflow_version);
 IF d->>'schema_version'='3' THEN
  IF EXISTS(SELECT 1 FROM workflow_steps s WHERE (s.tenant_id,s.partner_id,s.run_id)=(NEW.tenant_id,NEW.partner_id,NEW.run_id))
  OR NOT EXISTS(SELECT 1 FROM workflow_processing b JOIN record_projections p USING(tenant_id,partner_id,projection_id)
   WHERE (b.tenant_id,b.partner_id,b.actor_id,b.run_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.run_id)
   AND p.actor_id=NEW.actor_id AND p.definition_hash=b.definition_hash AND p.definition->'workflow'->>'run_id'=NEW.run_id::text)
  THEN RAISE EXCEPTION 'processing run requires one exact intent and zero delivery steps' USING ERRCODE='23514'; END IF;
  RETURN NEW;
 END IF;
 IF NOT EXISTS(SELECT 1 FROM workflow_revisions w WHERE (w.tenant_id,w.partner_id,w.workflow_id,w.version)=(NEW.tenant_id,NEW.partner_id,NEW.workflow_id,NEW.workflow_version) AND CASE WHEN w.definition->>'schema_version'='1' THEN jsonb_array_length(w.definition->'steps') ELSE jsonb_array_length(NEW.execution_plan->'selected_steps') END=(SELECT count(*) FROM workflow_steps s WHERE (s.tenant_id,s.partner_id,s.run_id)=(NEW.tenant_id,NEW.partner_id,NEW.run_id))) THEN
  RAISE EXCEPTION 'run must bind all workflow step intents atomically' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION freightctl_projection_slot_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r record_projections;
BEGIN
 SELECT * INTO r FROM record_projections WHERE (tenant_id,partner_id,projection_id,actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.projection_id,NEW.actor_id);
 IF r.projection_id IS NULL OR NOT ((r.definition->>'schema_version'='1' AND r.state='proposed') OR (r.definition->>'schema_version'='2' AND r.state='approved' AND r.revision=1 AND r.attempts=0)) OR NEW.file_id=r.source_file_id OR to_jsonb(NEW.file_id::text) IS DISTINCT FROM r.definition->'staging_slots'->(NEW.ordinal-1)
 OR EXISTS(SELECT 1 FROM files WHERE (tenant_id,partner_id,file_id)=(NEW.tenant_id,NEW.partner_id,NEW.file_id))
 THEN RAISE EXCEPTION 'projection slot must be exact unused owned effect' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
