-- Recovery creates an explicitly approved successor. Original capture, input
-- assignment, run plans, receipts and source facts are never rewritten.
CREATE TABLE workflow_collection_handoffs (
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,actor_id uuid NOT NULL,id uuid NOT NULL,
 job_id uuid NOT NULL,input_id uuid NOT NULL,source_run_id uuid NOT NULL,planned_run_id uuid NOT NULL,
 definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object' AND octet_length(definition::text)<=32768),
 definition_hash text NOT NULL CHECK(definition_hash ~ '^[0-9a-f]{64}$'),
 state text NOT NULL CHECK(state IN ('proposed','approved','cancelled','completed')),
 revision bigint NOT NULL CHECK(revision>0),approval_authority bigint NOT NULL CHECK(approval_authority>=0),changed_event_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,id),UNIQUE(tenant_id,partner_id,actor_id,planned_run_id),
 CHECK(source_run_id<>planned_run_id),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,job_id) REFERENCES workflow_collection_jobs(tenant_id,partner_id,id),
 FOREIGN KEY(tenant_id,partner_id,input_id) REFERENCES workflow_collection_inputs(tenant_id,partner_id,id),
 FOREIGN KEY(tenant_id,partner_id,source_run_id) REFERENCES workflow_runs(tenant_id,partner_id,run_id),
 FOREIGN KEY(tenant_id,partner_id,changed_event_id) REFERENCES events(tenant_id,partner_id,event_id)
);
CREATE UNIQUE INDEX collection_handoff_pending ON workflow_collection_handoffs(tenant_id,partner_id,actor_id,source_run_id) WHERE state IN ('proposed','approved');
CREATE UNIQUE INDEX collection_handoff_successor ON workflow_collection_handoffs(tenant_id,partner_id,actor_id,source_run_id) WHERE state='completed';
CREATE INDEX collection_handoff_history ON workflow_collection_handoffs(tenant_id,partner_id,actor_id,job_id,id);
ALTER TABLE workflow_collection_handoffs ENABLE ROW LEVEL SECURITY;
ALTER TABLE workflow_collection_handoffs FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON workflow_collection_handoffs USING(tenant_id=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND partner_id=nullif(current_setting('freightctl.partner_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND partner_id=nullif(current_setting('freightctl.partner_id',true),'')::uuid);
CREATE POLICY identity_scope ON workflow_collection_handoffs AS RESTRICTIVE USING(actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid) WITH CHECK(actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid);
REVOKE ALL ON workflow_collection_handoffs FROM PUBLIC;
GRANT SELECT,INSERT,UPDATE ON workflow_collection_handoffs TO freightctl_runtime;

CREATE FUNCTION freightctl_collection_handoff_definition(t uuid,p uuid,a uuid,jid uuid,iid uuid,srid uuid,wid uuid,wver integer,whash text,after_cancel boolean) RETURNS jsonb LANGUAGE plpgsql STABLE AS $$
DECLARE j workflow_collection_jobs%ROWTYPE;i workflow_collection_inputs%ROWTYPE;r workflow_runs%ROWTYPE;
 w jsonb;facts jsonb;plan jsonb;bindings jsonb;source jsonb;authority bigint;delta integer:=CASE WHEN after_cancel THEN 1 ELSE 0 END;
BEGIN
 SELECT * INTO j FROM workflow_collection_jobs WHERE (tenant_id,partner_id,actor_id,id)=(t,p,a,jid);
 SELECT * INTO i FROM workflow_collection_inputs WHERE (tenant_id,partner_id,actor_id,id,first_job_id,state)=(t,p,a,iid,jid,'queued');
 SELECT * INTO r FROM workflow_runs WHERE (tenant_id,partner_id,actor_id,run_id)=(t,p,a,srid);
 IF j.id IS NULL OR i.id IS NULL OR r.run_id IS NULL OR r.file_id IS DISTINCT FROM i.file_id OR r.workflow_id<>i.workflow_id OR r.execution_plan IS NULL
 OR (r.storage_id::text,r.namespace_root,r.authority_revision::text) IS DISTINCT FROM (j.definition->>'storage_id',j.definition->>'namespace_root',j.definition->>'authority_revision')
 OR (NOT after_cancel AND r.state NOT IN ('queued','running','attention'))
 OR (after_cancel AND (r.state<>'cancelled' OR r.reason<>'collection_handoff'))
 OR NOT(i.run_id=srid OR EXISTS(SELECT 1 FROM workflow_collection_handoffs h WHERE (h.tenant_id,h.partner_id,h.actor_id,h.job_id,h.input_id,h.planned_run_id,h.state)=(t,p,a,jid,iid,srid,'completed')))
 THEN RETURN NULL;END IF;
 facts:=freightctl_collection_original_facts(t,p,a,jid,i.file_id);
 w:=freightctl_collection_routing_target(t,p,a,jid,wid,wver,whash);
 IF facts IS NULL OR w IS NULL OR NOT freightctl_file_available(t,p,i.file_id) OR (r.workflow_version,r.workflow_hash)=(wver,whash) THEN RETURN NULL;END IF;
 -- Every prior effect must be completely untouched. A claim, ciphertext or
 -- uncertain outcome requires a different proof; it cannot enter this profile.
 IF NOT EXISTS(SELECT 1 FROM workflow_steps WHERE (tenant_id,partner_id,actor_id,run_id)=(t,p,a,srid)) OR EXISTS(
 SELECT 1 FROM workflow_steps s JOIN delivery_intents d USING(tenant_id,partner_id,delivery_id)
 WHERE (s.tenant_id,s.partner_id,s.actor_id,s.run_id)=(t,p,a,srid) AND
 (d.actor_id<>a OR d.state<>CASE WHEN after_cancel THEN 'cancelled' ELSE 'queued' END OR d.attempts<>0 OR d.fence<>0 OR d.lease_owner IS NOT NULL OR d.lease_until IS NOT NULL
 OR (after_cancel AND d.observation->>'code' IS DISTINCT FROM 'collection_handoff') OR EXISTS(SELECT 1 FROM delivery_ciphertexts c WHERE (c.tenant_id,c.partner_id,c.delivery_id)=(t,p,d.delivery_id)))) THEN RETURN NULL;END IF;
 IF EXISTS(SELECT 1 FROM workflow_collection_handoffs h WHERE (h.tenant_id,h.partner_id,h.actor_id,h.source_run_id,h.state)=(t,p,a,srid,'completed') AND NOT(after_cancel AND (h.definition->'workflow'->>'id',h.definition->'workflow'->>'version',h.definition->'workflow'->>'hash')=(wid::text,wver::text,whash))) THEN RETURN NULL;END IF;
 plan:=freightctl_program_compile(w,facts);
 IF plan IS NULL THEN RETURN NULL;END IF;
 SELECT authority_revision INTO authority FROM credentials WHERE (tenant_id,partner_id,actor_id)=(t,p,a);
 SELECT jsonb_agg(jsonb_build_object('id',d.delivery_id::text,'revision',d.revision-delta,'definition_hash',d.definition_hash,'step_id',s.step_id,'ordinal',s.ordinal) ORDER BY s.ordinal) INTO bindings
 FROM workflow_steps s JOIN delivery_intents d USING(tenant_id,partner_id,delivery_id) WHERE (s.tenant_id,s.partner_id,s.actor_id,s.run_id)=(t,p,a,srid);
 source:=jsonb_build_object('id',r.run_id::text,'revision',r.revision-delta,'plan_hash',r.execution_plan_hash,'workflow',jsonb_build_object('id',r.workflow_id::text,'version',r.workflow_version,'hash',r.workflow_hash));
 IF r.routing_authorization_id IS NOT NULL THEN source:=source||jsonb_build_object('routing_authorization_id',r.routing_authorization_id::text);END IF;
 RETURN jsonb_build_object('schema_version',1,'profile','untouched-collected-handoff-v1','collection',jsonb_build_object('id',j.id::text,'revision',j.revision,'definition_hash',j.definition_hash),
 'input_id',i.id::text,'source_run',source,'intents',bindings,'workflow',jsonb_build_object('id',wid::text,'version',wver,'hash',whash),'plan',plan,
 'plan_hash',encode(sha256(convert_to(freightctl_program_wire(plan),'UTF8')),'hex'),'authority_revision',authority,'storage_id',r.storage_id::text,'namespace_root',r.namespace_root);
END $$;

-- Fixed Go JSON field order; the plan uses its existing independently checked
-- wire form, including the original producer facts and exact selected steps.
CREATE FUNCTION freightctl_collection_handoff_wire(d jsonb) RETURNS text LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE out text;r jsonb:=d->'source_run';c jsonb:=d->'collection';v jsonb;separator text:='';
BEGIN
 out:='{"schema_version":1,"profile":'||freightctl_program_quote(d->>'profile')||',"collection":{"id":'||freightctl_program_quote(c->>'id')||',"revision":'||(c->>'revision')||',"definition_hash":'||freightctl_program_quote(c->>'definition_hash')||'},"input_id":'||freightctl_program_quote(d->>'input_id')||',"source_run":{"id":'||freightctl_program_quote(r->>'id')||',"revision":'||(r->>'revision')||',"plan_hash":'||freightctl_program_quote(r->>'plan_hash')||',"workflow":'||freightctl_collection_routing_ref_wire(r->'workflow');
 IF r ? 'routing_authorization_id' THEN out:=out||',"routing_authorization_id":'||freightctl_program_quote(r->>'routing_authorization_id');END IF;
 out:=out||'},"intents":[';
 FOR v IN SELECT value FROM jsonb_array_elements(d->'intents') LOOP
 out:=out||separator||'{"id":'||freightctl_program_quote(v->>'id')||',"revision":'||(v->>'revision')||',"definition_hash":'||freightctl_program_quote(v->>'definition_hash')||',"step_id":'||freightctl_program_quote(v->>'step_id')||',"ordinal":'||(v->>'ordinal')||'}';separator:=',';
 END LOOP;
 RETURN out||'],"workflow":'||freightctl_collection_routing_ref_wire(d->'workflow')||',"plan":'||freightctl_program_wire(d->'plan')||',"plan_hash":'||freightctl_program_quote(d->>'plan_hash')||',"authority_revision":'||(d->>'authority_revision')||',"storage_id":'||freightctl_program_quote(d->>'storage_id')||',"namespace_root":'||freightctl_program_quote(d->>'namespace_root')||'}';
END $$;
CREATE FUNCTION freightctl_collection_handoff_matches(t uuid,p uuid,a uuid,d jsonb,after_cancel boolean) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT d IS NOT NULL AND d=freightctl_collection_handoff_definition(t,p,a,(d->'collection'->>'id')::uuid,(d->>'input_id')::uuid,(d->'source_run'->>'id')::uuid,(d->'workflow'->>'id')::uuid,(d->'workflow'->>'version')::integer,d->'workflow'->>'hash',after_cancel)
$$;
CREATE FUNCTION freightctl_collection_handoff_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE e jsonb;current_authority bigint;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'handoff history is immutable' USING ERRCODE='23514';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended(NEW.tenant_id::text||':'||NEW.partner_id::text||':workflow-schedules',0));
 IF NOT pg_try_advisory_xact_lock(hashtextextended(NEW.tenant_id::text||':'||NEW.partner_id::text||':workflow-collections',0)) THEN RAISE EXCEPTION 'handoff admission busy' USING ERRCODE='40001';END IF;
 SELECT payload INTO e FROM events WHERE (tenant_id,partner_id,actor_id,event_id,resource_id,kind)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.changed_event_id,NEW.id,'WorkflowCollectionHandoffChanged');
 IF e IS NULL OR e IS DISTINCT FROM (to_jsonb(NEW)-ARRAY['tenant_id','partner_id','actor_id','changed_event_id']) THEN RAISE EXCEPTION 'handoff needs its exact journal record' USING ERRCODE='23514';END IF;
 IF (NEW.definition->'collection'->>'id',NEW.definition->>'input_id',NEW.definition->'source_run'->>'id') IS DISTINCT FROM (NEW.job_id::text,NEW.input_id::text,NEW.source_run_id::text)
 OR NEW.definition_hash IS DISTINCT FROM encode(sha256(convert_to(freightctl_collection_handoff_wire(NEW.definition),'UTF8')),'hex') THEN RAISE EXCEPTION 'handoff definition binding differs' USING ERRCODE='23514';END IF;
 SELECT authority_revision INTO current_authority FROM credentials WHERE (tenant_id,partner_id,actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id);
 IF TG_OP='INSERT' THEN
  IF NEW.state<>'proposed' OR NEW.revision<>1 OR NEW.approval_authority<>0 OR NOT freightctl_schedule_owner(NEW.tenant_id,NEW.partner_id,NEW.actor_id,ARRAY['workflow_manage'])
  OR freightctl_collection_handoff_matches(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.definition,false) IS NOT TRUE
  OR EXISTS(SELECT 1 FROM workflow_runs WHERE (tenant_id,partner_id,run_id)=(NEW.tenant_id,NEW.partner_id,NEW.planned_run_id)) THEN RAISE EXCEPTION 'handoff begins as exact current proposal' USING ERRCODE='23514';END IF;
 ELSE
  IF (NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.id,NEW.job_id,NEW.input_id,NEW.source_run_id,NEW.planned_run_id,NEW.definition,NEW.definition_hash) IS DISTINCT FROM (OLD.tenant_id,OLD.partner_id,OLD.actor_id,OLD.id,OLD.job_id,OLD.input_id,OLD.source_run_id,OLD.planned_run_id,OLD.definition,OLD.definition_hash) OR NEW.revision<>OLD.revision+1 THEN RAISE EXCEPTION 'handoff binding is immutable' USING ERRCODE='23514';END IF;
  IF OLD.state IN ('proposed','approved') AND NEW.state='cancelled' THEN
   IF NEW.approval_authority<>OLD.approval_authority OR NOT freightctl_schedule_owner(NEW.tenant_id,NEW.partner_id,NEW.actor_id,ARRAY['workflow_manage','read']) THEN RAISE EXCEPTION 'handoff cancellation authority changed' USING ERRCODE='42501';END IF;
  ELSIF OLD.state='proposed' AND NEW.state='approved' THEN
   IF NEW.approval_authority<>current_authority OR NOT freightctl_schedule_owner(NEW.tenant_id,NEW.partner_id,NEW.actor_id,ARRAY['workflow_approve']) OR freightctl_collection_handoff_matches(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.definition,false) IS NOT TRUE THEN RAISE EXCEPTION 'handoff approval is stale' USING ERRCODE='23514';END IF;
  ELSIF OLD.state='approved' AND NEW.state='completed' THEN
   IF NEW.approval_authority<>OLD.approval_authority OR NEW.approval_authority<>current_authority OR NOT freightctl_schedule_owner(NEW.tenant_id,NEW.partner_id,NEW.actor_id,ARRAY['workflow_manage']) OR freightctl_collection_handoff_matches(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.definition,true) IS NOT TRUE
   OR NOT EXISTS(SELECT 1 FROM workflow_runs r WHERE (r.tenant_id,r.partner_id,r.actor_id,r.run_id,r.workflow_id,r.workflow_version,r.workflow_hash,r.file_id,r.storage_id,r.namespace_root,r.authority_revision,r.revision)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.planned_run_id,(NEW.definition->'workflow'->>'id')::uuid,(NEW.definition->'workflow'->>'version')::integer,NEW.definition->'workflow'->>'hash',(NEW.definition->'plan'->'facts'->'file'->>'id')::uuid,(NEW.definition->>'storage_id')::uuid,NEW.definition->>'namespace_root',current_authority,1) AND r.execution_plan=NEW.definition->'plan' AND r.execution_plan_hash=NEW.definition->>'plan_hash' AND r.routing_authorization_id IS NULL AND r.state IN ('queued','kept_local')) THEN RAISE EXCEPTION 'handoff needs its exact atomic successor' USING ERRCODE='23514';END IF;
  ELSE RAISE EXCEPTION 'invalid handoff transition' USING ERRCODE='23514';END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER collection_handoff_guard BEFORE INSERT OR UPDATE OR DELETE ON workflow_collection_handoffs FOR EACH ROW EXECUTE FUNCTION freightctl_collection_handoff_guard();
CREATE FUNCTION freightctl_collection_handoff_projection_complete() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.kind='WorkflowCollectionHandoffChanged' AND NOT EXISTS(SELECT 1 FROM workflow_collection_handoffs h WHERE (h.tenant_id,h.partner_id,h.actor_id,h.id,h.changed_event_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.resource_id,NEW.event_id)) THEN RAISE EXCEPTION 'handoff event needs exact projection' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER collection_handoff_projection_complete AFTER INSERT ON events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION freightctl_collection_handoff_projection_complete();
CREATE FUNCTION freightctl_collection_handoff_cancellation_complete() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_TABLE_NAME='workflow_runs' THEN
  IF NEW.state='cancelled' AND NEW.reason='collection_handoff' AND NOT EXISTS(SELECT 1 FROM workflow_collection_handoffs h WHERE (h.tenant_id,h.partner_id,h.actor_id,h.source_run_id,h.state)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.run_id,'completed')) THEN RAISE EXCEPTION 'cancelled source requires completed handoff' USING ERRCODE='23514';END IF;
 ELSE
  IF NEW.state='cancelled' AND NEW.observation->>'code'='collection_handoff' AND NOT EXISTS(SELECT 1 FROM workflow_collection_handoffs h CROSS JOIN LATERAL jsonb_array_elements(h.definition->'intents') prior_intent(value) WHERE (h.tenant_id,h.partner_id,h.actor_id,h.id,h.state)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,(NEW.observation->>'handoff_id')::uuid,'completed') AND prior_intent.value->>'id'=NEW.delivery_id::text) THEN RAISE EXCEPTION 'cancelled intent requires exact completed handoff' USING ERRCODE='23514';END IF;
 END IF;RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER collection_handoff_cancelled_run AFTER INSERT OR UPDATE ON workflow_runs DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION freightctl_collection_handoff_cancellation_complete();
CREATE CONSTRAINT TRIGGER collection_handoff_cancelled_delivery AFTER INSERT OR UPDATE ON delivery_intents DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION freightctl_collection_handoff_cancellation_complete();

CREATE OR REPLACE FUNCTION freightctl_program_run_facts(t uuid,p uuid,a uuid,wid uuid,wver integer,whash text,fid uuid) RETURNS jsonb LANGUAGE plpgsql STABLE AS $$
DECLARE d jsonb;f jsonb;i record;choice workflow_collection_routing%ROWTYPE;facts jsonb;result jsonb;matched integer:=0;handoff workflow_collection_handoffs%ROWTYPE;
BEGIN
 SELECT definition INTO d FROM workflow_revisions WHERE (tenant_id,partner_id,actor_id,workflow_id,version,definition_hash,state)=(t,p,a,wid,wver,whash,'approved');
 IF d IS NULL OR freightctl_schedule_owner(t,p,a,ARRAY['workflow_execute','read']) IS NOT TRUE OR freightctl_file_available(t,p,fid) IS NOT TRUE THEN RETURN NULL;END IF;
 SELECT * INTO handoff FROM workflow_collection_handoffs h WHERE (h.tenant_id,h.partner_id,h.actor_id)=(t,p,a) AND h.state IN ('approved','completed') AND (h.definition->'workflow'->>'id',h.definition->'workflow'->>'version',h.definition->'workflow'->>'hash',h.definition->'plan'->'facts'->'file'->>'id')=(wid::text,wver::text,whash,fid::text) AND freightctl_collection_handoff_matches(t,p,a,h.definition,true) LIMIT 1;
 IF handoff.id IS NOT NULL THEN RETURN handoff.definition->'plan'->'facts';END IF;
 IF NOT(d ? 'source') THEN
  SELECT jsonb_build_object('id',file_id::text,'size_bytes',size_bytes,'sha256',sha256,'policy',policy,'accepted_event_id',accepted_event_id::text) INTO f FROM files WHERE (tenant_id,partner_id,file_id)=(t,p,fid);
  IF f IS NULL THEN RETURN NULL;END IF;
  RETURN jsonb_build_object('file',f);
 END IF;
 FOR i IN SELECT * FROM workflow_collection_inputs WHERE (tenant_id,partner_id,actor_id,workflow_id,file_id)=(t,p,a,wid,fid) LOOP
  facts:=freightctl_collection_original_facts(t,p,a,i.first_job_id,fid);
  IF facts IS NULL THEN CONTINUE;END IF;
  SELECT * INTO choice FROM freightctl_collection_routing_choice(t,p,a,i.first_job_id);
  IF choice.id IS NULL THEN
   IF NOT EXISTS(SELECT 1 FROM workflow_collection_jobs j WHERE (j.tenant_id,j.partner_id,j.actor_id,j.id,j.workflow_version,j.workflow_hash)=(t,p,a,i.first_job_id,wver,whash) AND j.definition->'source'=d->'source') THEN CONTINUE;END IF;
  ELSE
   IF choice.state<>'approved' OR (choice.definition->'workflow'->>'id',choice.definition->'workflow'->>'version',choice.definition->'workflow'->>'hash') IS DISTINCT FROM (wid::text,wver::text,whash) OR freightctl_collection_routing_target(t,p,a,i.first_job_id,wid,wver,whash) IS NULL THEN CONTINUE;END IF;
  END IF;
  matched:=matched+1;result:=facts;
 END LOOP;
 IF matched<>1 THEN RETURN NULL;END IF;
 RETURN result;
END $$;


CREATE FUNCTION freightctl_collection_handoff_run_matches(t uuid,p uuid,a uuid,rid uuid,wid uuid,wver integer,whash text,fid uuid,plan_hash text,completed boolean) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT EXISTS(SELECT 1 FROM workflow_collection_handoffs h WHERE (h.tenant_id,h.partner_id,h.actor_id,h.planned_run_id)=(t,p,a,rid) AND h.state=CASE WHEN completed THEN 'completed' ELSE 'approved' END
 AND (h.definition->'workflow'->>'id',h.definition->'workflow'->>'version',h.definition->'workflow'->>'hash',h.definition->'plan'->'facts'->'file'->>'id',h.definition->>'plan_hash')=(wid::text,wver::text,whash,fid::text,plan_hash) AND freightctl_collection_handoff_matches(t,p,a,h.definition,true))
$$;
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
  IF d->>'schema_version'='1' THEN
   IF NEW.execution_plan IS NOT NULL OR NEW.execution_plan_hash IS NOT NULL OR NEW.state='kept_local' THEN RAISE EXCEPTION 'legacy run cannot acquire a new plan' USING ERRCODE='23514';END IF;
  ELSIF d->>'schema_version'='2' THEN
   facts:=freightctl_program_run_facts(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.workflow_id,NEW.workflow_version,NEW.workflow_hash,NEW.file_id);
   expected:=freightctl_program_compile(d,facts);
   IF expected IS NULL OR NEW.execution_plan IS DISTINCT FROM expected OR NEW.execution_plan_hash IS DISTINCT FROM encode(sha256(convert_to(freightctl_program_wire(expected),'UTF8')),'hex') OR ((NEW.state='kept_local') IS DISTINCT FROM (expected ? 'local_reason')) THEN RAISE EXCEPTION 'run requires exact independently compiled program and authoritative facts' USING ERRCODE='23514';END IF;
  ELSE RAISE EXCEPTION 'unsupported workflow execution schema' USING ERRCODE='23514';END IF;
  IF NEW.state NOT IN ('queued','kept_local') OR NEW.revision<>1 OR NOT EXISTS(SELECT 1 FROM workflow_revisions w WHERE (w.tenant_id,w.partner_id,w.workflow_id,w.version,w.actor_id,w.definition_hash,w.state,w.approval_authority)=(NEW.tenant_id,NEW.partner_id,NEW.workflow_id,NEW.workflow_version,NEW.actor_id,NEW.workflow_hash,'approved',NEW.authority_revision)) OR NOT EXISTS(SELECT 1 FROM files f WHERE (f.tenant_id,f.partner_id,f.file_id)=(NEW.tenant_id,NEW.partner_id,NEW.file_id) AND NEW.source=jsonb_build_object('id',f.file_id::text,'size_bytes',f.size_bytes,'sha256',f.sha256,'policy',f.policy,'accepted_event_id',f.accepted_event_id::text)) THEN
   RAISE EXCEPTION 'run requires exact approved workflow and accepted source' USING ERRCODE='23514';END IF;
 ELSE
  IF (NEW.execution_plan,NEW.execution_plan_hash) IS DISTINCT FROM (OLD.execution_plan,OLD.execution_plan_hash) OR NEW.state='kept_local' THEN RAISE EXCEPTION 'execution plan and local disposition are immutable' USING ERRCODE='23514';END IF;
  IF (NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.run_id,NEW.workflow_id,NEW.workflow_version,NEW.workflow_hash,NEW.file_id,NEW.source,NEW.storage_id,NEW.namespace_root,NEW.authority_revision) IS DISTINCT FROM (OLD.tenant_id,OLD.partner_id,OLD.actor_id,OLD.run_id,OLD.workflow_id,OLD.workflow_version,OLD.workflow_hash,OLD.file_id,OLD.source,OLD.storage_id,OLD.namespace_root,OLD.authority_revision) OR OLD.state IN ('succeeded','cancelled','kept_local') OR NEW.state='queued' OR NEW.revision<>OLD.revision+1 THEN
   RAISE EXCEPTION 'invalid workflow run transition' USING ERRCODE='23514';END IF;
  IF NEW.state='succeeded' AND EXISTS(SELECT 1 FROM workflow_steps s JOIN delivery_intents d USING(tenant_id,partner_id,delivery_id) WHERE (s.tenant_id,s.partner_id,s.run_id)=(NEW.tenant_id,NEW.partner_id,NEW.run_id) AND d.state<>'succeeded') THEN RAISE EXCEPTION 'run success requires every exact intent receipt' USING ERRCODE='23514';END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION freightctl_collection_run_complete() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM workflow_revisions w WHERE (w.tenant_id,w.partner_id,w.actor_id,w.workflow_id,w.version)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.workflow_id,NEW.workflow_version) AND w.definition ? 'source') THEN
  IF NOT (NEW.routing_authorization_id IS NULL AND freightctl_collection_handoff_run_matches(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.run_id,NEW.workflow_id,NEW.workflow_version,NEW.workflow_hash,NEW.file_id,NEW.execution_plan_hash,true)) AND NOT EXISTS(SELECT 1 FROM workflow_collection_inputs i WHERE (i.tenant_id,i.partner_id,i.actor_id,i.run_id,i.file_id,i.workflow_id,i.state)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.run_id,NEW.file_id,NEW.workflow_id,'queued') AND freightctl_collection_routing_run_matches(NEW.tenant_id,NEW.partner_id,NEW.actor_id,i.first_job_id,NEW.routing_authorization_id,NEW.workflow_id,NEW.workflow_version,NEW.workflow_hash,NEW.file_id,NEW.execution_plan_hash)) THEN RAISE EXCEPTION 'collection run needs its exact original lineage and effective routing approval' USING ERRCODE='23514';END IF;
 ELSIF NEW.routing_authorization_id IS NOT NULL THEN RAISE EXCEPTION 'only captured inputs can use a routing authorization' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;


ALTER FUNCTION freightctl_collected_run_status(uuid,uuid,uuid,uuid) RENAME TO freightctl_collected_run_status_v33;
CREATE FUNCTION freightctl_collected_run_status(t uuid,p uuid,a uuid,target_run uuid) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT CASE WHEN EXISTS(SELECT 1 FROM workflow_collection_handoffs WHERE (tenant_id,partner_id,actor_id,planned_run_id)=(t,p,a,target_run)) THEN EXISTS(
 SELECT 1 FROM workflow_runs r WHERE (r.tenant_id,r.partner_id,r.actor_id,r.run_id)=(t,p,a,target_run) AND freightctl_collection_handoff_run_matches(t,p,a,r.run_id,r.workflow_id,r.workflow_version,r.workflow_hash,r.file_id,r.execution_plan_hash,true))
 ELSE freightctl_collected_run_status_v33(t,p,a,target_run) END
$$;
CREATE OR REPLACE FUNCTION freightctl_collected_run_current(t uuid,p uuid,a uuid,target_run uuid) RETURNS boolean LANGUAGE plpgsql VOLATILE AS $$
BEGIN
 PERFORM pg_advisory_xact_lock_shared(hashtextextended(t::text||':'||p::text||':workflow-collections',0));
 RETURN freightctl_collected_run_status(t,p,a,target_run);
END $$;
