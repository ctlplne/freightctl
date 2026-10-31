-- Captured input stays owned by its original job. A separate actor-private
-- decision authorizes exact replacement plans before any run exists.
CREATE TABLE workflow_collection_routing (
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,actor_id uuid NOT NULL,id uuid NOT NULL,job_id uuid NOT NULL,
 version integer NOT NULL CHECK(version>0),
 definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object' AND octet_length(definition::text)<=24576),
 definition_hash text NOT NULL CHECK(definition_hash ~ '^[0-9a-f]{64}$'),
 state text NOT NULL CHECK(state IN ('proposed','approved','revoked','withdrawn')),
 revision bigint NOT NULL CHECK(revision>0),approval_authority bigint NOT NULL CHECK(approval_authority>=0),changed_event_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,id),UNIQUE(tenant_id,partner_id,actor_id,id),UNIQUE(tenant_id,partner_id,actor_id,job_id,version),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,job_id) REFERENCES workflow_collection_jobs(tenant_id,partner_id,id),
 FOREIGN KEY(tenant_id,partner_id,changed_event_id) REFERENCES events(tenant_id,partner_id,event_id)
);
CREATE UNIQUE INDEX collection_routing_one_proposal ON workflow_collection_routing(tenant_id,partner_id,actor_id,job_id) WHERE state='proposed';
CREATE INDEX collection_routing_decisions ON workflow_collection_routing(tenant_id,partner_id,actor_id,job_id,version DESC) WHERE state IN ('approved','revoked');
ALTER TABLE workflow_collection_routing ENABLE ROW LEVEL SECURITY;
ALTER TABLE workflow_collection_routing FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON workflow_collection_routing USING(tenant_id=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND partner_id=nullif(current_setting('freightctl.partner_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND partner_id=nullif(current_setting('freightctl.partner_id',true),'')::uuid);
CREATE POLICY identity_scope ON workflow_collection_routing AS RESTRICTIVE USING(actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid) WITH CHECK(actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid);
GRANT SELECT,INSERT,UPDATE ON workflow_collection_routing TO freightctl_runtime;
ALTER TABLE workflow_runs ADD COLUMN routing_authorization_id uuid;
ALTER TABLE workflow_runs ADD CONSTRAINT workflow_run_routing_actor FOREIGN KEY(tenant_id,partner_id,actor_id,routing_authorization_id) REFERENCES workflow_collection_routing(tenant_id,partner_id,actor_id,id);

CREATE FUNCTION freightctl_collection_routing_choice(t uuid,p uuid,a uuid,jid uuid) RETURNS SETOF workflow_collection_routing LANGUAGE sql STABLE ROWS 1 AS $$
 SELECT * FROM workflow_collection_routing WHERE (tenant_id,partner_id,actor_id,job_id)=(t,p,a,jid) AND state IN ('approved','revoked') ORDER BY version DESC LIMIT 1
$$;

-- This is the capture's original evidence, never facts supplied by a caller or
-- derived from the replacement program. Availability covers every owned sibling.
CREATE FUNCTION freightctl_collection_original_facts(t uuid,p uuid,a uuid,jid uuid,fid uuid) RETURNS jsonb LANGUAGE plpgsql STABLE AS $$
DECLARE facts jsonb;n integer;
BEGIN
 IF freightctl_schedule_owner(t,p,a,ARRAY['workflow_execute','read','write','list']) IS NOT TRUE THEN RETURN NULL;END IF;
 SELECT count(*),jsonb_agg(jsonb_build_object(
  'file',jsonb_build_object('id',f.file_id::text,'size_bytes',f.size_bytes,'sha256',f.sha256,'policy',f.policy,'accepted_event_id',f.accepted_event_id::text),
  'source',jsonb_build_object('collection_id',j.id::text,'manifest_hash',j.manifest_hash,'name',i.source_name,'batch_id',j.manifest->>'batch_id','file_count',jsonb_array_length(j.manifest->'files'),'index',manifest.ordinal-1)))->0 INTO n,facts
 FROM workflow_collection_jobs j
 JOIN workflow_collection_inputs i ON (i.tenant_id,i.partner_id,i.actor_id,i.first_job_id)=(j.tenant_id,j.partner_id,j.actor_id,j.id)
 JOIN files f ON (f.tenant_id,f.partner_id,f.file_id,f.size_bytes,f.sha256)=(i.tenant_id,i.partner_id,i.file_id,i.size_bytes,i.sha256)
 CROSS JOIN LATERAL jsonb_array_elements(j.manifest->'files') WITH ORDINALITY manifest(value,ordinal)
 JOIN namespace_entries published ON (published.tenant_id,published.partner_id,published.path,published.file_id,published.kind)=(i.tenant_id,i.partner_id,i.target_path,i.file_id,'file')
 JOIN credentials reader ON (reader.tenant_id,reader.partner_id,reader.actor_id)=(t,p,a)
 WHERE (j.tenant_id,j.partner_id,j.actor_id,j.id,i.file_id)=(t,p,a,jid,fid)
 AND j.captured AND j.state='captured' AND j.deadline_at>clock_timestamp() AND j.manifest_hash IS NOT NULL
 AND i.state IN ('accepted','queued') AND i.workflow_id=j.workflow_id
 AND (manifest.value->>'name',manifest.value->>'size_bytes',manifest.value->>'sha256')=(i.source_name,i.size_bytes::text,i.sha256)
 AND freightctl_collection_definition_current(t,p,a,j.definition) AND freightctl_file_available(t,p,fid)
 AND NOT published.deleted AND ('admin'=ANY(reader.permissions) OR (published.owner_actor_id=a AND (published.mode & 256)=256) OR (published.owner_actor_id<>a AND (published.mode & 32)=32))
 AND NOT EXISTS(SELECT 1 FROM workflow_collection_inputs sibling WHERE (sibling.tenant_id,sibling.partner_id,sibling.actor_id,sibling.first_job_id)=(t,p,a,jid) AND (sibling.file_id IS NULL OR freightctl_file_available(t,p,sibling.file_id) IS NOT TRUE));
 IF n<>1 THEN RETURN NULL;END IF;
 RETURN facts;
END $$;

-- Current target approval, source identity, fixed recipient catalog and key
-- custody are checked independently of the application.
CREATE FUNCTION freightctl_collection_routing_target(t uuid,p uuid,a uuid,jid uuid,wid uuid,wver integer,whash text) RETURNS jsonb LANGUAGE sql STABLE AS $$
 SELECT w.definition FROM workflow_collection_jobs j
 JOIN credentials u ON (u.tenant_id,u.partner_id,u.actor_id)=(j.tenant_id,j.partner_id,j.actor_id)
 JOIN workflow_revisions w ON (w.tenant_id,w.partner_id,w.actor_id,w.workflow_id,w.version,w.definition_hash,w.state,w.approval_authority)=(t,p,a,wid,wver,whash,'approved',u.authority_revision)
 WHERE (j.tenant_id,j.partner_id,j.actor_id,j.id,j.workflow_id)=(t,p,a,jid,wid)
 AND w.definition->>'schema_version'='2' AND w.definition->'source'=j.definition->'source'
 AND freightctl_schedule_owner(t,p,a,ARRAY['workflow_execute','read','write','list'])
 AND (jsonb_array_length(w.definition->'steps')=0 OR freightctl_schedule_owner(t,p,a,ARRAY['deliver']))
 AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(w.definition->'steps') step
  LEFT JOIN connection_revisions c ON (c.tenant_id,c.partner_id,c.actor_id,c.connection_id,c.version,c.definition_hash,c.state)=(t,p,a,(step->'connection'->>'id')::uuid,(step->'connection'->>'version')::integer,step->'connection'->>'hash','active')
  WHERE c.connection_id IS NULL OR (step ? 'encryption' AND NOT EXISTS(SELECT 1 FROM pgp_keys k WHERE (k.tenant_id,k.partner_id,k.key_id,k.version,k.definition_hash,k.state)=(t,p,(step->'encryption'->'key'->>'id')::uuid,(step->'encryption'->'key'->>'version')::integer,step->'encryption'->'key'->>'hash','active') AND k.definition->>'purpose'='encrypt' AND (k.valid_until IS NULL OR k.valid_until>clock_timestamp()) AND k.definition->'recipient'->'profiles' ? (step->'encryption'->>'profile'))))
$$;

CREATE FUNCTION freightctl_collection_routing_definition(t uuid,p uuid,a uuid,jid uuid,wid uuid,wver integer,whash text) RETURNS jsonb LANGUAGE plpgsql STABLE AS $$
DECLARE j workflow_collection_jobs%ROWTYPE;w jsonb;u bigint;i record;facts jsonb;plan jsonb;bindings jsonb:='[]';d jsonb;prior workflow_collection_routing%ROWTYPE;n integer:=0;
BEGIN
 SELECT * INTO j FROM workflow_collection_jobs WHERE (tenant_id,partner_id,actor_id,id)=(t,p,a,jid);
 IF j.id IS NULL OR NOT j.captured OR j.state<>'captured' OR j.deadline_at<=clock_timestamp() OR freightctl_collection_definition_current(t,p,a,j.definition) IS NOT TRUE THEN RETURN NULL;END IF;
 SELECT authority_revision INTO u FROM credentials WHERE (tenant_id,partner_id,actor_id)=(t,p,a);
 w:=freightctl_collection_routing_target(t,p,a,jid,wid,wver,whash);
 IF w IS NULL THEN RETURN NULL;END IF;
 FOR i IN SELECT input.* FROM workflow_collection_inputs input
  CROSS JOIN LATERAL jsonb_array_elements(j.manifest->'files') WITH ORDINALITY manifest(value,ordinal)
  WHERE (input.tenant_id,input.partner_id,input.actor_id,input.first_job_id)=(t,p,a,jid)
  AND (manifest.value->>'name',manifest.value->>'size_bytes',manifest.value->>'sha256')=(input.source_name,input.size_bytes::text,input.sha256) ORDER BY manifest.ordinal
 LOOP
  n:=n+1;IF n>64 OR i.state<>'accepted' OR i.run_id IS NOT NULL OR i.file_id IS NULL THEN RETURN NULL;END IF;
  facts:=freightctl_collection_original_facts(t,p,a,jid,i.file_id);
  plan:=freightctl_program_compile(w,facts);IF plan IS NULL THEN RETURN NULL;END IF;
  bindings:=bindings||jsonb_build_array(jsonb_build_object('input_id',i.id::text,'file_id',i.file_id::text,'plan_hash',encode(sha256(convert_to(freightctl_program_wire(plan),'UTF8')),'hex')));
 END LOOP;
 IF n<1 OR n<>(SELECT count(*) FROM workflow_collection_inputs WHERE (tenant_id,partner_id,actor_id,first_job_id)=(t,p,a,jid)) THEN RETURN NULL;END IF;
 d:=jsonb_build_object('schema_version',1,'collection',jsonb_build_object('id',j.id::text,'revision',j.revision,'definition_hash',j.definition_hash),'original_workflow',j.definition->'workflow','workflow',jsonb_build_object('id',wid::text,'version',wver,'hash',whash),'manifest_hash',j.manifest_hash,'authority_revision',u,'storage_id',j.definition->>'storage_id','namespace_root',j.definition->>'namespace_root','inputs',bindings);
 SELECT * INTO prior FROM freightctl_collection_routing_choice(t,p,a,jid);
 IF prior.id IS NOT NULL THEN d:=d||jsonb_build_object('previous',jsonb_build_object('id',prior.id::text,'version',prior.version,'definition_hash',prior.definition_hash,'revision',prior.revision));END IF;
 RETURN d;
END $$;

-- Fixed typed wire order matches encoding/json in CollectionRoutingDefinition.
-- Never hash PostgreSQL's presentation whitespace or sorted object key order.
CREATE FUNCTION freightctl_collection_routing_ref_wire(r jsonb) RETURNS text LANGUAGE sql IMMUTABLE AS $$
 SELECT '{"id":'||freightctl_program_quote(r->>'id')||',"version":'||(r->>'version')||',"hash":'||freightctl_program_quote(r->>'hash')||'}'
$$;
CREATE FUNCTION freightctl_collection_routing_wire(d jsonb) RETURNS text LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE out text;i jsonb;separator text:='';r jsonb:=d->'collection';prior jsonb:=d->'previous';
BEGIN
 out:='{"schema_version":1,"collection":{"id":'||freightctl_program_quote(r->>'id')||',"revision":'||(r->>'revision')||',"definition_hash":'||freightctl_program_quote(r->>'definition_hash')||'},"original_workflow":'||freightctl_collection_routing_ref_wire(d->'original_workflow')||',"workflow":'||freightctl_collection_routing_ref_wire(d->'workflow')||',"manifest_hash":'||freightctl_program_quote(d->>'manifest_hash')||',"authority_revision":'||(d->>'authority_revision')||',"storage_id":'||freightctl_program_quote(d->>'storage_id')||',"namespace_root":'||freightctl_program_quote(d->>'namespace_root')||',"inputs":[';
 FOR i IN SELECT value FROM jsonb_array_elements(d->'inputs') LOOP
  out:=out||separator||'{"input_id":'||freightctl_program_quote(i->>'input_id')||',"file_id":'||freightctl_program_quote(i->>'file_id')||',"plan_hash":'||freightctl_program_quote(i->>'plan_hash')||'}';separator:=',';
 END LOOP;
 out:=out||']';
 IF prior IS NOT NULL THEN out:=out||',"previous":{"id":'||freightctl_program_quote(prior->>'id')||',"version":'||(prior->>'version')||',"definition_hash":'||freightctl_program_quote(prior->>'definition_hash')||',"revision":'||(prior->>'revision')||'}';END IF;
 RETURN out||'}';
END $$;

CREATE FUNCTION freightctl_collection_routing_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE e jsonb;expected jsonb;authority bigint;n integer;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'routing authorization history is immutable' USING ERRCODE='23514';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended(NEW.tenant_id::text||':'||NEW.partner_id::text||':workflow-schedules',0));
 IF NOT pg_try_advisory_xact_lock(hashtextextended(NEW.tenant_id::text||':'||NEW.partner_id::text||':workflow-collections',0)) THEN RAISE EXCEPTION 'routing authorization admission is busy' USING ERRCODE='40001';END IF;
 SELECT payload INTO e FROM events WHERE (tenant_id,partner_id,actor_id,event_id,resource_id,kind)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.changed_event_id,NEW.id,'WorkflowCollectionRoutingChanged');
 IF e IS NULL OR e IS DISTINCT FROM (to_jsonb(NEW)-ARRAY['tenant_id','partner_id','actor_id','changed_event_id']) THEN RAISE EXCEPTION 'routing authorization needs its exact journal record' USING ERRCODE='23514';END IF;
 SELECT authority_revision INTO authority FROM credentials WHERE (tenant_id,partner_id,actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id);
 IF TG_OP='INSERT' THEN
  SELECT coalesce(max(version),0)+1 INTO n FROM workflow_collection_routing WHERE (tenant_id,partner_id,actor_id,job_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.job_id);
  IF NEW.version<>n OR NEW.state<>'proposed' OR NEW.revision<>1 OR NEW.approval_authority<>0 THEN RAISE EXCEPTION 'routing begins as a versioned proposal' USING ERRCODE='23514';END IF;
 ELSE
  IF (NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.id,NEW.job_id,NEW.version,NEW.definition,NEW.definition_hash) IS DISTINCT FROM (OLD.tenant_id,OLD.partner_id,OLD.actor_id,OLD.id,OLD.job_id,OLD.version,OLD.definition,OLD.definition_hash) OR NEW.revision<>OLD.revision+1 THEN RAISE EXCEPTION 'routing definition and history are immutable' USING ERRCODE='23514';END IF;
  IF OLD.state='proposed' AND NEW.state='withdrawn' THEN
   IF NEW.approval_authority<>OLD.approval_authority OR freightctl_schedule_owner(NEW.tenant_id,NEW.partner_id,NEW.actor_id,ARRAY['workflow_execute','read']) IS NOT TRUE THEN RAISE EXCEPTION 'withdrawal needs current proposal authority' USING ERRCODE='42501';END IF;
   RETURN NEW;
  ELSIF OLD.state='approved' AND NEW.state='revoked' THEN
   IF NEW.approval_authority<>OLD.approval_authority OR freightctl_schedule_owner(NEW.tenant_id,NEW.partner_id,NEW.actor_id,ARRAY['workflow_approve','read']) IS NOT TRUE THEN RAISE EXCEPTION 'revocation needs current approval authority' USING ERRCODE='42501';END IF;
   RETURN NEW;
  ELSIF OLD.state<>'proposed' OR NEW.state<>'approved' OR NEW.approval_authority IS DISTINCT FROM authority OR freightctl_schedule_owner(NEW.tenant_id,NEW.partner_id,NEW.actor_id,ARRAY['workflow_approve','read']) IS NOT TRUE THEN
   RAISE EXCEPTION 'routing needs a separate current approval' USING ERRCODE='42501';
  END IF;
 END IF;
 expected:=freightctl_collection_routing_definition(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.job_id,(NEW.definition->'workflow'->>'id')::uuid,(NEW.definition->'workflow'->>'version')::integer,NEW.definition->'workflow'->>'hash');
 IF expected IS NULL OR NEW.definition IS DISTINCT FROM expected OR NEW.definition_hash IS DISTINCT FROM encode(sha256(convert_to(freightctl_collection_routing_wire(expected),'UTF8')),'hex') THEN RAISE EXCEPTION 'routing needs exact current capture, prior decision and independently compiled bindings before any run' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER collection_routing_guard BEFORE INSERT OR UPDATE OR DELETE ON workflow_collection_routing FOR EACH ROW EXECUTE FUNCTION freightctl_collection_routing_guard();
CREATE FUNCTION freightctl_collection_routing_projection_complete() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.kind='WorkflowCollectionRoutingChanged' AND NOT EXISTS(SELECT 1 FROM workflow_collection_routing r WHERE (r.tenant_id,r.partner_id,r.actor_id,r.id,r.changed_event_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.resource_id,NEW.event_id)) THEN RAISE EXCEPTION 'routing journal event needs its exact projection' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER collection_routing_projection_complete AFTER INSERT ON events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION freightctl_collection_routing_projection_complete();

-- This guard is used both before run insertion and by the deferred lineage
-- check. Pending proposals have no effect; an effective revocation blocks.
CREATE FUNCTION freightctl_collection_routing_run_matches(t uuid,p uuid,a uuid,jid uuid,rid uuid,wid uuid,wver integer,whash text,fid uuid,plan_hash text) RETURNS boolean LANGUAGE plpgsql STABLE AS $$
DECLARE j workflow_collection_jobs%ROWTYPE;choice workflow_collection_routing%ROWTYPE;
BEGIN
 SELECT * INTO j FROM workflow_collection_jobs WHERE (tenant_id,partner_id,actor_id,id)=(t,p,a,jid);
 IF j.id IS NULL OR freightctl_collection_original_facts(t,p,a,jid,fid) IS NULL THEN RETURN false;END IF;
 SELECT * INTO choice FROM freightctl_collection_routing_choice(t,p,a,jid);
 IF choice.id IS NULL THEN RETURN rid IS NULL AND (j.workflow_id,j.workflow_version,j.workflow_hash)=(wid,wver,whash);END IF;
 RETURN rid IS NOT DISTINCT FROM choice.id AND choice.state='approved'
 AND choice.approval_authority=(choice.definition->>'authority_revision')::bigint
 AND (choice.definition->'workflow'->>'id',choice.definition->'workflow'->>'version',choice.definition->'workflow'->>'hash')=(wid::text,wver::text,whash)
 AND freightctl_collection_routing_target(t,p,a,jid,wid,wver,whash) IS NOT NULL
 AND EXISTS(SELECT 1 FROM jsonb_array_elements(choice.definition->'inputs') binding JOIN workflow_collection_inputs input ON (input.tenant_id,input.partner_id,input.actor_id,input.first_job_id,input.file_id)=(t,p,a,jid,fid) WHERE (binding->>'input_id',binding->>'file_id',binding->>'plan_hash')=(input.id::text,fid::text,plan_hash));
END $$;

CREATE OR REPLACE FUNCTION freightctl_program_run_facts(t uuid,p uuid,a uuid,wid uuid,wver integer,whash text,fid uuid) RETURNS jsonb LANGUAGE plpgsql STABLE AS $$
DECLARE d jsonb;f jsonb;i record;choice workflow_collection_routing%ROWTYPE;facts jsonb;result jsonb;matched integer:=0;
BEGIN
 SELECT definition INTO d FROM workflow_revisions WHERE (tenant_id,partner_id,actor_id,workflow_id,version,definition_hash,state)=(t,p,a,wid,wver,whash,'approved');
 IF d IS NULL OR freightctl_schedule_owner(t,p,a,ARRAY['workflow_execute','read']) IS NOT TRUE OR freightctl_file_available(t,p,fid) IS NOT TRUE THEN RETURN NULL;END IF;
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

CREATE OR REPLACE FUNCTION freightctl_collection_run_complete() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM workflow_revisions w WHERE (w.tenant_id,w.partner_id,w.actor_id,w.workflow_id,w.version)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.workflow_id,NEW.workflow_version) AND w.definition ? 'source') THEN
  IF NOT EXISTS(SELECT 1 FROM workflow_collection_inputs i WHERE (i.tenant_id,i.partner_id,i.actor_id,i.run_id,i.file_id,i.workflow_id,i.state)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.run_id,NEW.file_id,NEW.workflow_id,'queued') AND freightctl_collection_routing_run_matches(NEW.tenant_id,NEW.partner_id,NEW.actor_id,i.first_job_id,NEW.routing_authorization_id,NEW.workflow_id,NEW.workflow_version,NEW.workflow_hash,NEW.file_id,NEW.execution_plan_hash)) THEN RAISE EXCEPTION 'collection run needs its exact original lineage and effective routing approval' USING ERRCODE='23514';END IF;
 ELSIF NEW.routing_authorization_id IS NOT NULL THEN RAISE EXCEPTION 'only captured inputs can use a routing authorization' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION freightctl_collected_run_status(t uuid,p uuid,a uuid,target_run uuid) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT NOT EXISTS(SELECT 1 FROM workflow_collection_inputs WHERE (tenant_id,partner_id,actor_id,run_id)=(t,p,a,target_run)) OR EXISTS(
 SELECT 1 FROM workflow_collection_inputs i JOIN workflow_runs r ON (r.tenant_id,r.partner_id,r.actor_id,r.run_id)=(i.tenant_id,i.partner_id,i.actor_id,i.run_id)
 WHERE (i.tenant_id,i.partner_id,i.actor_id,i.run_id,i.state)=(t,p,a,target_run,'queued') AND freightctl_collection_routing_run_matches(t,p,a,i.first_job_id,r.routing_authorization_id,r.workflow_id,r.workflow_version,r.workflow_hash,r.file_id,r.execution_plan_hash))
$$;

-- Preserve every schema-1/schema-2 run guard and freeze the routing reference.
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
   IF NOT EXISTS(SELECT 1 FROM workflow_collection_inputs i WHERE (i.tenant_id,i.partner_id,i.actor_id,i.workflow_id,i.file_id,i.state)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.workflow_id,NEW.file_id,'accepted') AND i.run_id IS NULL AND freightctl_collection_routing_run_matches(NEW.tenant_id,NEW.partner_id,NEW.actor_id,i.first_job_id,NEW.routing_authorization_id,NEW.workflow_id,NEW.workflow_version,NEW.workflow_hash,NEW.file_id,NEW.execution_plan_hash)) THEN RAISE EXCEPTION 'run needs original captured input and effective routing decision' USING ERRCODE='23514';END IF;
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
