-- Preserve schema-1 run meaning. Schema-2 plans are immutable, actor-private
-- columns on the existing forced-RLS run relation; no default permission changes.
ALTER TABLE workflow_runs ADD COLUMN execution_plan jsonb;
ALTER TABLE workflow_runs ADD COLUMN execution_plan_hash text;
ALTER TABLE workflow_runs ADD CONSTRAINT workflow_plan_pair CHECK((execution_plan IS NULL)=(execution_plan_hash IS NULL));
ALTER TABLE workflow_runs ADD CONSTRAINT workflow_plan_bound CHECK(execution_plan IS NULL OR (jsonb_typeof(execution_plan)='object' AND octet_length(execution_plan::text)<=32768 AND execution_plan_hash ~ '^[0-9a-f]{64}$'));
ALTER TABLE workflow_runs DROP CONSTRAINT workflow_runs_state_check;
ALTER TABLE workflow_runs ADD CONSTRAINT workflow_runs_state_check CHECK(state IN ('queued','running','attention','succeeded','cancelled','kept_local'));
-- Pure, bounded, independently evaluated workflow-program contract. No peer I/O.
CREATE FUNCTION freightctl_program_text(v jsonb) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
 SELECT jsonb_typeof(v)='string' AND octet_length(v#>>'{}') BETWEEN 1 AND 128 AND (v#>>'{}') !~ '[[:cntrl:]]'
$$;
CREATE FUNCTION freightctl_program_field(field text, has_source boolean) RETURNS text LANGUAGE sql IMMUTABLE AS $$
 SELECT CASE WHEN field IN ('file.id','file.sha256','file.policy') THEN 'text' WHEN field='file.size_bytes' THEN 'number' WHEN has_source AND field IN ('source.name','source.batch_id') THEN 'text' WHEN has_source AND field IN ('source.file_count','source.index') THEN 'number' ELSE NULL END
$$;
CREATE FUNCTION freightctl_program_condition_cost(v jsonb,has_source boolean,vars jsonb,depth integer DEFAULT 0) RETURNS integer LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE op text;kind text;child jsonb;terms jsonb;n integer;cost integer:=1;allowed text[];operand text;
BEGIN
 IF depth>3 OR jsonb_typeof(v) IS DISTINCT FROM 'object' OR jsonb_typeof(v->'op') IS DISTINCT FROM 'string' THEN RETURN NULL;END IF;
 op:=v->>'op';
 IF op IN ('all','any','not') THEN
  allowed:=ARRAY['op',op];IF EXISTS(SELECT 1 FROM jsonb_object_keys(v) k WHERE k<>ALL(allowed)) OR NOT (v ? op) THEN RETURN NULL;END IF;
  IF op='not' THEN terms:=jsonb_build_array(v->'not');ELSE terms:=v->op;IF jsonb_typeof(terms) IS DISTINCT FROM 'array' OR jsonb_array_length(terms) NOT BETWEEN 1 AND 16 THEN RETURN NULL;END IF;END IF;
  FOR child IN SELECT value FROM jsonb_array_elements(terms) LOOP n:=freightctl_program_condition_cost(child,has_source,vars,depth+1);IF n IS NULL THEN RETURN NULL;END IF;cost:=cost+n;END LOOP;
 ELSE
  IF EXISTS(SELECT 1 FROM jsonb_object_keys(v) k WHERE k<>ALL(ARRAY['op','field','variable','text','number'])) OR (v ? 'field')=(v ? 'variable') THEN RETURN NULL;END IF;
  IF v ? 'variable' THEN operand:=v->>'variable';IF jsonb_typeof(v->'variable') IS DISTINCT FROM 'string' OR NOT(vars ? operand) THEN RETURN NULL;END IF;kind:='text';
  ELSE IF jsonb_typeof(v->'field') IS DISTINCT FROM 'string' THEN RETURN NULL;END IF;kind:=freightctl_program_field(v->>'field',has_source);END IF;
  IF kind='number' THEN
   IF op NOT IN ('eq','ne','lt','le','gt','ge') OR v ? 'text' OR jsonb_typeof(v->'number') IS DISTINCT FROM 'string' OR (v->>'number') !~ '^(0|[1-9][0-9]{0,18})$' OR (v->>'number')::numeric>9223372036854775807 THEN RETURN NULL;END IF;
  ELSIF kind='text' THEN
   IF op NOT IN ('eq','ne','prefix','suffix','glob') OR v ? 'number' OR freightctl_program_text(v->'text') IS NOT TRUE THEN RETURN NULL;END IF;
   IF op='glob' AND (v->>'text') !~ '^[A-Za-z0-9._*?-]{1,128}$' THEN RETURN NULL;END IF;
   IF v->>'field'='file.sha256' AND (op NOT IN ('eq','ne') OR (v->>'text') !~ '^[0-9a-f]{64}$') THEN RETURN NULL;END IF;
   IF v->>'field' IN ('file.id','source.batch_id') AND (op NOT IN ('eq','ne') OR (v->>'text') !~ '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$') THEN RETURN NULL;END IF;
  ELSE RETURN NULL;END IF;
 END IF;
 RETURN cost;
EXCEPTION WHEN OTHERS THEN RETURN NULL;
END $$;
CREATE FUNCTION freightctl_program_nodes_cost(nodes jsonb,catalog jsonb,has_source boolean,vars jsonb,depth integer DEFAULT 0) RETURNS jsonb LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE node jsonb;kind text;term jsonb;sub jsonb;more jsonb;inner_vars jsonb;key text;cost integer:=0;count_nodes integer:=0;count_conditions integer:=0;k integer;allowed text[];
BEGIN
 IF depth>=4 OR jsonb_typeof(nodes) IS DISTINCT FROM 'array' OR jsonb_array_length(nodes)>64 THEN RETURN NULL;END IF;
 FOR node IN SELECT value FROM jsonb_array_elements(nodes) LOOP
  IF jsonb_typeof(node) IS DISTINCT FROM 'object' OR jsonb_typeof(node->'kind') IS DISTINCT FROM 'string' THEN RETURN NULL;END IF;
  kind:=node->>'kind';count_nodes:=count_nodes+1;cost:=cost+1;
  CASE kind
  WHEN 'deliver' THEN
   allowed:=ARRAY['kind','step','step_variable'];IF (node ? 'step')=(node ? 'step_variable') THEN RETURN NULL;END IF;
   IF node ? 'step' THEN IF jsonb_typeof(node->'step') IS DISTINCT FROM 'string' OR NOT(catalog ? (node->>'step')) THEN RETURN NULL;END IF;
   ELSE IF jsonb_typeof(node->'step_variable') IS DISTINCT FROM 'string' OR NOT(vars ? (node->>'step_variable')) THEN RETURN NULL;END IF;END IF;
  WHEN 'keep_local' THEN
   allowed:=ARRAY['kind','reason'];IF jsonb_typeof(node->'reason') IS DISTINCT FROM 'string' OR (node->>'reason') !~ '^[a-z][a-z0-9_]{0,63}$' THEN RETURN NULL;END IF;
  WHEN 'if' THEN
   allowed:=ARRAY['kind','when','then','else'];IF jsonb_typeof(node->'then') IS DISTINCT FROM 'array' OR jsonb_array_length(node->'then')<1 THEN RETURN NULL;END IF;
   k:=freightctl_program_condition_cost(node->'when',has_source,vars);IF k IS NULL THEN RETURN NULL;END IF;cost:=cost+k;count_conditions:=count_conditions+k;
   sub:=freightctl_program_nodes_cost(node->'then',catalog,has_source,vars,depth+1);IF sub IS NULL THEN RETURN NULL;END IF;
   more:=freightctl_program_nodes_cost(coalesce(node->'else','[]'::jsonb),catalog,has_source,vars,depth+1);IF more IS NULL THEN RETURN NULL;END IF;
   cost:=cost+(sub->>'cost')::integer+(more->>'cost')::integer;count_nodes:=count_nodes+(sub->>'nodes')::integer+(more->>'nodes')::integer;count_conditions:=count_conditions+(sub->>'conditions')::integer+(more->>'conditions')::integer;
  WHEN 'for_each' THEN
   allowed:=ARRAY['kind','variable','steps','body'];key:=node->>'variable';
   IF jsonb_typeof(node->'variable') IS DISTINCT FROM 'string' OR key !~ '^[a-z][a-z0-9_]{0,63}$' OR vars ? key OR jsonb_typeof(node->'steps') IS DISTINCT FROM 'array' OR jsonb_array_length(node->'steps') NOT BETWEEN 1 AND 16 OR jsonb_typeof(node->'body') IS DISTINCT FROM 'array' OR jsonb_array_length(node->'body')<1 THEN RETURN NULL;END IF;
   IF EXISTS(SELECT 1 FROM jsonb_array_elements(node->'steps') e WHERE jsonb_typeof(e) IS DISTINCT FROM 'string' OR NOT(catalog ? (e#>>'{}'))) OR (SELECT count(DISTINCT e) FROM jsonb_array_elements(node->'steps') e)<>jsonb_array_length(node->'steps') THEN RETURN NULL;END IF;
   inner_vars:=vars||jsonb_build_object(key,true);sub:=freightctl_program_nodes_cost(node->'body',catalog,has_source,inner_vars,depth+1);IF sub IS NULL THEN RETURN NULL;END IF;
   cost:=cost+jsonb_array_length(node->'steps')*(sub->>'cost')::integer;count_nodes:=count_nodes+(sub->>'nodes')::integer;count_conditions:=count_conditions+(sub->>'conditions')::integer;
  ELSE RETURN NULL;
  END CASE;
  IF EXISTS(SELECT 1 FROM jsonb_object_keys(node) AS members(name) WHERE members.name<>ALL(allowed)) OR cost>256 OR count_nodes>64 OR count_conditions>64 THEN RETURN NULL;END IF;
 END LOOP;
 RETURN jsonb_build_object('cost',cost,'nodes',count_nodes,'conditions',count_conditions);
EXCEPTION WHEN OTHERS THEN RETURN NULL;
END $$;
CREATE FUNCTION freightctl_program_condition(v jsonb,facts jsonb,vars jsonb) RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE op text:=v->>'op';term jsonb;result boolean;lhs jsonb;rhs jsonb;n bigint;m bigint;field text;pattern text;ch text;i integer;
BEGIN
 IF op='not' THEN RETURN NOT freightctl_program_condition(v->'not',facts,vars);END IF;
 IF op IN ('all','any') THEN
  FOR term IN SELECT value FROM jsonb_array_elements(v->op) LOOP result:=freightctl_program_condition(term,facts,vars);IF result IS NULL THEN RETURN NULL;END IF;IF op='all' AND NOT result THEN RETURN false;END IF;IF op='any' AND result THEN RETURN true;END IF;END LOOP;
  RETURN op='all';
 END IF;
 IF v ? 'variable' THEN lhs:=vars->(v->>'variable');ELSE field:=v->>'field';lhs:=facts->split_part(field,'.',1)->split_part(field,'.',2);END IF;
 IF lhs IS NULL THEN RETURN NULL;END IF;
 IF v ? 'number' THEN
  IF jsonb_typeof(lhs) IS DISTINCT FROM 'number' THEN RETURN NULL;END IF;n:=(lhs#>>'{}')::bigint;m:=(v->>'number')::bigint;
  RETURN CASE op WHEN 'eq' THEN n=m WHEN 'ne' THEN n<>m WHEN 'lt' THEN n<m WHEN 'le' THEN n<=m WHEN 'gt' THEN n>m WHEN 'ge' THEN n>=m ELSE NULL END;
 END IF;
 IF jsonb_typeof(lhs) IS DISTINCT FROM 'string' THEN RETURN NULL;END IF;rhs:=v->'text';
 CASE op
 WHEN 'eq' THEN RETURN lhs=rhs;
 WHEN 'ne' THEN RETURN lhs<>rhs;
 WHEN 'prefix' THEN RETURN left(lhs#>>'{}',length(rhs#>>'{}'))=(rhs#>>'{}');
 WHEN 'suffix' THEN RETURN right(lhs#>>'{}',length(rhs#>>'{}'))=(rhs#>>'{}');
 WHEN 'glob' THEN
  pattern:='^';FOR i IN 1..length(rhs#>>'{}') LOOP ch:=substr(rhs#>>'{}',i,1);pattern:=pattern||CASE ch WHEN '*' THEN '.*' WHEN '?' THEN '.' WHEN '.' THEN '[.]' ELSE ch END;END LOOP;pattern:=pattern||'$';RETURN (lhs#>>'{}') ~ pattern;
 ELSE RETURN NULL;
 END CASE;
EXCEPTION WHEN OTHERS THEN RETURN NULL;
END $$;
CREATE FUNCTION freightctl_program_nodes(nodes jsonb,facts jsonb,vars jsonb,prefix text DEFAULT '') RETURNS jsonb LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE node jsonb;kind text;position integer:=0;path text;selected jsonb:='[]';decisions jsonb:='[]';local_reason text;part jsonb;item jsonb;index integer;matched boolean;step text;branch jsonb;suffix text;
BEGIN
 FOR node IN SELECT value FROM jsonb_array_elements(nodes) LOOP
  path:=prefix||position::text;position:=position+1;kind:=node->>'kind';part:=NULL;
  CASE kind
  WHEN 'deliver' THEN
   step:=coalesce(node->>'step',vars->>(node->>'step_variable'));IF step IS NULL OR local_reason IS NOT NULL THEN RETURN NULL;END IF;
   selected:=selected||to_jsonb(step);decisions:=decisions||jsonb_build_object('path',path,'kind',kind,'step',step);
  WHEN 'keep_local' THEN
   IF local_reason IS NOT NULL OR jsonb_array_length(selected)>0 THEN RETURN NULL;END IF;local_reason:=node->>'reason';decisions:=decisions||jsonb_build_object('path',path,'kind',kind,'reason',local_reason);
  WHEN 'if' THEN
   matched:=freightctl_program_condition(node->'when',facts,vars);IF matched IS NULL THEN RETURN NULL;END IF;
   decisions:=decisions||jsonb_build_object('path',path,'kind',kind,'matched',matched);IF matched THEN branch:=node->'then';suffix:='.then.';ELSE branch:=coalesce(node->'else','[]');suffix:='.else.';END IF;
   part:=freightctl_program_nodes(branch,facts,vars,path||suffix);IF part IS NULL THEN RETURN NULL;END IF;
  WHEN 'for_each' THEN
   decisions:=decisions||jsonb_build_object('path',path,'kind',kind,'variable',node->>'variable','steps',node->'steps');index:=0;
   FOR item IN SELECT value FROM jsonb_array_elements(node->'steps') LOOP
    part:=freightctl_program_nodes(node->'body',facts,vars||jsonb_build_object(node->>'variable',item),path||'['||index::text||'].body.');index:=index+1;IF part IS NULL THEN RETURN NULL;END IF;
    IF part ? 'local_reason' THEN IF local_reason IS NOT NULL THEN RETURN NULL;END IF;local_reason:=part->>'local_reason';END IF;
    selected:=selected||(part->'selected_steps');decisions:=decisions||(part->'decisions');part:=NULL;
   END LOOP;
  ELSE RETURN NULL;
  END CASE;
  IF part IS NOT NULL THEN
   IF part ? 'local_reason' THEN IF local_reason IS NOT NULL THEN RETURN NULL;END IF;local_reason:=part->>'local_reason';END IF;
   selected:=selected||(part->'selected_steps');decisions:=decisions||(part->'decisions');
  END IF;
  IF (local_reason IS NOT NULL AND jsonb_array_length(selected)>0) OR (SELECT count(DISTINCT e) FROM jsonb_array_elements(selected) e)<>jsonb_array_length(selected) THEN RETURN NULL;END IF;
 END LOOP;
 RETURN jsonb_build_object('selected_steps',selected,'decisions',decisions)||CASE WHEN local_reason IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('local_reason',local_reason) END;
EXCEPTION WHEN OTHERS THEN RETURN NULL;
END $$;
CREATE FUNCTION freightctl_program_compile(d jsonb,facts jsonb) RETURNS jsonb LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE catalog jsonb:='{}';item jsonb;key text;stat jsonb;result jsonb;f jsonb;s jsonb;
BEGIN
 IF d->'schema_version' IS DISTINCT FROM '2'::jsonb OR jsonb_typeof(d->'program') IS DISTINCT FROM 'object' OR (d->'program')-'nodes'<>'{}'::jsonb OR jsonb_typeof(d->'program'->'nodes') IS DISTINCT FROM 'array' OR jsonb_array_length(d->'program'->'nodes')<1 OR jsonb_typeof(d->'steps') IS DISTINCT FROM 'array' OR jsonb_array_length(d->'steps')>16 OR jsonb_typeof(facts) IS DISTINCT FROM 'object' OR facts-ARRAY['file','source']<>'{}'::jsonb THEN RETURN NULL;END IF;
 FOR item IN SELECT value FROM jsonb_array_elements(d->'steps') LOOP
  key:=item->>'id';IF item->>'kind' IS DISTINCT FROM 'sftp.deliver' OR key IS NULL OR key !~ '^[a-z][a-z0-9_]{0,63}$' OR catalog ? key THEN RETURN NULL;END IF;catalog:=catalog||jsonb_build_object(key,true);
 END LOOP;
 f:=facts->'file';IF EXISTS(SELECT 1 FROM unnest(ARRAY['id','accepted_event_id','sha256','policy']) k WHERE jsonb_typeof(f->k) IS DISTINCT FROM 'string') THEN RETURN NULL;END IF;IF jsonb_typeof(f) IS DISTINCT FROM 'object' OR ARRAY(SELECT jsonb_object_keys(f) ORDER BY 1) IS DISTINCT FROM ARRAY['accepted_event_id','id','policy','sha256','size_bytes']::text[] OR jsonb_typeof(f->'size_bytes') IS DISTINCT FROM 'number' OR f->>'size_bytes' !~ '^(0|[1-9][0-9]*)$' OR (f->>'size_bytes')::numeric>1073741824 OR f->>'id' !~ '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$' OR f->>'accepted_event_id' !~ '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$' OR f->>'sha256' !~ '^[0-9a-f]{64}$' OR freightctl_program_text(f->'policy') IS NOT TRUE THEN RETURN NULL;END IF;
 IF d ? 'source' THEN
  s:=facts->'source';IF EXISTS(SELECT 1 FROM unnest(ARRAY['collection_id','manifest_hash','name','batch_id']) k WHERE jsonb_typeof(s->k) IS DISTINCT FROM 'string') THEN RETURN NULL;END IF;IF jsonb_typeof(s) IS DISTINCT FROM 'object' OR ARRAY(SELECT jsonb_object_keys(s) ORDER BY 1) IS DISTINCT FROM ARRAY['batch_id','collection_id','file_count','index','manifest_hash','name']::text[] OR s->>'collection_id' !~ '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$' OR s->>'batch_id' !~ '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$' OR s->>'manifest_hash' !~ '^[0-9a-f]{64}$' OR s->>'name' !~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$' OR right(s->>'name',11)='.ready.json' OR jsonb_typeof(s->'file_count') IS DISTINCT FROM 'number' OR jsonb_typeof(s->'index') IS DISTINCT FROM 'number' OR s->>'file_count' !~ '^[1-9][0-9]*$' OR s->>'index' !~ '^(0|[1-9][0-9]*)$' OR (s->>'file_count')::integer>(d->'source'->>'max_files')::integer OR (s->>'index')::integer>=(s->>'file_count')::integer OR (f->>'size_bytes')::bigint>(d->'source'->>'max_file_bytes')::bigint THEN RETURN NULL;END IF;
 ELSIF facts ? 'source' THEN RETURN NULL;END IF;
 stat:=freightctl_program_nodes_cost(d->'program'->'nodes',catalog,d ? 'source','{}');IF stat IS NULL THEN RETURN NULL;END IF;
 result:=freightctl_program_nodes(d->'program'->'nodes',facts,'{}');IF result IS NULL OR (jsonb_array_length(result->'selected_steps')=0 AND NOT(result ? 'local_reason')) THEN RETURN NULL;END IF;
 result:=jsonb_build_object('schema_version',1,'facts',facts)||result;IF octet_length(result::text)>32768 THEN RETURN NULL;END IF;RETURN result;
EXCEPTION WHEN OTHERS THEN RETURN NULL;
END $$;
-- Exact schema-1 plan wire order, matching Go's typed encoding. Database SHA-256
-- is only a metadata fingerprint; no key operation or custom cryptography.
CREATE FUNCTION freightctl_program_quote(v text) RETURNS text LANGUAGE sql IMMUTABLE STRICT AS $$
 SELECT replace(replace(replace(replace(replace(to_jsonb(v)::text,'<',chr(92)||'u003c'),'>',chr(92)||'u003e'),'&',chr(92)||'u0026'),chr(8232),chr(92)||'u2028'),chr(8233),chr(92)||'u2029')
$$;
CREATE FUNCTION freightctl_program_strings(v jsonb) RETURNS text LANGUAGE sql IMMUTABLE AS $$
 SELECT '['||coalesce(string_agg(freightctl_program_quote(value#>>'{}'),',' ORDER BY ordinal),'')||']' FROM jsonb_array_elements(v) WITH ORDINALITY a(value,ordinal)
$$;
CREATE FUNCTION freightctl_program_wire(plan jsonb) RETURNS text LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE f jsonb:=plan->'facts'->'file';s jsonb:=plan->'facts'->'source';out text;item jsonb;part text;separator text:='';
BEGIN
 out:='{"schema_version":1,"facts":{"file":{"id":'||freightctl_program_quote(f->>'id')||',"size_bytes":'||(f->>'size_bytes')||',"sha256":'||freightctl_program_quote(f->>'sha256')||',"policy":'||freightctl_program_quote(f->>'policy')||',"accepted_event_id":'||freightctl_program_quote(f->>'accepted_event_id')||'}';
 IF s IS NOT NULL THEN out:=out||',"source":{"collection_id":'||freightctl_program_quote(s->>'collection_id')||',"manifest_hash":'||freightctl_program_quote(s->>'manifest_hash')||',"name":'||freightctl_program_quote(s->>'name')||',"batch_id":'||freightctl_program_quote(s->>'batch_id')||',"file_count":'||(s->>'file_count')||',"index":'||(s->>'index')||'}';END IF;
 out:=out||'},"selected_steps":'||freightctl_program_strings(plan->'selected_steps')||',"decisions":[';
 FOR item IN SELECT value FROM jsonb_array_elements(plan->'decisions') LOOP
  part:='{"path":'||freightctl_program_quote(item->>'path')||',"kind":'||freightctl_program_quote(item->>'kind');
  IF item ? 'matched' THEN part:=part||',"matched":'||(item->>'matched');END IF;
  IF item ? 'step' THEN part:=part||',"step":'||freightctl_program_quote(item->>'step');END IF;
  IF item ? 'variable' THEN part:=part||',"variable":'||freightctl_program_quote(item->>'variable');END IF;
  IF item ? 'steps' THEN part:=part||',"steps":'||freightctl_program_strings(item->'steps');END IF;
  IF item ? 'reason' THEN part:=part||',"reason":'||freightctl_program_quote(item->>'reason');END IF;
  out:=out||separator||part||'}';separator:=',';
 END LOOP;
 out:=out||']';IF plan ? 'local_reason' THEN out:=out||',"local_reason":'||freightctl_program_quote(plan->>'local_reason');END IF;
 RETURN out||'}';
END $$;
CREATE FUNCTION freightctl_program_run_facts(t uuid,p uuid,a uuid,wid uuid,wver integer,whash text,fid uuid) RETURNS jsonb LANGUAGE plpgsql STABLE AS $$
DECLARE d jsonb;f jsonb;candidate record;source jsonb;matched integer:=0;
BEGIN
 SELECT w.definition INTO d FROM workflow_revisions w WHERE (w.tenant_id,w.partner_id,w.actor_id,w.workflow_id,w.version,w.definition_hash,w.state)=(t,p,a,wid,wver,whash,'approved');
 IF d IS NULL OR NOT freightctl_schedule_owner(t,p,a,ARRAY['workflow_execute','read']) OR freightctl_file_available(t,p,fid) IS NOT TRUE THEN RETURN NULL;END IF;
 SELECT jsonb_build_object('id',file_id::text,'size_bytes',size_bytes,'sha256',sha256,'policy',policy,'accepted_event_id',accepted_event_id::text) INTO f FROM files WHERE (tenant_id,partner_id,file_id)=(t,p,fid);
 IF f IS NULL THEN RETURN NULL;END IF;
 IF NOT(d ? 'source') THEN RETURN jsonb_build_object('file',f);END IF;
 FOR candidate IN
  SELECT j.id,j.manifest_hash,i.source_name,j.manifest->>'batch_id' AS batch_id,jsonb_array_length(j.manifest->'files') AS file_count,manifest.ordinal-1 AS item_index
  FROM workflow_collection_inputs i JOIN workflow_collection_jobs j ON (j.tenant_id,j.partner_id,j.actor_id,j.id)=(i.tenant_id,i.partner_id,i.actor_id,i.first_job_id)
  CROSS JOIN LATERAL jsonb_array_elements(j.manifest->'files') WITH ORDINALITY manifest(value,ordinal)
  WHERE (i.tenant_id,i.partner_id,i.actor_id,i.workflow_id,i.file_id)=(t,p,a,wid,fid) AND (j.workflow_version,j.workflow_hash)=(wver,whash) AND j.captured AND j.state='captured' AND j.deadline_at>clock_timestamp()
  AND j.definition->'source'=d->'source' AND freightctl_collection_definition_current(t,p,a,j.definition)
  AND manifest.value->>'name'=i.source_name AND manifest.value->>'size_bytes'=i.size_bytes::text AND manifest.value->>'sha256'=i.sha256
  AND NOT EXISTS(SELECT 1 FROM workflow_collection_inputs sibling WHERE (sibling.tenant_id,sibling.partner_id,sibling.actor_id,sibling.first_job_id)=(t,p,a,j.id) AND (sibling.file_id IS NULL OR freightctl_file_available(t,p,sibling.file_id) IS NOT TRUE))
 LOOP
  matched:=matched+1;
  source:=jsonb_build_object('collection_id',candidate.id::text,'manifest_hash',candidate.manifest_hash,'name',candidate.source_name,'batch_id',candidate.batch_id,'file_count',candidate.file_count,'index',candidate.item_index);
 END LOOP;
 IF matched<>1 THEN RETURN NULL;END IF;
 RETURN jsonb_build_object('file',f,'source',source);
END $$;
CREATE FUNCTION freightctl_planned_step(d jsonb,plan jsonb,ordinal integer) RETURNS jsonb LANGUAGE sql IMMUTABLE AS $$
 SELECT CASE WHEN d->>'schema_version'='1' AND plan IS NULL THEN d->'steps'->(ordinal-1)
 WHEN d->>'schema_version'='2' AND plan IS NOT NULL THEN (SELECT value FROM jsonb_array_elements(d->'steps') WHERE value->>'id'=plan->'selected_steps'->>(ordinal-1)) ELSE NULL END
$$;
CREATE FUNCTION freightctl_collection_needs_routing(t uuid,p uuid,a uuid,d jsonb) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT jsonb_array_length(d->'effects')>0 OR EXISTS(SELECT 1 FROM workflow_revisions w WHERE (w.tenant_id,w.partner_id,w.actor_id,w.workflow_id,w.version,w.definition_hash)=(t,p,a,(d->'workflow'->>'id')::uuid,(d->'workflow'->>'version')::integer,d->'workflow'->>'hash') AND w.definition->>'schema_version'='2')
$$;
CREATE OR REPLACE FUNCTION freightctl_run_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE p jsonb;d jsonb;facts jsonb;expected jsonb;
BEGIN
 SELECT payload INTO p FROM events WHERE (tenant_id,partner_id,event_id)=(NEW.tenant_id,NEW.partner_id,NEW.changed_event_id) AND actor_id=NEW.actor_id AND resource_id=NEW.run_id AND kind='WorkflowRunChanged';
 IF p IS NULL OR p->>'id' IS DISTINCT FROM NEW.run_id::text OR p->>'workflow_id' IS DISTINCT FROM NEW.workflow_id::text OR p->>'workflow_version' IS DISTINCT FROM NEW.workflow_version::text OR p->>'workflow_hash' IS DISTINCT FROM NEW.workflow_hash OR p->>'file_id' IS DISTINCT FROM NEW.file_id::text OR p->'source' IS DISTINCT FROM NEW.source OR p->>'storage_id' IS DISTINCT FROM NEW.storage_id::text OR p->>'namespace_root' IS DISTINCT FROM NEW.namespace_root OR p->>'authority_revision' IS DISTINCT FROM NEW.authority_revision::text OR p->>'state' IS DISTINCT FROM NEW.state OR p->>'reason' IS DISTINCT FROM NEW.reason OR p->>'revision' IS DISTINCT FROM NEW.revision::text THEN
  RAISE EXCEPTION 'workflow run requires its exact event' USING ERRCODE='23514';END IF;
 IF NEW.execution_plan IS DISTINCT FROM p->'execution_plan' OR coalesce(NEW.execution_plan_hash,'') IS DISTINCT FROM coalesce(p->>'execution_plan_hash','') THEN RAISE EXCEPTION 'run plan requires its exact journal record' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN
  SELECT definition INTO d FROM workflow_revisions WHERE (tenant_id,partner_id,actor_id,workflow_id,version)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.workflow_id,NEW.workflow_version);
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
CREATE OR REPLACE FUNCTION freightctl_workflow_step_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE e jsonb; planned jsonb;
BEGIN
 IF NOT EXISTS(SELECT 1 FROM delivery_intents d WHERE (d.tenant_id,d.partner_id,d.actor_id,d.delivery_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.delivery_id) AND d.definition ? 'workflow_binding') THEN RAISE EXCEPTION 'workflow step requires a bound delivery' USING ERRCODE='23514';END IF;
 SELECT payload INTO e FROM events WHERE (tenant_id,partner_id,event_id)=(NEW.tenant_id,NEW.partner_id,NEW.created_event_id) AND actor_id=NEW.actor_id AND resource_id=NEW.run_id AND kind='WorkflowStepBound';
 SELECT freightctl_planned_step(w.definition,r.execution_plan,NEW.ordinal) INTO planned FROM workflow_runs r JOIN workflow_revisions w ON (w.tenant_id,w.partner_id,w.workflow_id,w.version)=(r.tenant_id,r.partner_id,r.workflow_id,r.workflow_version) WHERE (r.tenant_id,r.partner_id,r.run_id,r.actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.run_id,NEW.actor_id);
 IF e IS NULL OR e->>'run_id' IS DISTINCT FROM NEW.run_id::text OR e->>'step_id' IS DISTINCT FROM NEW.step_id OR e->>'ordinal' IS DISTINCT FROM NEW.ordinal::text OR e->>'delivery_id' IS DISTINCT FROM NEW.delivery_id::text OR e->>'connection_id' IS DISTINCT FROM NEW.connection_id::text OR e->>'connection_version' IS DISTINCT FROM NEW.connection_version::text OR e->>'connection_hash' IS DISTINCT FROM NEW.connection_hash OR planned->>'id' IS DISTINCT FROM NEW.step_id OR planned->>'kind' IS DISTINCT FROM 'sftp.deliver' OR planned->'connection'->>'id' IS DISTINCT FROM NEW.connection_id::text OR planned->'connection'->>'version' IS DISTINCT FROM NEW.connection_version::text OR planned->'connection'->>'hash' IS DISTINCT FROM NEW.connection_hash THEN
  RAISE EXCEPTION 'step must match its exact workflow and binding event' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION freightctl_workflow_binding_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.definition ? 'workflow_binding' AND NOT EXISTS(
  SELECT 1 FROM workflow_steps s JOIN workflow_runs r USING(tenant_id,partner_id,run_id) JOIN workflow_revisions w ON (w.tenant_id,w.partner_id,w.workflow_id,w.version)=(r.tenant_id,r.partner_id,r.workflow_id,r.workflow_version) JOIN connection_revisions c ON (c.tenant_id,c.partner_id,c.connection_id,c.version)=(s.tenant_id,s.partner_id,s.connection_id,s.connection_version)
  WHERE (s.tenant_id,s.partner_id,s.actor_id,s.delivery_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.delivery_id)
  AND NEW.definition->'workflow_binding'=jsonb_build_object('workflow_id',r.workflow_id::text,'workflow_version',r.workflow_version,'workflow_hash',r.workflow_hash,'run_id',r.run_id::text,'step_id',s.step_id,'connection_id',s.connection_id::text,'connection_version',s.connection_version,'connection_hash',s.connection_hash)
  AND NEW.definition->'source'=r.source AND NEW.file_id=r.file_id AND NEW.definition->>'storage_id'=r.storage_id::text AND NEW.definition->>'namespace_root'=r.namespace_root AND NEW.definition->>'authority_revision'=r.authority_revision::text
  AND NEW.definition->'destination'=c.definition->'destination' AND NEW.definition->>'directory'=c.definition->>'directory' AND NEW.definition->>'filename'=freightctl_planned_step(w.definition,r.execution_plan,s.ordinal)->>'filename' AND c.definition_hash=s.connection_hash) THEN
  RAISE EXCEPTION 'delivery requires exact workflow run, step, source and connection bindings' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION freightctl_workflow_run_complete() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM workflow_revisions w WHERE (w.tenant_id,w.partner_id,w.workflow_id,w.version)=(NEW.tenant_id,NEW.partner_id,NEW.workflow_id,NEW.workflow_version) AND CASE WHEN w.definition->>'schema_version'='1' THEN jsonb_array_length(w.definition->'steps') ELSE jsonb_array_length(NEW.execution_plan->'selected_steps') END=(SELECT count(*) FROM workflow_steps s WHERE (s.tenant_id,s.partner_id,s.run_id)=(NEW.tenant_id,NEW.partner_id,NEW.run_id))) THEN
  RAISE EXCEPTION 'run must bind all workflow step intents atomically' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION freightctl_encrypted_delivery_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.definition ? 'workflow_binding' AND NOT EXISTS(SELECT 1 FROM workflow_steps s JOIN workflow_runs r USING(tenant_id,partner_id,run_id) JOIN workflow_revisions w ON (w.tenant_id,w.partner_id,w.workflow_id,w.version)=(r.tenant_id,r.partner_id,r.workflow_id,r.workflow_version) WHERE (s.tenant_id,s.partner_id,s.delivery_id)=(NEW.tenant_id,NEW.partner_id,NEW.delivery_id) AND NEW.definition->'encryption' IS NOT DISTINCT FROM freightctl_planned_step(w.definition,r.execution_plan,s.ordinal)->'encryption') THEN RAISE EXCEPTION 'delivery encryption must match approved workflow step' USING ERRCODE='23514';END IF;
 IF NEW.definition ? 'encryption' THEN
  IF NEW.state IN ('draft','queued','staging','publishing') AND NOT EXISTS(SELECT 1 FROM pgp_keys k WHERE (k.tenant_id,k.partner_id,k.key_id,k.version,k.definition_hash,k.state)=(NEW.tenant_id,NEW.partner_id,(NEW.definition->'encryption'->'key'->>'id')::uuid,(NEW.definition->'encryption'->'key'->>'version')::integer,NEW.definition->'encryption'->'key'->>'hash','active') AND k.definition->>'purpose'='encrypt' AND (k.valid_until IS NULL OR k.valid_until>clock_timestamp()) AND k.definition->'recipient'->'profiles' ? (NEW.definition->'encryption'->>'profile')) THEN RAISE EXCEPTION 'delivery requires exact live encryption recipient' USING ERRCODE='23514';END IF;
  IF NEW.state IN ('publishing','succeeded') AND NOT EXISTS(SELECT 1 FROM delivery_ciphertexts c WHERE (c.tenant_id,c.partner_id,c.actor_id,c.delivery_id,c.definition_hash,c.source_file_id,c.source_sha256)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.delivery_id,NEW.definition_hash,NEW.file_id,NEW.definition->'source'->>'sha256') AND c.encryption=NEW.definition->'encryption' AND (NEW.state<>'succeeded' OR (NEW.observation->>'sha256'=c.sha256 AND NEW.observation->>'size_bytes'=c.size_bytes::text))) THEN RAISE EXCEPTION 'encrypted publication requires exact durable ciphertext proof' USING ERRCODE='23514';END IF;
 END IF;RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION freightctl_schedule_arrival_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE e jsonb;d jsonb;s workflow_schedules%ROWTYPE;arrival_end timestamptz;execution_end timestamptz;poll integer;max_probes integer;live boolean;n integer;claimed_at timestamptz;journal_at timestamptz;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'arrival history is immutable' USING ERRCODE='23514';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id::text||':'||NEW.partner_id::text||':workflow-schedules',0));
 SELECT payload,happened_at INTO e,journal_at FROM events WHERE (tenant_id,partner_id,actor_id,event_id,resource_id,kind)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.changed_event_id,NEW.occurrence_id,'WorkflowScheduleArrivalChanged');
 IF e IS NULL OR (e-ARRAY['lease_owner','lease_until','next_probe_at','observed_at']) IS DISTINCT FROM (to_jsonb(NEW)-ARRAY['tenant_id','partner_id','actor_id','changed_event_id','lease_owner','lease_until','next_probe_at','observed_at']) OR e->>'lease_owner' IS DISTINCT FROM coalesce(NEW.lease_owner::text,'') OR (e->>'lease_until')::timestamptz IS DISTINCT FROM NEW.lease_until OR (e->>'next_probe_at')::timestamptz IS DISTINCT FROM NEW.next_probe_at OR (e->>'observed_at')::timestamptz IS DISTINCT FROM NEW.observed_at THEN RAISE EXCEPTION 'arrival requires its exact journal record' USING ERRCODE='23514';END IF;
 d:=NEW.definition;
 IF (NEW.schedule_id,NEW.schedule_version,NEW.occurrence_id) IS DISTINCT FROM ((d->'schedule'->>'id')::uuid,(d->'schedule'->>'version')::integer,(d->>'occurrence_id')::uuid) OR freightctl_arrival_definition_valid(NEW.tenant_id,NEW.partner_id,NEW.actor_id,d) IS NOT TRUE THEN RAISE EXCEPTION 'arrival must bind one exact reviewed calendar occurrence' USING ERRCODE='23514';END IF;
 SELECT * INTO s FROM workflow_schedules WHERE (tenant_id,partner_id,actor_id,schedule_id,version)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.schedule_id,NEW.schedule_version);
 arrival_end:=(d->>'arrival_deadline_at')::timestamptz;execution_end:=(d->>'deadline_at')::timestamptz;poll:=(s.definition->'collection'->'arrival'->>'poll_interval_seconds')::integer;
 max_probes:=((s.definition->'collection'->'arrival'->>'arrival_deadline_seconds')::integer+poll-1)/poll+1;
 IF NEW.next_probe_at<(d->>'due_at')::timestamptz OR NEW.next_probe_at>arrival_end OR NEW.probes>max_probes THEN RAISE EXCEPTION 'arrival probe times and count exceed approved bounds' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN
  IF NOT freightctl_schedule_owner(NEW.tenant_id,NEW.partner_id,NEW.actor_id,ARRAY['workflow_execute']) THEN RAISE EXCEPTION 'arrival creation requires current scheduler identity' USING ERRCODE='42501';END IF;
  IF NEW.revision<>1 OR NEW.probes<>0 OR NEW.fence<>0 OR NEW.lease_owner IS NOT NULL OR NEW.manifest IS NOT NULL OR NEW.collection_id IS NOT NULL OR NEW.next_probe_at<>(d->>'due_at')::timestamptz OR NEW.state NOT IN ('waiting','missing') OR (NEW.state='waiting') IS DISTINCT FROM (clock_timestamp()<arrival_end) OR freightctl_arrival_current(NEW.tenant_id,NEW.partner_id,NEW.actor_id,d) IS NOT TRUE THEN RAISE EXCEPTION 'arrival begins as current bounded waiting intent or elapsed window' USING ERRCODE='23514';END IF;
  IF NEW.state='waiting' THEN
   SELECT count(*) INTO n FROM workflow_schedule_arrivals prior JOIN workflow_schedules active ON (active.tenant_id,active.partner_id,active.actor_id,active.schedule_id,active.version,active.state)=(prior.tenant_id,prior.partner_id,prior.actor_id,prior.schedule_id,prior.schedule_version,'active') LEFT JOIN workflow_collection_jobs j ON (j.tenant_id,j.partner_id,j.id)=(prior.tenant_id,prior.partner_id,prior.collection_id)
   WHERE (prior.tenant_id,prior.partner_id,prior.actor_id,prior.schedule_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.schedule_id) AND (prior.definition->>'deadline_at')::timestamptz>clock_timestamp()
   AND ((prior.state='ready' OR (prior.state IN ('waiting','probing','attention') AND (prior.definition->>'arrival_deadline_at')::timestamptz>clock_timestamp())) OR (prior.state='admitted' AND j.state NOT IN ('cancelled','expired') AND (NOT j.captured OR (freightctl_collection_needs_routing(j.tenant_id,j.partner_id,j.actor_id,j.definition) AND EXISTS(SELECT 1 FROM workflow_collection_inputs i LEFT JOIN workflow_runs r ON (r.tenant_id,r.partner_id,r.run_id)=(i.tenant_id,i.partner_id,i.run_id) WHERE (i.tenant_id,i.partner_id,i.actor_id,i.first_job_id)=(prior.tenant_id,prior.partner_id,prior.actor_id,prior.collection_id) AND (i.state<>'queued' OR r.state NOT IN ('succeeded','cancelled','kept_local')))))));
   IF n>=(s.definition->>'max_active_runs')::integer THEN RAISE EXCEPTION 'source occurrence concurrency budget exhausted' USING ERRCODE='23514';END IF;
  END IF;

 ELSE
  IF NOT freightctl_schedule_owner(NEW.tenant_id,NEW.partner_id,NEW.actor_id,ARRAY['workflow_execute']) THEN RAISE EXCEPTION 'arrival mutation requires current executor identity' USING ERRCODE='42501';END IF;
  IF (NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.occurrence_id,NEW.schedule_id,NEW.schedule_version,NEW.definition,NEW.definition_hash) IS DISTINCT FROM (OLD.tenant_id,OLD.partner_id,OLD.actor_id,OLD.occurrence_id,OLD.schedule_id,OLD.schedule_version,OLD.definition,OLD.definition_hash) OR NEW.revision<>OLD.revision+1 OR OLD.state IN ('missing','expired','cancelled') OR (OLD.manifest IS NOT NULL AND (NEW.manifest,NEW.manifest_hash,NEW.observed_at) IS DISTINCT FROM (OLD.manifest,OLD.manifest_hash,OLD.observed_at)) OR (OLD.collection_id IS NOT NULL AND NEW.collection_id IS DISTINCT FROM OLD.collection_id) THEN RAISE EXCEPTION 'arrival definition, observation and history are immutable' USING ERRCODE='23514';END IF;
  live:=OLD.state='probing' AND OLD.lease_until>clock_timestamp() AND clock_timestamp()<arrival_end;
  SELECT happened_at INTO claimed_at FROM events WHERE (tenant_id,partner_id,event_id)=(OLD.tenant_id,OLD.partner_id,OLD.changed_event_id);
  IF NEW.state='cancelled' THEN
   IF NOT freightctl_schedule_owner(NEW.tenant_id,NEW.partner_id,NEW.actor_id,ARRAY['workflow_execute']) THEN RAISE EXCEPTION 'arrival cancellation requires current owner' USING ERRCODE='42501';END IF;
  ELSIF NEW.state='missing' THEN
   IF clock_timestamp()<arrival_end OR OLD.manifest IS NOT NULL THEN RAISE EXCEPTION 'missing means no eligible ready manifest observed by arrival cutoff' USING ERRCODE='23514';END IF;
  ELSIF NEW.state='expired' THEN
   IF clock_timestamp()<execution_end OR OLD.state<>'ready' THEN RAISE EXCEPTION 'observed arrival has not reached execution cutoff' USING ERRCODE='23514';END IF;
  ELSIF NEW.state='probing' AND NEW.fence=OLD.fence+1 THEN
   IF OLD.state NOT IN ('waiting','attention','probing') OR (OLD.state='probing' AND OLD.lease_until>clock_timestamp()) OR OLD.next_probe_at>clock_timestamp() OR clock_timestamp()>=arrival_end OR OLD.probes>=max_probes OR NEW.probes<>OLD.probes+1 OR NEW.lease_owner IS NULL OR NEW.lease_until<=clock_timestamp() OR NEW.lease_until>least(clock_timestamp()+interval '31 seconds',arrival_end) OR NEW.next_probe_at<>OLD.next_probe_at THEN RAISE EXCEPTION 'probe takeover requires original expired lease and approved cadence' USING ERRCODE='23514';END IF;
  ELSIF NEW.state IN ('waiting','attention','ready') AND OLD.state='probing' THEN
   IF NOT live OR NEW.fence<>OLD.fence OR NEW.probes<>OLD.probes OR (NEW.state IN ('waiting','attention') AND (NEW.manifest IS NOT NULL OR NEW.next_probe_at<least(claimed_at+make_interval(secs=>poll),arrival_end))) OR (NEW.state='ready' AND (NEW.manifest IS NULL OR NEW.observed_at IS NULL OR NEW.observed_at IS DISTINCT FROM journal_at OR NEW.observed_at<claimed_at OR NEW.observed_at>clock_timestamp() OR NEW.observed_at<(d->>'due_at')::timestamptz OR NEW.observed_at>=arrival_end OR NOT freightctl_arrival_manifest_valid(s.definition->'collection'->'source',NEW.manifest))) THEN RAISE EXCEPTION 'only live probe can record its bounded absence, attention or verified ready manifest' USING ERRCODE='23514';END IF;
  ELSIF NEW.state='admitted' THEN
   IF OLD.state<>'ready' OR clock_timestamp()>=execution_end OR NEW.collection_id IS NULL OR NEW.manifest IS NULL THEN RAISE EXCEPTION 'collection admission needs original frozen ready manifest before cutoff' USING ERRCODE='23514';END IF;
  ELSE RAISE EXCEPTION 'invalid arrival transition' USING ERRCODE='23514';END IF;
  IF NEW.state<>'ready' AND (NEW.manifest,NEW.manifest_hash,NEW.observed_at) IS DISTINCT FROM (OLD.manifest,OLD.manifest_hash,OLD.observed_at) THEN RAISE EXCEPTION 'only verified ready transition can freeze an observation' USING ERRCODE='23514';END IF;
  IF NEW.state<>'admitted' AND NEW.collection_id IS DISTINCT FROM OLD.collection_id THEN RAISE EXCEPTION 'only atomic admission can assign a collection job' USING ERRCODE='23514';END IF;
  IF NEW.state<>'probing' AND (NEW.fence<>OLD.fence OR NEW.probes<>OLD.probes OR NEW.lease_owner IS NOT NULL OR NEW.lease_until IS NOT NULL) THEN RAISE EXCEPTION 'arrival completion preserves original probe counters and releases lease' USING ERRCODE='23514';END IF;
  IF NEW.state IN ('probing','waiting','attention','ready','admitted') AND freightctl_arrival_current(NEW.tenant_id,NEW.partner_id,NEW.actor_id,d) IS NOT TRUE THEN RAISE EXCEPTION 'current calendar and source authority required' USING ERRCODE='42501';END IF;
 END IF;
 RETURN NEW;
END $$;
