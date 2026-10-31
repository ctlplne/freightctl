-- Collection is a typed input stage of an ordinary approved workflow. Remote
-- reads begin only after a durable job; original source and accepted-byte claims
-- survive a worker or HTTP response loss. No remote mutation is authorized here.
CREATE TABLE workflow_collection_jobs (
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,actor_id uuid NOT NULL,id uuid NOT NULL,
 workflow_id uuid NOT NULL,workflow_version integer NOT NULL,workflow_hash text NOT NULL CHECK(workflow_hash ~ '^[0-9a-f]{64}$'),
 definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object' AND octet_length(definition::text)<=24576),definition_hash text NOT NULL CHECK(definition_hash ~ '^[0-9a-f]{64}$'),
 state text NOT NULL CHECK(state IN ('queued','reading','retry','captured','attention','expired','cancelled')),captured boolean NOT NULL DEFAULT false,revision bigint NOT NULL CHECK(revision>0),
 fence bigint NOT NULL CHECK(fence>=0),attempts integer NOT NULL CHECK(attempts BETWEEN 0 AND 8),lease_owner uuid,lease_until timestamptz,
 next_at timestamptz NOT NULL,created_at timestamptz NOT NULL,deadline_at timestamptz NOT NULL,
 manifest jsonb CHECK(manifest IS NULL OR (jsonb_typeof(manifest)='object' AND octet_length(manifest::text)<=32768)),manifest_hash text CHECK(manifest_hash IS NULL OR manifest_hash ~ '^[0-9a-f]{64}$'),
 reason text NOT NULL CHECK(reason ~ '^[a-z_]{1,64}$'),changed_event_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,id),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,workflow_id,workflow_version) REFERENCES workflow_revisions(tenant_id,partner_id,workflow_id,version),
 FOREIGN KEY(tenant_id,partner_id,changed_event_id) REFERENCES events(tenant_id,partner_id,event_id),
 CHECK((state='reading' AND lease_owner IS NOT NULL AND lease_until IS NOT NULL) OR (state<>'reading' AND lease_owner IS NULL AND lease_until IS NULL)),CHECK((manifest IS NULL)=(manifest_hash IS NULL))
);
CREATE UNIQUE INDEX workflow_collection_one_open ON workflow_collection_jobs(tenant_id,partner_id,actor_id,workflow_id) WHERE state IN ('queued','reading','retry');
CREATE INDEX workflow_collection_pending ON workflow_collection_jobs(tenant_id,partner_id,actor_id,state,next_at,id);
CREATE INDEX workflow_collection_history ON workflow_collection_jobs(tenant_id,partner_id,actor_id,id);
CREATE TABLE workflow_collection_batches (
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,actor_id uuid NOT NULL,id uuid NOT NULL,job_id uuid NOT NULL,workflow_id uuid NOT NULL,
 source_identity text NOT NULL CHECK(source_identity ~ '^[0-9a-f]{64}$'),producer_batch_id uuid NOT NULL,
 manifest_hash text NOT NULL CHECK(manifest_hash ~ '^[0-9a-f]{64}$'),manifest jsonb NOT NULL CHECK(jsonb_typeof(manifest)='object' AND octet_length(manifest::text)<=32768),changed_event_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,id),UNIQUE(tenant_id,partner_id,actor_id,workflow_id,source_identity,producer_batch_id),UNIQUE(tenant_id,partner_id,job_id),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,job_id) REFERENCES workflow_collection_jobs(tenant_id,partner_id,id),
 FOREIGN KEY(tenant_id,partner_id,changed_event_id) REFERENCES events(tenant_id,partner_id,event_id)
);
CREATE TABLE workflow_collection_inputs (
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,actor_id uuid NOT NULL,id uuid NOT NULL,first_job_id uuid NOT NULL,workflow_id uuid NOT NULL,
 source_identity text NOT NULL CHECK(source_identity ~ '^[0-9a-f]{64}$'),input_identity text NOT NULL CHECK(input_identity ~ '^[0-9a-f]{64}$'),
 source_name text NOT NULL CHECK(source_name ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),size_bytes bigint NOT NULL CHECK(size_bytes BETWEEN 0 AND 1073741824),sha256 text NOT NULL CHECK(sha256 ~ '^[0-9a-f]{64}$'),
 target_path text NOT NULL CHECK(length(target_path)<=4096),object_id uuid NOT NULL,state text NOT NULL CHECK(state IN ('pending','accepted','queued')),revision bigint NOT NULL CHECK(revision>0),
 capture_fence bigint NOT NULL CHECK(capture_fence>0),capture_owner uuid NOT NULL,file_id uuid,run_id uuid,changed_event_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,id),UNIQUE(tenant_id,partner_id,actor_id,workflow_id,input_identity),UNIQUE(tenant_id,partner_id,file_id),UNIQUE(tenant_id,partner_id,run_id),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,first_job_id) REFERENCES workflow_collection_jobs(tenant_id,partner_id,id),
 FOREIGN KEY(tenant_id,partner_id,file_id) REFERENCES files(tenant_id,partner_id,file_id),
 FOREIGN KEY(tenant_id,partner_id,run_id) REFERENCES workflow_runs(tenant_id,partner_id,run_id),
 FOREIGN KEY(tenant_id,partner_id,changed_event_id) REFERENCES events(tenant_id,partner_id,event_id),
 CHECK((state='pending')=(file_id IS NULL)),CHECK((state='queued')=(run_id IS NOT NULL)),CHECK(file_id IS NULL OR file_id=object_id)
);
-- Availability is shared by every authorized file reader. Its hold cannot
-- depend on actor-private source tables: RLS would hide another actor's hold.
-- This projection contains no source, job, actor, path or credential metadata.
CREATE TABLE workflow_collection_file_gates (
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,file_id uuid NOT NULL,
 captured boolean NOT NULL,changed_event_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,file_id),
 FOREIGN KEY(tenant_id,partner_id,file_id) REFERENCES files(tenant_id,partner_id,file_id),
 FOREIGN KEY(tenant_id,partner_id,changed_event_id) REFERENCES events(tenant_id,partner_id,event_id)
);
ALTER TABLE workflow_collection_file_gates ENABLE ROW LEVEL SECURITY;
ALTER TABLE workflow_collection_file_gates FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON workflow_collection_file_gates USING(tenant_id=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND partner_id=nullif(current_setting('freightctl.partner_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND partner_id=nullif(current_setting('freightctl.partner_id',true),'')::uuid);
GRANT SELECT,INSERT,UPDATE ON workflow_collection_file_gates TO freightctl_runtime;
CREATE INDEX workflow_collection_input_job ON workflow_collection_inputs(tenant_id,partner_id,actor_id,first_job_id,id);
DO $$ DECLARE n text;BEGIN FOREACH n IN ARRAY ARRAY['workflow_collection_jobs','workflow_collection_batches','workflow_collection_inputs'] LOOP
 EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',n);EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',n);
 EXECUTE format('CREATE POLICY scope ON %I USING(tenant_id=nullif(current_setting(''freightctl.tenant_id'',true),'''')::uuid AND partner_id=nullif(current_setting(''freightctl.partner_id'',true),'''')::uuid) WITH CHECK(tenant_id=nullif(current_setting(''freightctl.tenant_id'',true),'''')::uuid AND partner_id=nullif(current_setting(''freightctl.partner_id'',true),'''')::uuid)',n);
 EXECUTE format('CREATE POLICY identity_scope ON %I AS RESTRICTIVE USING(actor_id=nullif(current_setting(''freightctl.actor_id'',true),'''')::uuid) WITH CHECK(actor_id=nullif(current_setting(''freightctl.actor_id'',true),'''')::uuid)',n);
END LOOP;END $$;
GRANT SELECT,INSERT,UPDATE ON workflow_collection_jobs,workflow_collection_inputs TO freightctl_runtime;
GRANT SELECT,INSERT ON workflow_collection_batches TO freightctl_runtime;

CREATE FUNCTION freightctl_collection_target_writable(t uuid,p uuid,a uuid,directory text) RETURNS boolean LANGUAGE plpgsql STABLE AS $$
DECLARE parts text[];cur text:='/';part text;idx integer;mask integer;entry record;is_admin boolean;
BEGIN
 IF directory IS NULL OR left(directory,1)<>'/' OR octet_length(directory)>830 THEN RETURN false;END IF;
 SELECT 'admin'=ANY(c.permissions) INTO is_admin FROM credentials c WHERE (c.tenant_id,c.partner_id,c.actor_id)=(t,p,a);
 IF is_admin IS NULL THEN RETURN false;END IF;
 parts:=CASE WHEN directory='/' THEN ARRAY[]::text[] ELSE string_to_array(substring(directory FROM 2),'/') END;
 FOR idx IN 0..cardinality(parts) LOOP
  -- Namespace root is virtual, with owner-mode 0770, exactly as Entry("/").
  -- There is deliberately no persisted root row in namespace_entries.
  IF idx=0 THEN CONTINUE;END IF;
  IF idx>0 THEN
   part:=parts[idx];
   IF part=ANY(ARRAY['','.','..','.freightctl']) OR octet_length(part)>255 OR right(part,1) IN ('.',' ') OR part ~ '[[:cntrl:]]' OR position(chr(92) IN part)>0 OR position(':' IN part)>0 OR upper(split_part(part,'.',1)) ~ '^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$' THEN RETURN false;END IF;
   cur:=rtrim(cur,'/')||'/'||part;
  END IF;
  SELECT n.owner_actor_id,n.mode INTO entry FROM namespace_entries n WHERE (n.tenant_id,n.partner_id,n.path)=(t,p,cur) AND n.kind='dir' AND NOT n.deleted;
  IF NOT FOUND THEN RETURN false;END IF;
  mask:=CASE WHEN idx=cardinality(parts) THEN 3 ELSE 1 END;
  IF NOT is_admin AND ((entry.mode >> CASE WHEN entry.owner_actor_id=a THEN 6 ELSE 3 END) & mask)<>mask THEN RETURN false;END IF;
 END LOOP;
 RETURN true;
END $$;
CREATE FUNCTION freightctl_collection_definition_current(t uuid,p uuid,a uuid,d jsonb) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT freightctl_schedule_owner(t,p,a,ARRAY['workflow_execute','write','list','read']) AND d->>'schema_version'='1' AND d->>'namespace_root'='/'
 AND ARRAY(SELECT jsonb_object_keys(d) ORDER BY 1)=ARRAY['authority_revision','effects','namespace_root','schema_version','source','source_connection','source_identity','storage_id','timeout_seconds','workflow']::text[]
 AND (d->>'timeout_seconds')::integer BETWEEN 1 AND 3600
 AND (jsonb_array_length(d->'effects')=0 OR freightctl_schedule_owner(t,p,a,ARRAY['deliver']))
 AND freightctl_collection_target_writable(t,p,a,d->'source'->>'target_directory')
 AND EXISTS(SELECT 1 FROM credentials u WHERE (u.tenant_id,u.partner_id,u.actor_id,u.authority_revision)=(t,p,a,(d->>'authority_revision')::bigint))
 AND freightctl_schedule_effects_current(t,p,a,d)
 AND EXISTS(SELECT 1 FROM workflow_revisions w JOIN connection_revisions c ON (c.tenant_id,c.partner_id,c.actor_id,c.connection_id,c.version,c.definition_hash,c.state)=(t,p,a,(d->'source'->'connection'->>'id')::uuid,(d->'source'->'connection'->>'version')::integer,d->'source'->'connection'->>'hash','active')
 WHERE (w.tenant_id,w.partner_id,w.actor_id,w.workflow_id,w.version,w.definition_hash,w.state,w.approval_authority)=(t,p,a,(d->'workflow'->>'id')::uuid,(d->'workflow'->>'version')::integer,d->'workflow'->>'hash','approved',(d->>'authority_revision')::bigint)
 AND w.definition->'source'=d->'source' AND d->'source'->>'kind'='sftp.collect' AND d->'source'->>'completion_contract'='immutable-files-sha256-manifest-v1'
 AND ARRAY(SELECT jsonb_object_keys(d->'source') ORDER BY 1)=ARRAY['completion_contract','connection','kind','manifest','max_file_bytes','max_files','max_total_bytes','target_directory']::text[]
 AND d->'source'->>'manifest' ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$' AND right(d->'source'->>'manifest',11)='.ready.json'
 AND (d->'source'->>'max_files')::integer BETWEEN 1 AND 64 AND (d->'source'->>'max_file_bytes')::bigint BETWEEN 1 AND 1073741824
 AND (d->'source'->>'max_total_bytes')::bigint BETWEEN 1 AND (d->'source'->>'max_files')::bigint*(d->'source'->>'max_file_bytes')::bigint
 AND d->>'source_identity'=encode(sha256(convert_to(c.connection_id::text||':'||(c.definition->>'directory'),'UTF8')),'hex')
 AND d->'source_connection'=jsonb_build_object('id',c.connection_id,'version',c.version,'definition_hash',c.definition_hash,'state',c.state,'revision',c.revision,'address',c.definition->'destination'->>'address','user',c.definition->'destination'->>'user','directory',c.definition->>'directory','host_fingerprint',c.definition->'destination'->'host'->>'Fingerprint','key_fingerprint',c.definition->'destination'->>'key_fingerprint'))
$$;

CREATE FUNCTION freightctl_collection_job_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE e jsonb;d jsonb;n integer;live boolean;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'collection history is immutable' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' AND NOT pg_try_advisory_xact_lock(hashtextextended(NEW.tenant_id::text||':'||NEW.partner_id::text||':workflow-collections',0)) THEN RAISE EXCEPTION 'collection admission guard busy' USING ERRCODE='40001';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended(NEW.tenant_id::text||':'||NEW.partner_id::text||':workflow-collections',0));
 SELECT payload INTO e FROM events WHERE (tenant_id,partner_id,actor_id,event_id,resource_id,kind)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.changed_event_id,NEW.id,'WorkflowCollectionChanged');
 IF e IS NULL OR (e-ARRAY['lease_owner','lease_until','next_at','created_at','deadline_at']) IS DISTINCT FROM (to_jsonb(NEW)-ARRAY['tenant_id','partner_id','actor_id','changed_event_id','lease_owner','lease_until','next_at','created_at','deadline_at']) OR e->>'lease_owner' IS DISTINCT FROM coalesce(NEW.lease_owner::text,'') OR (e->>'lease_until')::timestamptz IS DISTINCT FROM NEW.lease_until OR (e->>'next_at')::timestamptz IS DISTINCT FROM NEW.next_at OR (e->>'created_at')::timestamptz IS DISTINCT FROM NEW.created_at OR (e->>'deadline_at')::timestamptz IS DISTINCT FROM NEW.deadline_at THEN RAISE EXCEPTION 'collection requires its exact journal event' USING ERRCODE='23514';END IF;
 d:=NEW.definition;
 IF (NEW.workflow_id,NEW.workflow_version,NEW.workflow_hash) IS DISTINCT FROM ((d->'workflow'->>'id')::uuid,(d->'workflow'->>'version')::integer,d->'workflow'->>'hash') OR NEW.deadline_at<>NEW.created_at+make_interval(secs=>(d->>'timeout_seconds')::integer) THEN RAISE EXCEPTION 'collection workflow and cutoff are immutable bindings' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN
  SELECT count(*) INTO n FROM workflow_collection_jobs WHERE (tenant_id,partner_id,actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id) AND state IN ('queued','reading','retry');
  IF NEW.captured OR NEW.state<>'queued' OR NEW.revision<>1 OR NEW.fence<>0 OR NEW.attempts<>0 OR NEW.lease_owner IS NOT NULL OR NEW.manifest IS NOT NULL OR NEW.next_at<>NEW.created_at OR NEW.created_at>clock_timestamp() OR NEW.created_at<clock_timestamp()-interval '10 seconds' OR NEW.deadline_at<=clock_timestamp() OR n>=128 OR freightctl_collection_definition_current(NEW.tenant_id,NEW.partner_id,NEW.actor_id,d) IS NOT TRUE THEN RAISE EXCEPTION 'collection begins as an authorized bounded intent' USING ERRCODE='23514';END IF;
 ELSE
  IF (NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.id,NEW.workflow_id,NEW.workflow_version,NEW.workflow_hash,NEW.definition,NEW.definition_hash,NEW.created_at,NEW.deadline_at) IS DISTINCT FROM (OLD.tenant_id,OLD.partner_id,OLD.actor_id,OLD.id,OLD.workflow_id,OLD.workflow_version,OLD.workflow_hash,OLD.definition,OLD.definition_hash,OLD.created_at,OLD.deadline_at) OR NEW.revision<>OLD.revision+1 OR (OLD.manifest IS NOT NULL AND (NEW.manifest,NEW.manifest_hash) IS DISTINCT FROM (OLD.manifest,OLD.manifest_hash)) THEN RAISE EXCEPTION 'collection definition and captured manifest are immutable' USING ERRCODE='23514';END IF;
  IF OLD.manifest IS NULL AND NEW.manifest IS NOT NULL AND (OLD.state<>'reading' OR NEW.state<>'reading' OR NEW.fence<>OLD.fence OR NEW.lease_owner IS DISTINCT FROM OLD.lease_owner) THEN RAISE EXCEPTION 'manifest capture requires the same reading owner' USING ERRCODE='23514';END IF;
  IF NEW.captured IS DISTINCT FROM (OLD.captured OR NEW.state='captured') THEN RAISE EXCEPTION 'durable batch capture cannot be invented or withdrawn' USING ERRCODE='23514';END IF;
  live:=OLD.state='reading' AND OLD.lease_until>clock_timestamp() AND OLD.deadline_at>clock_timestamp();
  IF NEW.state='reading' AND NEW.fence=OLD.fence+1 THEN
   IF NOT (OLD.state IN ('queued','retry','attention') OR (OLD.state='reading' AND OLD.lease_until<=clock_timestamp())) OR OLD.next_at>clock_timestamp() OR OLD.attempts>=8 OR NEW.attempts<>OLD.attempts+1 OR NEW.lease_owner IS NULL OR NEW.lease_until<=clock_timestamp() OR NEW.lease_until>clock_timestamp()+interval '31 seconds' OR NEW.lease_until>NEW.deadline_at OR NEW.next_at<>OLD.next_at OR (NEW.manifest,NEW.manifest_hash) IS DISTINCT FROM (OLD.manifest,OLD.manifest_hash) THEN RAISE EXCEPTION 'collection takeover requires original expired lease and attempt budget' USING ERRCODE='23514';END IF;
  ELSIF NEW.state='reading' AND NEW.fence=OLD.fence THEN
   IF NOT live OR NEW.lease_owner IS DISTINCT FROM OLD.lease_owner OR NEW.attempts<>OLD.attempts OR NEW.lease_until<OLD.lease_until OR NEW.lease_until>clock_timestamp()+interval '31 seconds' OR NEW.lease_until>NEW.deadline_at OR NEW.next_at<>OLD.next_at THEN RAISE EXCEPTION 'only live collection owner may renew or capture a manifest' USING ERRCODE='23514';END IF;
  ELSE
   IF NEW.fence<>OLD.fence OR NEW.attempts<>OLD.attempts OR NEW.lease_owner IS NOT NULL OR NEW.lease_until IS NOT NULL THEN RAISE EXCEPTION 'collection completion preserves fence and attempt history' USING ERRCODE='23514';END IF;
   IF NEW.state='cancelled' THEN
    IF OLD.state IN ('cancelled','expired') OR NOT freightctl_schedule_owner(NEW.tenant_id,NEW.partner_id,NEW.actor_id,ARRAY['workflow_execute']) THEN RAISE EXCEPTION 'collection cancellation requires current owner' USING ERRCODE='42501';END IF;
   ELSIF NEW.state='expired' THEN
    IF OLD.state IN ('cancelled','expired') OR NEW.deadline_at>clock_timestamp() THEN RAISE EXCEPTION 'collection has not expired' USING ERRCODE='23514';END IF;
   ELSIF NEW.state IN ('retry','attention') THEN
    IF OLD.state<>'reading' OR (NEW.state='retry' AND (NOT live OR OLD.attempts>=8 OR NEW.next_at<=clock_timestamp() OR NEW.next_at>NEW.deadline_at)) THEN RAISE EXCEPTION 'invalid collection failure recording' USING ERRCODE='23514';END IF;
   ELSIF NEW.state='captured' THEN
    IF NOT live OR NEW.manifest IS NULL OR EXISTS(SELECT 1 FROM jsonb_array_elements(NEW.manifest->'files') f WHERE NOT EXISTS(SELECT 1 FROM workflow_collection_inputs i WHERE (i.tenant_id,i.partner_id,i.actor_id,i.workflow_id,i.source_identity,i.source_name,i.size_bytes,i.sha256)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.workflow_id,d->>'source_identity',f->>'name',(f->>'size_bytes')::bigint,f->>'sha256') AND i.state IN ('accepted','queued'))) THEN RAISE EXCEPTION 'collection capture requires all exact durable accepted inputs' USING ERRCODE='23514';END IF;
   ELSE RAISE EXCEPTION 'invalid collection transition' USING ERRCODE='23514';END IF;
  END IF;
  IF NEW.state IN ('reading','captured') AND freightctl_collection_definition_current(NEW.tenant_id,NEW.partner_id,NEW.actor_id,d) IS NOT TRUE THEN RAISE EXCEPTION 'collection authority or effects changed' USING ERRCODE='42501';END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER workflow_collection_job_guard BEFORE INSERT OR UPDATE OR DELETE ON workflow_collection_jobs FOR EACH ROW EXECUTE FUNCTION freightctl_collection_job_guard();

CREATE FUNCTION freightctl_collection_batch_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE j workflow_collection_jobs%ROWTYPE;e jsonb;m jsonb;f jsonb;n integer;total bigint;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'producer batch claims are immutable' USING ERRCODE='23514';END IF;
 SELECT * INTO j FROM workflow_collection_jobs WHERE (tenant_id,partner_id,actor_id,id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.job_id);
 SELECT payload INTO e FROM events WHERE (tenant_id,partner_id,actor_id,event_id,resource_id,kind)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.changed_event_id,NEW.id,'WorkflowCollectionBatch');
 IF e IS NULL OR e IS DISTINCT FROM (to_jsonb(NEW)-ARRAY['tenant_id','partner_id','actor_id','changed_event_id']) OR j.id IS NULL OR j.state<>'reading' OR j.lease_until<=clock_timestamp() OR j.deadline_at<=clock_timestamp() OR j.workflow_id<>NEW.workflow_id OR j.definition->>'source_identity'<>NEW.source_identity OR j.manifest IS DISTINCT FROM NEW.manifest OR j.manifest_hash IS DISTINCT FROM NEW.manifest_hash OR freightctl_collection_definition_current(NEW.tenant_id,NEW.partner_id,NEW.actor_id,j.definition) IS NOT TRUE THEN RAISE EXCEPTION 'batch requires exact live job and journal binding' USING ERRCODE='23514';END IF;
 m:=NEW.manifest;
 IF ARRAY(SELECT jsonb_object_keys(m) ORDER BY 1) IS DISTINCT FROM ARRAY['batch_id','files','schema_version']::text[] OR m->>'schema_version'<>'1' OR (m->>'batch_id')::uuid IS DISTINCT FROM NEW.producer_batch_id OR jsonb_typeof(m->'files')<>'array' OR jsonb_array_length(m->'files') NOT BETWEEN 1 AND (j.definition->'source'->>'max_files')::integer THEN RAISE EXCEPTION 'invalid bounded producer manifest' USING ERRCODE='23514';END IF;
 total:=0;
 FOR f IN SELECT value FROM jsonb_array_elements(m->'files') LOOP
  IF ARRAY(SELECT jsonb_object_keys(f) ORDER BY 1) IS DISTINCT FROM ARRAY['name','sha256','size_bytes']::text[] OR f->>'name' !~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$' OR (right(f->>'name',11)='.ready.json' OR right(f->>'name',1)='.') OR f->>'sha256' !~ '^[0-9a-f]{64}$' OR jsonb_typeof(f->'size_bytes')<>'number' OR (f->>'size_bytes')::bigint NOT BETWEEN 0 AND (j.definition->'source'->>'max_file_bytes')::bigint THEN RAISE EXCEPTION 'invalid producer file claim' USING ERRCODE='23514';END IF;
  total:=total+(f->>'size_bytes')::bigint;
 END LOOP;
 SELECT count(DISTINCT value->>'name') INTO n FROM jsonb_array_elements(m->'files');
 IF n<>jsonb_array_length(m->'files') OR total>(j.definition->'source'->>'max_total_bytes')::bigint THEN RAISE EXCEPTION 'duplicate producer name or byte budget exceeded' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER workflow_collection_batch_guard BEFORE INSERT OR UPDATE OR DELETE ON workflow_collection_batches FOR EACH ROW EXECUTE FUNCTION freightctl_collection_batch_guard();

CREATE FUNCTION freightctl_collection_input_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE e jsonb;j workflow_collection_jobs%ROWTYPE;f files%ROWTYPE;live boolean;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'collection input history is immutable' USING ERRCODE='23514';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended(NEW.tenant_id::text||':'||NEW.partner_id::text||':workflow-collections',0));
 SELECT payload INTO e FROM events WHERE (tenant_id,partner_id,actor_id,event_id,resource_id,kind)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.changed_event_id,NEW.id,'WorkflowCollectionInput');
 IF e IS NULL OR e IS DISTINCT FROM (to_jsonb(NEW)-ARRAY['tenant_id','partner_id','actor_id','changed_event_id']) THEN RAISE EXCEPTION 'collection input requires its exact journal event' USING ERRCODE='23514';END IF;
 SELECT * INTO j FROM workflow_collection_jobs WHERE (tenant_id,partner_id,actor_id,id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.first_job_id);
 live:=j.state='reading' AND j.lease_until>clock_timestamp() AND j.deadline_at>clock_timestamp() AND NEW.capture_fence=j.fence AND NEW.capture_owner=j.lease_owner;
 IF j.id IS NULL OR j.workflow_id<>NEW.workflow_id OR j.definition->>'source_identity'<>NEW.source_identity OR NEW.input_identity<>encode(sha256(convert_to(NEW.source_identity||':'||NEW.source_name||':'||NEW.size_bytes::text||':'||NEW.sha256,'UTF8')),'hex') OR NEW.target_path<>rtrim(j.definition->'source'->>'target_directory','/')||'/'||NEW.sha256||'-'||NEW.source_name OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(j.manifest->'files') q WHERE (q->>'name',(q->>'size_bytes')::bigint,q->>'sha256')=(NEW.source_name,NEW.size_bytes,NEW.sha256)) THEN RAISE EXCEPTION 'collection input differs from exact producer batch or local target' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN
  IF NOT live OR NEW.state<>'pending' OR NEW.revision<>1 OR NEW.file_id IS NOT NULL OR NEW.run_id IS NOT NULL OR freightctl_collection_definition_current(NEW.tenant_id,NEW.partner_id,NEW.actor_id,j.definition) IS NOT TRUE THEN RAISE EXCEPTION 'input starts as an authorized fenced claim' USING ERRCODE='23514';END IF;
 ELSE
  IF (NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.id,NEW.first_job_id,NEW.workflow_id,NEW.source_identity,NEW.input_identity,NEW.source_name,NEW.size_bytes,NEW.sha256,NEW.target_path) IS DISTINCT FROM (OLD.tenant_id,OLD.partner_id,OLD.actor_id,OLD.id,OLD.first_job_id,OLD.workflow_id,OLD.source_identity,OLD.input_identity,OLD.source_name,OLD.size_bytes,OLD.sha256,OLD.target_path) OR NEW.revision<>OLD.revision+1 OR OLD.state='queued' THEN RAISE EXCEPTION 'input meaning and queued lineage are immutable' USING ERRCODE='23514';END IF;
  IF OLD.state='pending' THEN
   IF NOT live OR NEW.capture_fence<OLD.capture_fence OR NEW.state NOT IN ('pending','accepted') OR NEW.run_id IS NOT NULL OR (NEW.state='accepted' AND NEW.object_id<>OLD.object_id) OR freightctl_collection_definition_current(NEW.tenant_id,NEW.partner_id,NEW.actor_id,j.definition) IS NOT TRUE THEN RAISE EXCEPTION 'only live fenced collector can accept its exact input' USING ERRCODE='23514';END IF;
  ELSIF OLD.state='accepted' THEN
   IF NEW.state<>'queued' OR NEW.file_id IS DISTINCT FROM OLD.file_id OR NEW.object_id<>OLD.object_id OR NEW.capture_fence<>OLD.capture_fence OR NEW.capture_owner<>OLD.capture_owner OR NEW.run_id IS NULL OR j.state<>'captured' OR j.deadline_at<=clock_timestamp() OR freightctl_collection_definition_current(NEW.tenant_id,NEW.partner_id,NEW.actor_id,j.definition) IS NOT TRUE OR NOT freightctl_file_available(NEW.tenant_id,NEW.partner_id,NEW.file_id) OR NOT EXISTS(SELECT 1 FROM namespace_entries n WHERE (n.tenant_id,n.partner_id,n.path,n.file_id,n.kind)=(NEW.tenant_id,NEW.partner_id,NEW.target_path,NEW.file_id,'file') AND NOT n.deleted AND (EXISTS(SELECT 1 FROM credentials credential WHERE (credential.tenant_id,credential.partner_id,credential.actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id) AND 'admin'=ANY(credential.permissions)) OR (n.owner_actor_id=NEW.actor_id AND (n.mode & 256)=256) OR (n.owner_actor_id<>NEW.actor_id AND (n.mode & 32)=32))) THEN RAISE EXCEPTION 'only current published exact input may queue downstream' USING ERRCODE='23514';END IF;
  ELSE RAISE EXCEPTION 'invalid input transition' USING ERRCODE='23514';END IF;
 END IF;
 IF NEW.state IN ('accepted','queued') THEN
  SELECT * INTO f FROM files WHERE (tenant_id,partner_id,file_id)=(NEW.tenant_id,NEW.partner_id,NEW.file_id);
  IF f.file_id IS NULL OR (f.size_bytes,f.sha256) IS DISTINCT FROM (NEW.size_bytes,NEW.sha256) OR NEW.file_id<>NEW.object_id OR NOT EXISTS(SELECT 1 FROM idempotency k WHERE (k.tenant_id,k.partner_id,k.request_key,k.file_id)=(NEW.tenant_id,NEW.partner_id,'collect-'||NEW.id::text,NEW.file_id)) THEN RAISE EXCEPTION 'input acceptance requires exact durable file and same-transaction retry receipt' USING ERRCODE='23514';END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER workflow_collection_input_guard BEFORE INSERT OR UPDATE OR DELETE ON workflow_collection_inputs FOR EACH ROW EXECUTE FUNCTION freightctl_collection_input_guard();

CREATE FUNCTION freightctl_collection_event_complete() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.kind='WorkflowCollectionChanged' AND NOT EXISTS(SELECT 1 FROM workflow_collection_jobs j WHERE (j.tenant_id,j.partner_id,j.changed_event_id)=(NEW.tenant_id,NEW.partner_id,NEW.event_id)) THEN RAISE EXCEPTION 'collection event requires its projection' USING ERRCODE='23514';END IF;
 IF NEW.kind='WorkflowCollectionBatch' AND NOT EXISTS(SELECT 1 FROM workflow_collection_batches b WHERE (b.tenant_id,b.partner_id,b.changed_event_id)=(NEW.tenant_id,NEW.partner_id,NEW.event_id) AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(b.manifest->'files') q WHERE NOT EXISTS(SELECT 1 FROM workflow_collection_inputs i WHERE (i.tenant_id,i.partner_id,i.actor_id,i.workflow_id,i.source_identity,i.source_name,i.size_bytes,i.sha256)=(b.tenant_id,b.partner_id,b.actor_id,b.workflow_id,b.source_identity,q->>'name',(q->>'size_bytes')::bigint,q->>'sha256')))) THEN RAISE EXCEPTION 'batch event requires all exact input claims' USING ERRCODE='23514';END IF;
 IF NEW.kind='WorkflowCollectionInput' AND NOT EXISTS(SELECT 1 FROM workflow_collection_inputs i WHERE (i.tenant_id,i.partner_id,i.changed_event_id)=(NEW.tenant_id,NEW.partner_id,NEW.event_id)) THEN RAISE EXCEPTION 'input event requires its projection' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER collection_event_complete AFTER INSERT ON events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION freightctl_collection_event_complete();
CREATE FUNCTION freightctl_collection_manifest_complete() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.manifest IS NOT NULL AND NOT EXISTS(SELECT 1 FROM workflow_collection_batches b WHERE (b.tenant_id,b.partner_id,b.actor_id,b.workflow_id,b.source_identity,b.producer_batch_id,b.manifest_hash,b.manifest)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.workflow_id,NEW.definition->>'source_identity',(NEW.manifest->>'batch_id')::uuid,NEW.manifest_hash,NEW.manifest)) THEN RAISE EXCEPTION 'captured manifest requires immutable batch binding' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER collection_manifest_complete AFTER INSERT OR UPDATE ON workflow_collection_jobs DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION freightctl_collection_manifest_complete();

CREATE FUNCTION freightctl_collected_run_status(t uuid,p uuid,a uuid,target_run uuid) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT NOT EXISTS(SELECT 1 FROM workflow_collection_inputs WHERE (tenant_id,partner_id,actor_id,run_id)=(t,p,a,target_run)) OR EXISTS(SELECT 1 FROM workflow_collection_inputs i JOIN workflow_collection_jobs j ON (j.tenant_id,j.partner_id,j.actor_id,j.id)=(i.tenant_id,i.partner_id,i.actor_id,i.first_job_id) WHERE (i.tenant_id,i.partner_id,i.actor_id,i.run_id)=(t,p,a,target_run) AND i.state='queued' AND EXISTS(SELECT 1 FROM namespace_entries n JOIN credentials reader ON (reader.tenant_id,reader.partner_id,reader.actor_id)=(i.tenant_id,i.partner_id,i.actor_id) WHERE (n.tenant_id,n.partner_id,n.path,n.file_id,n.kind)=(i.tenant_id,i.partner_id,i.target_path,i.file_id,'file') AND NOT n.deleted AND ('admin'=ANY(reader.permissions) OR (n.owner_actor_id=i.actor_id AND (n.mode & 256)=256) OR (n.owner_actor_id<>i.actor_id AND (n.mode & 32)=32))) AND j.state='captured' AND j.deadline_at>clock_timestamp() AND freightctl_collection_definition_current(t,p,a,j.definition))
$$;
CREATE FUNCTION freightctl_collected_run_current(t uuid,p uuid,a uuid,target_run uuid) RETURNS boolean LANGUAGE plpgsql VOLATILE AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM workflow_collection_inputs WHERE (tenant_id,partner_id,actor_id,run_id)=(t,p,a,target_run)) THEN RETURN true;END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended(t::text||':'||p::text||':workflow-collections',0));
 RETURN freightctl_collected_run_status(t,p,a,target_run);
END $$;
CREATE FUNCTION freightctl_collection_run_complete() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM workflow_revisions w WHERE (w.tenant_id,w.partner_id,w.actor_id,w.workflow_id,w.version)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.workflow_id,NEW.workflow_version) AND w.definition ? 'source') AND NOT EXISTS(SELECT 1 FROM workflow_collection_inputs i JOIN workflow_collection_jobs j ON (j.tenant_id,j.partner_id,j.id)=(i.tenant_id,i.partner_id,i.first_job_id) WHERE (i.tenant_id,i.partner_id,i.actor_id,i.run_id,i.file_id,i.workflow_id,i.state)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.run_id,NEW.file_id,NEW.workflow_id,'queued') AND (j.workflow_version,j.workflow_hash)=(NEW.workflow_version,NEW.workflow_hash)) THEN RAISE EXCEPTION 'collection workflow run requires exact proven input lineage' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER collection_run_complete AFTER INSERT ON workflow_runs DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION freightctl_collection_run_complete();
CREATE FUNCTION freightctl_collection_effect_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE run_id uuid;
BEGIN
 IF TG_TABLE_NAME='delivery_intents' THEN
  IF NEW.state NOT IN ('staging','publishing','succeeded') OR (TG_OP='UPDATE' AND OLD.state='ambiguous' AND NEW.state='succeeded' AND NEW.observation->>'code'='remote_file_integrity_observed' AND NEW.observation->>'reconciled'='true') THEN RETURN NEW;END IF;
  run_id:=(NEW.definition->'workflow_binding'->>'run_id')::uuid;
 ELSE SELECT (d.definition->'workflow_binding'->>'run_id')::uuid INTO run_id FROM delivery_intents d WHERE (d.tenant_id,d.partner_id,d.delivery_id)=(NEW.tenant_id,NEW.partner_id,NEW.delivery_id);END IF;
 IF run_id IS NOT NULL AND NOT freightctl_collected_run_current(NEW.tenant_id,NEW.partner_id,NEW.actor_id,run_id) THEN RAISE EXCEPTION 'collection source authority or execution cutoff changed' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
-- Names preserve schedule -> collection -> dispatch effect-lock ordering.
CREATE TRIGGER outbound_ab_collection_effect BEFORE INSERT OR UPDATE ON delivery_intents FOR EACH ROW EXECUTE FUNCTION freightctl_collection_effect_guard();
CREATE TRIGGER outbound_ab_collection_ciphertext BEFORE INSERT ON delivery_ciphertexts FOR EACH ROW EXECUTE FUNCTION freightctl_collection_effect_guard();
CREATE FUNCTION freightctl_collection_authority_lock() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id::text||':'||NEW.partner_id::text||':workflow-collections',0));RETURN NEW;END $$;
CREATE TRIGGER onboarding_source_collection_authority_lock BEFORE UPDATE ON credentials FOR EACH ROW EXECUTE FUNCTION freightctl_collection_authority_lock();
CREATE TRIGGER source_collection_authority_lock BEFORE UPDATE ON connection_revisions FOR EACH ROW EXECUTE FUNCTION freightctl_collection_authority_lock();
CREATE TRIGGER source_collection_workflow_lock BEFORE UPDATE ON workflow_revisions FOR EACH ROW EXECUTE FUNCTION freightctl_collection_authority_lock();

-- Only the original actor can create this projection from its exact accepted
-- input event, or release it through that original job's capture event.
CREATE FUNCTION freightctl_collection_file_gate_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE input workflow_collection_inputs%ROWTYPE;job workflow_collection_jobs%ROWTYPE;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'collection file hold is immutable history' USING ERRCODE='23514';END IF;
 SELECT * INTO input FROM workflow_collection_inputs i WHERE (i.tenant_id,i.partner_id,i.file_id)=(NEW.tenant_id,NEW.partner_id,NEW.file_id);
 IF input.id IS NULL OR input.state NOT IN ('accepted','queued') THEN RAISE EXCEPTION 'collection file hold requires original actor exact accepted input' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.captured OR NEW.changed_event_id<>input.changed_event_id THEN RAISE EXCEPTION 'collection file begins held with its exact input event' USING ERRCODE='23514';END IF;
 ELSE
  SELECT * INTO job FROM workflow_collection_jobs j WHERE (j.tenant_id,j.partner_id,j.id)=(input.tenant_id,input.partner_id,input.first_job_id);
  IF (NEW.tenant_id,NEW.partner_id,NEW.file_id) IS DISTINCT FROM (OLD.tenant_id,OLD.partner_id,OLD.file_id) OR OLD.captured OR NOT NEW.captured OR job.id IS NULL OR NOT job.captured OR NEW.changed_event_id<>job.changed_event_id THEN RAISE EXCEPTION 'only original complete batch can release exact file hold' USING ERRCODE='23514';END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER workflow_collection_file_gate_guard BEFORE INSERT OR UPDATE OR DELETE ON workflow_collection_file_gates FOR EACH ROW EXECUTE FUNCTION freightctl_collection_file_gate_guard();
CREATE FUNCTION freightctl_collection_file_hold() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.file_id IS NOT NULL AND (TG_OP='INSERT' OR OLD.file_id IS NULL) THEN
  INSERT INTO workflow_collection_file_gates VALUES(NEW.tenant_id,NEW.partner_id,NEW.file_id,false,NEW.changed_event_id);
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER collection_file_hold AFTER INSERT OR UPDATE ON workflow_collection_inputs FOR EACH ROW EXECUTE FUNCTION freightctl_collection_file_hold();
CREATE FUNCTION freightctl_collection_file_capture() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.captured AND NOT OLD.captured THEN
  UPDATE workflow_collection_file_gates g SET captured=true,changed_event_id=NEW.changed_event_id WHERE (g.tenant_id,g.partner_id)=(NEW.tenant_id,NEW.partner_id) AND EXISTS(SELECT 1 FROM workflow_collection_inputs i WHERE (i.tenant_id,i.partner_id,i.actor_id,i.first_job_id,i.file_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.id,g.file_id));
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER collection_file_capture AFTER UPDATE ON workflow_collection_jobs FOR EACH ROW EXECUTE FUNCTION freightctl_collection_file_capture();
CREATE FUNCTION freightctl_collection_file_hold_complete() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.file_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM workflow_collection_file_gates g JOIN workflow_collection_jobs j ON (j.tenant_id,j.partner_id,j.id)=(NEW.tenant_id,NEW.partner_id,NEW.first_job_id) WHERE (g.tenant_id,g.partner_id,g.file_id,g.captured)=(NEW.tenant_id,NEW.partner_id,NEW.file_id,j.captured)) THEN RAISE EXCEPTION 'accepted collection input requires its exact shared file hold' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER collection_file_hold_complete AFTER INSERT OR UPDATE ON workflow_collection_inputs DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION freightctl_collection_file_hold_complete();
CREATE FUNCTION freightctl_collection_file_capture_complete() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.captured AND EXISTS(SELECT 1 FROM workflow_collection_inputs i WHERE (i.tenant_id,i.partner_id,i.actor_id,i.first_job_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.id) AND NOT EXISTS(SELECT 1 FROM workflow_collection_file_gates g WHERE (g.tenant_id,g.partner_id,g.file_id,g.captured)=(i.tenant_id,i.partner_id,i.file_id,true))) THEN RAISE EXCEPTION 'batch capture requires every exact shared file hold' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER collection_file_capture_complete AFTER INSERT OR UPDATE ON workflow_collection_jobs DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION freightctl_collection_file_capture_complete();

-- Preserve every existing intake/signature/scanner condition and the function
-- identity, adding the durable whole-batch input gate for collected files.
CREATE OR REPLACE FUNCTION freightctl_file_available(t uuid,p uuid,f uuid) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT EXISTS(SELECT 1 FROM files v WHERE (v.tenant_id,v.partner_id,v.file_id)=(t,p,f) AND (v.policy='integrity-only-v1' OR EXISTS(SELECT 1 FROM file_releases c JOIN intake_policies i ON (i.tenant_id,i.partner_id,i.policy_id,i.version)=(c.tenant_id,c.partner_id,c.policy_id,c.policy_version) WHERE (c.tenant_id,c.partner_id,c.file_id,i.state)=(t,p,f,'active') AND v.policy='intake-csv-v1:'||c.policy_hash AND c.policy_hash=i.definition_hash AND ((NOT (i.definition ? 'signature') OR i.definition->'signature'='null'::jsonb) OR EXISTS(SELECT 1 FROM pgp_keys k WHERE (k.tenant_id,k.partner_id,k.key_id,k.version,k.definition_hash,k.state)=(c.tenant_id,c.partner_id,c.pgp_key_id,c.pgp_key_version,c.pgp_key_hash,'active') AND (k.valid_until IS NULL OR k.valid_until>clock_timestamp()) AND (c.signature_expires_at IS NULL OR c.signature_expires_at>clock_timestamp()))) AND ((NOT (i.definition ? 'scanner') OR i.definition->'scanner'='null'::jsonb) OR EXISTS(SELECT 1 FROM scanner_profiles s WHERE (s.tenant_id,s.partner_id,s.scanner_id,s.version,s.definition_hash,s.state)=(c.tenant_id,c.partner_id,c.scanner_id,c.scanner_version,c.scanner_hash,'active') AND s.valid_until>clock_timestamp() AND c.scan_expires_at>clock_timestamp())))))
 AND NOT EXISTS(SELECT 1 FROM workflow_collection_file_gates g WHERE (g.tenant_id,g.partner_id,g.file_id)=(t,p,f) AND NOT g.captured)
$$;
