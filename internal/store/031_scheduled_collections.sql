-- Per-occurrence source arrival is a stage of the existing reviewed calendar.
-- Probe leases govern bounded ready-manifest reads, not byte-transfer retries.
CREATE TABLE workflow_schedule_arrivals(
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,actor_id uuid NOT NULL,occurrence_id uuid NOT NULL,
 schedule_id uuid NOT NULL,schedule_version integer NOT NULL,
 definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object' AND octet_length(definition::text)<=4096),definition_hash text NOT NULL CHECK(definition_hash ~ '^[a-f0-9]{64}$'),
 state text NOT NULL CHECK(state IN ('waiting','probing','attention','ready','admitted','missing','expired','cancelled')),
 revision bigint NOT NULL CHECK(revision>0),fence bigint NOT NULL CHECK(fence BETWEEN 0 AND 65536),probes integer NOT NULL CHECK(probes BETWEEN 0 AND 65536),
 lease_owner uuid,lease_until timestamptz,next_probe_at timestamptz NOT NULL,observed_at timestamptz,
 manifest jsonb CHECK(manifest IS NULL OR (jsonb_typeof(manifest)='object' AND octet_length(manifest::text)<=32768)),manifest_hash text CHECK(manifest_hash IS NULL OR manifest_hash ~ '^[a-f0-9]{64}$'),collection_id uuid,
 reason text NOT NULL CHECK(reason ~ '^[a-z_]{1,64}$'),changed_event_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,occurrence_id),UNIQUE(tenant_id,partner_id,collection_id),
 FOREIGN KEY(tenant_id,partner_id,actor_id,schedule_id,schedule_version) REFERENCES workflow_schedules(tenant_id,partner_id,actor_id,schedule_id,version),
 FOREIGN KEY(tenant_id,partner_id,occurrence_id) REFERENCES workflow_schedule_occurrences(tenant_id,partner_id,occurrence_id),
 FOREIGN KEY(tenant_id,partner_id,collection_id) REFERENCES workflow_collection_jobs(tenant_id,partner_id,id),
 FOREIGN KEY(tenant_id,partner_id,changed_event_id) REFERENCES events(tenant_id,partner_id,event_id),
 CHECK(fence=probes),CHECK((state='probing' AND lease_owner IS NOT NULL AND lease_until IS NOT NULL) OR (state<>'probing' AND lease_owner IS NULL AND lease_until IS NULL)),CHECK((manifest IS NULL)=(manifest_hash IS NULL)),CHECK((manifest IS NULL)=(observed_at IS NULL)),
 CHECK((state NOT IN ('ready','admitted') OR manifest IS NOT NULL) AND (state<>'admitted' OR collection_id IS NOT NULL) AND (collection_id IS NULL OR state IN ('admitted','cancelled')))
);
CREATE INDEX workflow_schedule_arrival_pending ON workflow_schedule_arrivals(tenant_id,partner_id,actor_id,schedule_id,schedule_version,state,next_probe_at);
ALTER TABLE workflow_schedule_arrivals ENABLE ROW LEVEL SECURITY;
ALTER TABLE workflow_schedule_arrivals FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON workflow_schedule_arrivals USING(tenant_id=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND partner_id=nullif(current_setting('freightctl.partner_id',true),'')::uuid AND actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND partner_id=nullif(current_setting('freightctl.partner_id',true),'')::uuid AND actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid);
REVOKE ALL ON workflow_schedule_arrivals FROM PUBLIC;
GRANT SELECT,INSERT,UPDATE ON workflow_schedule_arrivals TO freightctl_runtime;
ALTER TABLE workflow_schedule_occurrences DROP CONSTRAINT workflow_schedule_occurrences_kind_check;
ALTER TABLE workflow_schedule_occurrences ADD CHECK(kind IN ('queued','empty','missed','skipped','collection'));

CREATE FUNCTION freightctl_collection_manifest_pattern(contract text,name text) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
 SELECT CASE WHEN contract='immutable-files-sha256-manifest-v1' THEN name ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$' AND right(name,11)='.ready.json'
 WHEN contract='immutable-files-sha256-scheduled-manifest-v1' THEN length(name)-length(replace(name,'{due_utc}',''))=9 AND replace(name,'{due_utc}','20060102T150405Z') ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$' AND right(name,11)='.ready.json' ELSE false END
$$;
CREATE FUNCTION freightctl_schedule_execution_owner(t uuid,p uuid,a uuid,d jsonb) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT freightctl_schedule_owner(t,p,a,ARRAY['workflow_execute','list','read']) AND
 CASE WHEN d ? 'collection' THEN freightctl_schedule_owner(t,p,a,ARRAY['write']) AND (jsonb_array_length(d->'effects')=0 OR freightctl_schedule_owner(t,p,a,ARRAY['deliver'])) ELSE freightctl_schedule_owner(t,p,a,ARRAY['deliver']) END
$$;

CREATE FUNCTION freightctl_scheduled_source_shape(source jsonb) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
 SELECT coalesce(ARRAY(SELECT jsonb_object_keys(source) ORDER BY 1)=ARRAY['completion_contract','connection','kind','manifest','max_file_bytes','max_files','max_total_bytes','target_directory']::text[]
 AND ARRAY(SELECT jsonb_object_keys(source->'connection') ORDER BY 1)=ARRAY['hash','id','version']::text[]
 AND source->>'kind'='sftp.collect' AND source->>'completion_contract'='immutable-files-sha256-scheduled-manifest-v1'
 AND freightctl_collection_manifest_pattern(source->>'completion_contract',source->>'manifest')
 AND jsonb_typeof(source->'max_files')='number' AND (source->>'max_files')::integer BETWEEN 1 AND 64
 AND jsonb_typeof(source->'max_file_bytes')='number' AND (source->>'max_file_bytes')::bigint BETWEEN 1 AND 1073741824
 AND jsonb_typeof(source->'max_total_bytes')='number' AND (source->>'max_total_bytes')::bigint BETWEEN 1 AND (source->>'max_files')::bigint*(source->>'max_file_bytes')::bigint,false)
$$;

CREATE FUNCTION freightctl_schedule_collection_config(t uuid,p uuid,a uuid,d jsonb) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT CASE WHEN NOT (d ? 'collection') THEN coalesce(d->'source'->>'kind','')='' AND NOT EXISTS(SELECT 1 FROM workflow_revisions w WHERE (w.tenant_id,w.partner_id,w.actor_id,w.workflow_id,w.version)=(t,p,a,(d->'workflow'->>'id')::uuid,(d->'workflow'->>'version')::integer) AND w.definition ? 'source')
 ELSE
 freightctl_scheduled_source_shape(d->'collection'->'source')
 AND ARRAY(SELECT jsonb_object_keys(d->'collection') ORDER BY 1)=ARRAY['arrival','source','source_connection']::text[]
 AND ARRAY(SELECT jsonb_object_keys(d->'collection'->'arrival') ORDER BY 1)=ARRAY['arrival_deadline_seconds','late_after_seconds','poll_interval_seconds']::text[]
 AND (d->'collection'->'arrival'->>'late_after_seconds')::integer>=0
 AND (d->'collection'->'arrival'->>'arrival_deadline_seconds')::integer>(d->'collection'->'arrival'->>'late_after_seconds')::integer
 AND (d->'collection'->'arrival'->>'arrival_deadline_seconds')::integer<(d->>'execution_deadline_seconds')::integer
 AND (d->'collection'->'arrival'->>'poll_interval_seconds')::integer BETWEEN 1 AND least(3600,(d->'collection'->'arrival'->>'arrival_deadline_seconds')::integer)
 AND ((d->'collection'->'arrival'->>'arrival_deadline_seconds')::integer+(d->'collection'->'arrival'->>'poll_interval_seconds')::integer-1)/(d->'collection'->'arrival'->>'poll_interval_seconds')::integer+1<=65536
 AND d->'source'->>'kind'='sftp.collect' AND d->'source'->>'recursive'='false' AND d->'source'->>'filename_regex'=''
 AND d->'source'->>'directory'=d->'collection'->'source'->>'target_directory' AND d->'source'->>'filename_pattern'=d->'collection'->'source'->>'manifest'
 AND d->>'max_files_per_occurrence'=d->'collection'->'source'->>'max_files'
 AND EXISTS(SELECT 1 FROM workflow_revisions w JOIN connection_revisions c ON (c.tenant_id,c.partner_id,c.actor_id,c.connection_id,c.version,c.definition_hash,c.state)=(t,p,a,(d->'collection'->'source'->'connection'->>'id')::uuid,(d->'collection'->'source'->'connection'->>'version')::integer,d->'collection'->'source'->'connection'->>'hash','active')
 WHERE (w.tenant_id,w.partner_id,w.actor_id,w.workflow_id,w.version,w.definition_hash,w.state,w.approval_authority)=(t,p,a,(d->'workflow'->>'id')::uuid,(d->'workflow'->>'version')::integer,d->'workflow'->>'hash','approved',(d->>'authority_revision')::bigint)
 AND w.definition->'source'=d->'collection'->'source' AND w.definition->'source'->>'completion_contract'='immutable-files-sha256-scheduled-manifest-v1'
 AND freightctl_collection_manifest_pattern(w.definition->'source'->>'completion_contract',w.definition->'source'->>'manifest')
 AND freightctl_collection_target_writable(t,p,a,w.definition->'source'->>'target_directory')
 AND d->'collection'->'source_connection'=jsonb_build_object('id',c.connection_id,'version',c.version,'definition_hash',c.definition_hash,'state',c.state,'revision',c.revision,'address',c.definition->'destination'->>'address','user',c.definition->'destination'->>'user','directory',c.definition->>'directory','host_fingerprint',c.definition->'destination'->'host'->>'Fingerprint','key_fingerprint',c.definition->'destination'->>'key_fingerprint')) END
$$;

CREATE OR REPLACE FUNCTION freightctl_workflow_schedule_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE e jsonb;d jsonb;n integer;authority bigint;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'schedule history is immutable' USING ERRCODE='23514';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id::text||':'||NEW.partner_id::text||':workflow-schedules',0));
 d:=NEW.definition;
 SELECT payload INTO e FROM events WHERE (tenant_id,partner_id,actor_id,event_id,resource_id,kind)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.changed_event_id,NEW.schedule_id,'WorkflowScheduleChanged');
 IF e IS NULL OR e->>'id' IS DISTINCT FROM NEW.schedule_id::text OR e->>'version' IS DISTINCT FROM NEW.version::text OR e->'definition' IS DISTINCT FROM d OR e->>'definition_hash' IS DISTINCT FROM NEW.definition_hash OR e->>'state' IS DISTINCT FROM NEW.state OR e->>'revision' IS DISTINCT FROM NEW.revision::text OR e->>'approval_authority' IS DISTINCT FROM NEW.approval_authority::text OR (e->>'next_due')::timestamptz IS DISTINCT FROM NEW.next_due OR (e->>'created_at')::timestamptz IS DISTINCT FROM NEW.created_at THEN RAISE EXCEPTION 'schedule requires its exact journal record' USING ERRCODE='23514';END IF;
 SELECT authority_revision INTO authority FROM credentials WHERE (tenant_id,partner_id,actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id);
 IF TG_OP='INSERT' THEN
  SELECT coalesce(max(version),0)+1 INTO n FROM workflow_schedules WHERE (tenant_id,partner_id,schedule_id)=(NEW.tenant_id,NEW.partner_id,NEW.schedule_id);
  IF NOT freightctl_schedule_owner(NEW.tenant_id,NEW.partner_id,NEW.actor_id,ARRAY['workflow_manage']) OR NEW.state<>'draft' OR NEW.revision<>1 OR NEW.approval_authority<>0 OR NEW.next_due IS NOT NULL OR NEW.version<>n OR EXISTS(SELECT 1 FROM workflow_schedules WHERE (tenant_id,partner_id,schedule_id)=(NEW.tenant_id,NEW.partner_id,NEW.schedule_id) AND actor_id<>NEW.actor_id) THEN RAISE EXCEPTION 'schedule begins with authorized versioned draft' USING ERRCODE='42501';END IF;
  IF ARRAY(SELECT key FROM jsonb_object_keys(d) key WHERE key<>'collection' ORDER BY 1) IS DISTINCT FROM ARRAY['authority_revision','calendar','effects','execution_deadline_seconds','late_start_grace_seconds','max_active_runs','max_catch_up','max_files_per_occurrence','missed_run_policy','name','namespace_root','schema_version','source','storage_id','workflow']::text[] OR d->>'schema_version'<>'1' OR d->>'authority_revision'<>authority::text OR d->>'namespace_root'<>'/' OR freightctl_schedule_effects_current(NEW.tenant_id,NEW.partner_id,NEW.actor_id,d) IS NOT TRUE OR d->>'missed_run_policy' NOT IN ('skip','latest','all') OR (d->>'max_catch_up')::integer NOT BETWEEN 1 AND 100 OR (d->>'max_active_runs')::integer NOT BETWEEN 1 AND 64 OR (d->>'max_files_per_occurrence')::integer NOT BETWEEN 1 AND 64 OR (d->>'execution_deadline_seconds')::integer NOT BETWEEN 1 AND 604800 OR (d->>'late_start_grace_seconds')::integer NOT BETWEEN 1 AND 3600 OR (d->>'late_start_grace_seconds')::integer>(d->>'execution_deadline_seconds')::integer OR d->'calendar'->>'gap_policy'<>'skip' OR d->'calendar'->>'fold_policy' NOT IN ('first','second','both') OR jsonb_array_length(d->'calendar'->'offset_rules') NOT BETWEEN 1 AND 64 OR jsonb_array_length(d->'calendar'->'local_times') NOT BETWEEN 1 AND 96 OR jsonb_array_length(d->'calendar'->'holidays')>512 OR freightctl_schedule_collection_config(NEW.tenant_id,NEW.partner_id,NEW.actor_id,d) IS NOT TRUE OR (NOT (d ? 'collection') AND (d->'source'->>'filename_pattern' !~ '^[A-Za-z0-9._*?-]{1,128}$' OR d->'source'->>'filename_regex' IS DISTINCT FROM '^'||replace(replace(replace(d->'source'->>'filename_pattern','.','[.]'),'*','.*'),'?','.')||'$')) THEN RAISE EXCEPTION 'invalid typed schedule definition' USING ERRCODE='23514';END IF;
 ELSE
  IF (NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.schedule_id,NEW.version,NEW.definition,NEW.definition_hash,NEW.created_at) IS DISTINCT FROM (OLD.tenant_id,OLD.partner_id,OLD.actor_id,OLD.schedule_id,OLD.version,OLD.definition,OLD.definition_hash,OLD.created_at) OR NEW.revision<>OLD.revision+1 OR OLD.state='revoked' THEN RAISE EXCEPTION 'schedule definition and history are immutable' USING ERRCODE='23514';END IF;
  IF NEW.state=OLD.state THEN
   IF OLD.state<>'active' OR NEW.approval_authority<>OLD.approval_authority OR NOT freightctl_schedule_execution_owner(NEW.tenant_id,NEW.partner_id,NEW.actor_id,d) OR OLD.next_due IS NULL OR (NEW.next_due IS NOT NULL AND NEW.next_due<=OLD.next_due) THEN RAISE EXCEPTION 'cursor advances only under current scheduler authority' USING ERRCODE='23514';END IF;
  ELSE
   IF NOT freightctl_schedule_owner(NEW.tenant_id,NEW.partner_id,NEW.actor_id,ARRAY['workflow_approve']) OR NOT ((NEW.state='active' AND OLD.state IN ('draft','suspended') AND NEW.approval_authority=authority AND d->>'authority_revision'=authority::text) OR (NEW.state IN ('suspended','revoked') AND OLD.state IN ('draft','active','suspended') AND NEW.approval_authority=OLD.approval_authority AND NEW.next_due IS NOT DISTINCT FROM OLD.next_due)) THEN RAISE EXCEPTION 'schedule control requires exact current approval' USING ERRCODE='42501';END IF;
  END IF;
 END IF;
 IF NEW.state='active' AND (freightctl_schedule_effects_current(NEW.tenant_id,NEW.partner_id,NEW.actor_id,d) IS NOT TRUE OR freightctl_schedule_collection_config(NEW.tenant_id,NEW.partner_id,NEW.actor_id,d) IS NOT TRUE) THEN RAISE EXCEPTION 'active calendar requires current source and receiver effects' USING ERRCODE='23514';END IF;RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION freightctl_workflow_schedule_occurrence_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE e jsonb;s workflow_schedules%ROWTYPE;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'schedule occurrences are immutable' USING ERRCODE='23514';END IF;
 IF NOT pg_try_advisory_xact_lock(hashtextextended(NEW.tenant_id::text||':'||NEW.partner_id::text||':workflow-schedules',0)) THEN RAISE EXCEPTION 'schedule admission guard busy' USING ERRCODE='40001';END IF;
 SELECT * INTO s FROM workflow_schedules WHERE (tenant_id,partner_id,actor_id,schedule_id,version)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.schedule_id,NEW.schedule_version);
 SELECT payload INTO e FROM events WHERE (tenant_id,partner_id,actor_id,event_id,resource_id,kind)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.event_id,NEW.occurrence_id,'WorkflowScheduleOccurrence');
 IF e IS NULL OR e->>'id' IS DISTINCT FROM NEW.occurrence_id::text OR e->>'schedule_id' IS DISTINCT FROM NEW.schedule_id::text OR e->>'schedule_version' IS DISTINCT FROM NEW.schedule_version::text OR (e->>'due_at')::timestamptz IS DISTINCT FROM NEW.due_at OR (e->>'deadline_at')::timestamptz IS DISTINCT FROM NEW.deadline_at OR e->>'kind' IS DISTINCT FROM NEW.kind OR (e->>'skipped_until')::timestamptz IS DISTINCT FROM NEW.skipped_until OR e->>'input_count' IS DISTINCT FROM NEW.input_count::text THEN RAISE EXCEPTION 'occurrence requires its exact journal record' USING ERRCODE='23514';END IF;
 IF s.state<>'active' OR s.approval_authority IS DISTINCT FROM (s.definition->>'authority_revision')::bigint OR NOT freightctl_schedule_execution_owner(NEW.tenant_id,NEW.partner_id,NEW.actor_id,s.definition) OR NOT freightctl_calendar_due(s.definition->'calendar',NEW.due_at) OR NEW.due_at>clock_timestamp() OR NEW.deadline_at<>NEW.due_at+make_interval(secs=>(s.definition->>'execution_deadline_seconds')::integer) OR (NEW.kind IN ('queued','empty','collection') AND (NEW.deadline_at<=clock_timestamp() OR (s.definition->>'missed_run_policy'='skip' AND NEW.due_at+make_interval(secs=>(s.definition->>'late_start_grace_seconds')::integer)<clock_timestamp()) OR (s.definition->>'missed_run_policy'='latest' AND NEW.due_at IS DISTINCT FROM freightctl_calendar_latest(s.definition->'calendar',clock_timestamp())))) OR ((NEW.kind='queued') IS DISTINCT FROM (NEW.input_count>0)) OR (NEW.kind='missed' AND NEW.deadline_at>clock_timestamp()) OR (NEW.kind='skipped' AND (NEW.skipped_until IS NULL OR NEW.skipped_until<=NEW.due_at)) OR (NEW.kind<>'skipped' AND NEW.skipped_until IS NOT NULL) THEN RAISE EXCEPTION 'occurrence requires due calendar and exact active policy' USING ERRCODE='23514';END IF;
 IF (NEW.kind='collection') AND NOT (s.definition ? 'collection') OR (s.definition ? 'collection') AND NEW.kind IN ('queued','empty') THEN RAISE EXCEPTION 'remote occurrence requires its typed arrival stage' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;

CREATE FUNCTION freightctl_arrival_definition_valid(t uuid,p uuid,a uuid,d jsonb) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT ARRAY(SELECT key FROM jsonb_object_keys(d) key ORDER BY 1)=ARRAY['arrival_deadline_at','deadline_at','due_at','late_after_at','manifest_name','occurrence_id','schedule','schema_version']::text[]
 AND d->>'schema_version'='1' AND EXISTS(SELECT 1 FROM workflow_schedule_occurrences o JOIN workflow_schedules s ON (s.tenant_id,s.partner_id,s.actor_id,s.schedule_id,s.version)=(o.tenant_id,o.partner_id,o.actor_id,o.schedule_id,o.schedule_version)
 WHERE (o.tenant_id,o.partner_id,o.actor_id,o.occurrence_id,o.kind)=(t,p,a,(d->>'occurrence_id')::uuid,'collection')
 AND d->'schedule'=jsonb_build_object('id',s.schedule_id,'version',s.version,'hash',s.definition_hash)
 AND (d->>'due_at')::timestamptz=o.due_at AND (d->>'deadline_at')::timestamptz=o.deadline_at
 AND (d->>'late_after_at')::timestamptz=o.due_at+make_interval(secs=>(s.definition->'collection'->'arrival'->>'late_after_seconds')::integer)
 AND (d->>'arrival_deadline_at')::timestamptz=o.due_at+make_interval(secs=>(s.definition->'collection'->'arrival'->>'arrival_deadline_seconds')::integer)
 AND d->>'manifest_name'=replace(s.definition->'collection'->'source'->>'manifest','{due_utc}',to_char(o.due_at AT TIME ZONE 'UTC','YYYYMMDD"T"HH24MISS"Z"')))
$$;
CREATE FUNCTION freightctl_arrival_manifest_valid(source jsonb,m jsonb) RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE f jsonb;total bigint:=0;n integer;
BEGIN
 IF m IS NULL OR ARRAY(SELECT jsonb_object_keys(m) ORDER BY 1) IS DISTINCT FROM ARRAY['batch_id','files','schema_version']::text[] OR m->'schema_version' IS DISTINCT FROM '1'::jsonb OR jsonb_typeof(m->'batch_id') IS DISTINCT FROM 'string' OR m->>'batch_id' !~ '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$' OR jsonb_typeof(m->'files') IS DISTINCT FROM 'array' OR jsonb_array_length(m->'files') NOT BETWEEN 1 AND (source->>'max_files')::integer OR octet_length(m::text)>32768 THEN RETURN false;END IF;
 SELECT count(DISTINCT value->>'name') INTO n FROM jsonb_array_elements(m->'files');IF n<>jsonb_array_length(m->'files') THEN RETURN false;END IF;
 FOR f IN SELECT value FROM jsonb_array_elements(m->'files') LOOP
  IF ARRAY(SELECT jsonb_object_keys(f) ORDER BY 1) IS DISTINCT FROM ARRAY['name','sha256','size_bytes']::text[] OR jsonb_typeof(f->'name') IS DISTINCT FROM 'string' OR jsonb_typeof(f->'sha256') IS DISTINCT FROM 'string' OR f->>'name' !~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$' OR right(f->>'name',1)='.' OR right(f->>'name',11)='.ready.json' OR f->>'sha256' !~ '^[a-f0-9]{64}$' OR jsonb_typeof(f->'size_bytes') IS DISTINCT FROM 'number' OR (f->>'size_bytes')::bigint NOT BETWEEN 0 AND (source->>'max_file_bytes')::bigint THEN RETURN false;END IF;
  total:=total+(f->>'size_bytes')::bigint;
 END LOOP;
 RETURN total<=(source->>'max_total_bytes')::bigint;
END $$;
CREATE FUNCTION freightctl_arrival_current(t uuid,p uuid,a uuid,d jsonb) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT freightctl_arrival_definition_valid(t,p,a,d) AND EXISTS(SELECT 1 FROM workflow_schedules s WHERE (s.tenant_id,s.partner_id,s.actor_id,s.schedule_id,s.version,s.definition_hash,s.state)=(t,p,a,(d->'schedule'->>'id')::uuid,(d->'schedule'->>'version')::integer,d->'schedule'->>'hash','active') AND s.approval_authority=(s.definition->>'authority_revision')::bigint AND freightctl_schedule_execution_owner(t,p,a,s.definition) AND EXISTS(SELECT 1 FROM credentials c WHERE (c.tenant_id,c.partner_id,c.actor_id,c.authority_revision)=(t,p,a,s.approval_authority)) AND freightctl_schedule_effects_current(t,p,a,s.definition) AND freightctl_schedule_collection_config(t,p,a,s.definition))
$$;
-- A ready observation uses the immutable event's database clock, never a
-- caller-supplied timestamp. Other arrival transitions retain that instant.
CREATE FUNCTION freightctl_arrival_event_time() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.kind='WorkflowScheduleArrivalChanged' AND NEW.payload->>'state'='ready' THEN
  NEW.happened_at:=clock_timestamp();
  NEW.payload:=jsonb_set(NEW.payload,'{observed_at}',to_jsonb(NEW.happened_at));
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER workflow_schedule_arrival_event_time BEFORE INSERT ON events FOR EACH ROW EXECUTE FUNCTION freightctl_arrival_event_time();

CREATE FUNCTION freightctl_schedule_arrival_guard() RETURNS trigger LANGUAGE plpgsql AS $$
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
   AND ((prior.state='ready' OR (prior.state IN ('waiting','probing','attention') AND (prior.definition->>'arrival_deadline_at')::timestamptz>clock_timestamp())) OR (prior.state='admitted' AND j.state NOT IN ('cancelled','expired') AND (NOT j.captured OR (jsonb_array_length(j.definition->'effects')>0 AND EXISTS(SELECT 1 FROM workflow_collection_inputs i LEFT JOIN workflow_runs r ON (r.tenant_id,r.partner_id,r.run_id)=(i.tenant_id,i.partner_id,i.run_id) WHERE (i.tenant_id,i.partner_id,i.actor_id,i.first_job_id)=(prior.tenant_id,prior.partner_id,prior.actor_id,prior.collection_id) AND (i.state<>'queued' OR r.state NOT IN ('succeeded','cancelled')))))));
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
CREATE TRIGGER workflow_schedule_arrival_guard BEFORE INSERT OR UPDATE OR DELETE ON workflow_schedule_arrivals FOR EACH ROW EXECUTE FUNCTION freightctl_schedule_arrival_guard();

CREATE FUNCTION freightctl_collection_schedule_binding(t uuid,p uuid,a uuid,d jsonb) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT CASE WHEN NOT (d ? 'schedule') THEN d->'source'->>'completion_contract'='immutable-files-sha256-manifest-v1'
 ELSE ARRAY(SELECT jsonb_object_keys(d->'schedule') ORDER BY 1)=ARRAY['arrival_deadline_at','deadline_at','due_at','manifest_hash','manifest_name','occurrence_id','schedule']::text[]
 AND EXISTS(SELECT 1 FROM workflow_schedule_arrivals arrival JOIN workflow_schedules s ON (s.tenant_id,s.partner_id,s.actor_id,s.schedule_id,s.version)=(arrival.tenant_id,arrival.partner_id,arrival.actor_id,arrival.schedule_id,arrival.schedule_version)
 WHERE (arrival.tenant_id,arrival.partner_id,arrival.actor_id,arrival.occurrence_id)=(t,p,a,(d->'schedule'->>'occurrence_id')::uuid) AND arrival.state IN ('ready','admitted') AND arrival.manifest IS NOT NULL
 AND freightctl_arrival_current(t,p,a,arrival.definition)
 AND d->'schedule'->'schedule'=arrival.definition->'schedule' AND (d->'schedule'->>'due_at')::timestamptz=(arrival.definition->>'due_at')::timestamptz AND (d->'schedule'->>'arrival_deadline_at')::timestamptz=(arrival.definition->>'arrival_deadline_at')::timestamptz AND (d->'schedule'->>'deadline_at')::timestamptz=(arrival.definition->>'deadline_at')::timestamptz AND d->'schedule'->>'manifest_name'=arrival.definition->>'manifest_name' AND d->'schedule'->>'manifest_hash'=arrival.manifest_hash
 AND d->'source'=s.definition->'collection'->'source' AND d->'source_connection'=s.definition->'collection'->'source_connection' AND d->'workflow'=s.definition->'workflow' AND d->'effects'=s.definition->'effects' AND d->>'authority_revision'=s.definition->>'authority_revision' AND d->>'storage_id'=s.definition->>'storage_id' AND d->>'namespace_root'=s.definition->>'namespace_root' AND d->>'timeout_seconds'=s.definition->>'execution_deadline_seconds') END
$$;

CREATE OR REPLACE FUNCTION freightctl_collection_definition_current(t uuid,p uuid,a uuid,d jsonb) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT freightctl_schedule_owner(t,p,a,ARRAY['workflow_execute','write','list','read']) AND d->>'schema_version'='1' AND d->>'namespace_root'='/'
 AND ARRAY(SELECT key FROM jsonb_object_keys(d) key WHERE key<>'schedule' ORDER BY 1)=ARRAY['authority_revision','effects','namespace_root','schema_version','source','source_connection','source_identity','storage_id','timeout_seconds','workflow']::text[]
 AND (d->>'timeout_seconds')::integer BETWEEN 1 AND CASE WHEN d ? 'schedule' THEN 604800 ELSE 3600 END AND freightctl_collection_schedule_binding(t,p,a,d)
 AND (jsonb_array_length(d->'effects')=0 OR freightctl_schedule_owner(t,p,a,ARRAY['deliver']))
 AND freightctl_collection_target_writable(t,p,a,d->'source'->>'target_directory')
 AND EXISTS(SELECT 1 FROM credentials u WHERE (u.tenant_id,u.partner_id,u.actor_id,u.authority_revision)=(t,p,a,(d->>'authority_revision')::bigint))
 AND freightctl_schedule_effects_current(t,p,a,d)
 AND EXISTS(SELECT 1 FROM workflow_revisions w JOIN connection_revisions c ON (c.tenant_id,c.partner_id,c.actor_id,c.connection_id,c.version,c.definition_hash,c.state)=(t,p,a,(d->'source'->'connection'->>'id')::uuid,(d->'source'->'connection'->>'version')::integer,d->'source'->'connection'->>'hash','active')
 WHERE (w.tenant_id,w.partner_id,w.actor_id,w.workflow_id,w.version,w.definition_hash,w.state,w.approval_authority)=(t,p,a,(d->'workflow'->>'id')::uuid,(d->'workflow'->>'version')::integer,d->'workflow'->>'hash','approved',(d->>'authority_revision')::bigint)
 AND w.definition->'source'=d->'source' AND d->'source'->>'kind'='sftp.collect' AND freightctl_collection_manifest_pattern(d->'source'->>'completion_contract',d->'source'->>'manifest')
 AND ARRAY(SELECT jsonb_object_keys(d->'source') ORDER BY 1)=ARRAY['completion_contract','connection','kind','manifest','max_file_bytes','max_files','max_total_bytes','target_directory']::text[]
 
 AND (d->'source'->>'max_files')::integer BETWEEN 1 AND 64 AND (d->'source'->>'max_file_bytes')::bigint BETWEEN 1 AND 1073741824
 AND (d->'source'->>'max_total_bytes')::bigint BETWEEN 1 AND (d->'source'->>'max_files')::bigint*(d->'source'->>'max_file_bytes')::bigint
 AND d->>'source_identity'=encode(sha256(convert_to(c.connection_id::text||':'||(c.definition->>'directory'),'UTF8')),'hex')
 AND d->'source_connection'=jsonb_build_object('id',c.connection_id,'version',c.version,'definition_hash',c.definition_hash,'state',c.state,'revision',c.revision,'address',c.definition->'destination'->>'address','user',c.definition->'destination'->>'user','directory',c.definition->>'directory','host_fingerprint',c.definition->'destination'->'host'->>'Fingerprint','key_fingerprint',c.definition->'destination'->>'key_fingerprint'))
$$;
CREATE OR REPLACE FUNCTION freightctl_collection_job_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE e jsonb;d jsonb;n integer;live boolean;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'collection history is immutable' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' AND NOT pg_try_advisory_xact_lock(hashtextextended(NEW.tenant_id::text||':'||NEW.partner_id::text||':workflow-collections',0)) THEN RAISE EXCEPTION 'collection admission guard busy' USING ERRCODE='40001';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended(NEW.tenant_id::text||':'||NEW.partner_id::text||':workflow-collections',0));
 SELECT payload INTO e FROM events WHERE (tenant_id,partner_id,actor_id,event_id,resource_id,kind)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.changed_event_id,NEW.id,'WorkflowCollectionChanged');
 IF e IS NULL OR (e-ARRAY['lease_owner','lease_until','next_at','created_at','deadline_at']) IS DISTINCT FROM (to_jsonb(NEW)-ARRAY['tenant_id','partner_id','actor_id','changed_event_id','lease_owner','lease_until','next_at','created_at','deadline_at']) OR e->>'lease_owner' IS DISTINCT FROM coalesce(NEW.lease_owner::text,'') OR (e->>'lease_until')::timestamptz IS DISTINCT FROM NEW.lease_until OR (e->>'next_at')::timestamptz IS DISTINCT FROM NEW.next_at OR (e->>'created_at')::timestamptz IS DISTINCT FROM NEW.created_at OR (e->>'deadline_at')::timestamptz IS DISTINCT FROM NEW.deadline_at THEN RAISE EXCEPTION 'collection requires its exact journal event' USING ERRCODE='23514';END IF;
 d:=NEW.definition;
 IF (NEW.workflow_id,NEW.workflow_version,NEW.workflow_hash) IS DISTINCT FROM ((d->'workflow'->>'id')::uuid,(d->'workflow'->>'version')::integer,d->'workflow'->>'hash') OR NEW.deadline_at<>(CASE WHEN d ? 'schedule' THEN (d->'schedule'->>'deadline_at')::timestamptz ELSE NEW.created_at+make_interval(secs=>(d->>'timeout_seconds')::integer) END) THEN RAISE EXCEPTION 'collection workflow and cutoff are immutable bindings' USING ERRCODE='23514';END IF;
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
 IF NEW.manifest IS NOT NULL AND d ? 'schedule' AND NOT EXISTS(SELECT 1 FROM workflow_schedule_arrivals a WHERE (a.tenant_id,a.partner_id,a.actor_id,a.occurrence_id,a.manifest_hash,a.manifest)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,(d->'schedule'->>'occurrence_id')::uuid,NEW.manifest_hash,NEW.manifest)) THEN RAISE EXCEPTION 'scheduled collection cannot replace the observed ready manifest' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;

CREATE FUNCTION freightctl_collection_schedule_lock() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN PERFORM pg_advisory_xact_lock_shared(hashtextextended(NEW.tenant_id::text||':'||NEW.partner_id::text||':workflow-schedules',0));RETURN NEW;END $$;
CREATE TRIGGER collection_aa_calendar_lock BEFORE INSERT OR UPDATE ON workflow_collection_jobs FOR EACH ROW EXECUTE FUNCTION freightctl_collection_schedule_lock();
CREATE TRIGGER collection_aa_calendar_lock BEFORE INSERT OR UPDATE ON workflow_collection_inputs FOR EACH ROW EXECUTE FUNCTION freightctl_collection_schedule_lock();
CREATE TRIGGER collection_aa_calendar_lock BEFORE INSERT ON workflow_collection_batches FOR EACH ROW EXECUTE FUNCTION freightctl_collection_schedule_lock();
CREATE OR REPLACE FUNCTION freightctl_collected_run_current(t uuid,p uuid,a uuid,target_run uuid) RETURNS boolean LANGUAGE plpgsql VOLATILE AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM workflow_collection_inputs WHERE (tenant_id,partner_id,actor_id,run_id)=(t,p,a,target_run)) THEN RETURN true;END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended(t::text||':'||p::text||':workflow-schedules',0));
 PERFORM pg_advisory_xact_lock_shared(hashtextextended(t::text||':'||p::text||':workflow-collections',0));
 RETURN freightctl_collected_run_status(t,p,a,target_run);
END $$;
CREATE FUNCTION freightctl_arrival_projection_complete() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.kind='WorkflowScheduleArrivalChanged' AND NOT EXISTS(SELECT 1 FROM workflow_schedule_arrivals a WHERE (a.tenant_id,a.partner_id,a.changed_event_id)=(NEW.tenant_id,NEW.partner_id,NEW.event_id)) THEN RAISE EXCEPTION 'arrival event requires exact projection' USING ERRCODE='23514';END IF;
 IF NEW.kind='WorkflowScheduleOccurrence' AND NEW.payload->>'kind'='collection' AND NOT EXISTS(SELECT 1 FROM workflow_schedule_arrivals a WHERE (a.tenant_id,a.partner_id,a.occurrence_id)=(NEW.tenant_id,NEW.partner_id,NEW.resource_id)) THEN RAISE EXCEPTION 'collection due decision requires its durable arrival intent' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER arrival_projection_complete AFTER INSERT ON events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION freightctl_arrival_projection_complete();
CREATE FUNCTION freightctl_arrival_collection_complete() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_TABLE_NAME='workflow_collection_jobs' THEN
  IF NEW.definition ? 'schedule' AND NOT EXISTS(SELECT 1 FROM workflow_schedule_arrivals a WHERE (a.tenant_id,a.partner_id,a.actor_id,a.occurrence_id,a.collection_id,a.state)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,(NEW.definition->'schedule'->>'occurrence_id')::uuid,NEW.id,'admitted') AND a.manifest_hash=NEW.definition->'schedule'->>'manifest_hash') THEN RAISE EXCEPTION 'scheduled job requires exact atomic original arrival link' USING ERRCODE='23514';END IF;
 ELSE
  IF NEW.collection_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM workflow_collection_jobs j WHERE (j.tenant_id,j.partner_id,j.id)=(NEW.tenant_id,NEW.partner_id,NEW.collection_id) AND j.definition->'schedule'->>'occurrence_id'=NEW.occurrence_id::text AND j.definition->'schedule'->>'manifest_hash'=NEW.manifest_hash) THEN RAISE EXCEPTION 'admitted arrival requires exact atomic collection job' USING ERRCODE='23514';END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER arrival_job_complete AFTER INSERT ON workflow_collection_jobs DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION freightctl_arrival_collection_complete();
CREATE CONSTRAINT TRIGGER arrival_collection_complete AFTER INSERT OR UPDATE ON workflow_schedule_arrivals DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION freightctl_arrival_collection_complete();
