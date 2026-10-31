-- Calendar definitions, cursor changes, occurrence decisions and input claims
-- are journal-bound. An input revision is consumed once per schedule family.
CREATE INDEX schedule_workflow_choices ON workflow_revisions(tenant_id,partner_id,actor_id,workflow_id,version DESC) WHERE state='approved';
CREATE TABLE workflow_schedules(
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,actor_id uuid NOT NULL,schedule_id uuid NOT NULL,version integer NOT NULL CHECK(version>0),
 definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object' AND octet_length(definition::text)<=32768),definition_hash text NOT NULL CHECK(definition_hash ~ '^[a-f0-9]{64}$'),
 state text NOT NULL CHECK(state IN ('draft','active','suspended','revoked')),revision bigint NOT NULL CHECK(revision>0),approval_authority bigint NOT NULL CHECK(approval_authority>=0),next_due timestamptz,created_at timestamptz NOT NULL,changed_event_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,schedule_id,version),UNIQUE(tenant_id,partner_id,actor_id,schedule_id,version),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),FOREIGN KEY(tenant_id,partner_id,changed_event_id) REFERENCES events(tenant_id,partner_id,event_id)
);
CREATE UNIQUE INDEX workflow_schedule_one_active ON workflow_schedules(tenant_id,partner_id,schedule_id) WHERE state='active';
CREATE INDEX workflow_schedule_due ON workflow_schedules(tenant_id,partner_id,actor_id,next_due,schedule_id) WHERE state='active';
CREATE TABLE workflow_schedule_occurrences(
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,actor_id uuid NOT NULL,occurrence_id uuid NOT NULL,schedule_id uuid NOT NULL,schedule_version integer NOT NULL,
 due_at timestamptz NOT NULL,deadline_at timestamptz NOT NULL,kind text NOT NULL CHECK(kind IN ('queued','empty','missed','skipped')),skipped_until timestamptz,input_count integer NOT NULL CHECK(input_count BETWEEN 0 AND 64),event_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,occurrence_id),UNIQUE(tenant_id,partner_id,schedule_id,schedule_version,due_at),
 FOREIGN KEY(tenant_id,partner_id,actor_id,schedule_id,schedule_version) REFERENCES workflow_schedules(tenant_id,partner_id,actor_id,schedule_id,version),FOREIGN KEY(tenant_id,partner_id,event_id) REFERENCES events(tenant_id,partner_id,event_id)
);
CREATE TABLE workflow_schedule_inputs(
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,actor_id uuid NOT NULL,schedule_id uuid NOT NULL,schedule_version integer NOT NULL,occurrence_id uuid NOT NULL,file_id uuid NOT NULL,run_id uuid NOT NULL,event_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,schedule_id,file_id),UNIQUE(tenant_id,partner_id,run_id),
 FOREIGN KEY(tenant_id,partner_id,actor_id,schedule_id,schedule_version) REFERENCES workflow_schedules(tenant_id,partner_id,actor_id,schedule_id,version),FOREIGN KEY(tenant_id,partner_id,occurrence_id) REFERENCES workflow_schedule_occurrences(tenant_id,partner_id,occurrence_id),FOREIGN KEY(tenant_id,partner_id,file_id) REFERENCES files(tenant_id,partner_id,file_id),FOREIGN KEY(tenant_id,partner_id,run_id) REFERENCES workflow_runs(tenant_id,partner_id,run_id),FOREIGN KEY(tenant_id,partner_id,event_id) REFERENCES events(tenant_id,partner_id,event_id)
);
CREATE INDEX workflow_schedule_input_occurrence ON workflow_schedule_inputs(tenant_id,partner_id,actor_id,occurrence_id,run_id);
CREATE INDEX schedule_pending_runs ON workflow_runs(tenant_id,partner_id,actor_id,run_id) WHERE state NOT IN ('succeeded','cancelled');
DO $$ DECLARE t text;BEGIN
 FOREACH t IN ARRAY ARRAY['workflow_schedules','workflow_schedule_occurrences','workflow_schedule_inputs'] LOOP
  EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',t);EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('CREATE POLICY scope ON %I USING(tenant_id=nullif(current_setting(''freightctl.tenant_id'',true),'''')::uuid AND partner_id=nullif(current_setting(''freightctl.partner_id'',true),'''')::uuid AND actor_id=nullif(current_setting(''freightctl.actor_id'',true),'''')::uuid) WITH CHECK(tenant_id=nullif(current_setting(''freightctl.tenant_id'',true),'''')::uuid AND partner_id=nullif(current_setting(''freightctl.partner_id'',true),'''')::uuid AND actor_id=nullif(current_setting(''freightctl.actor_id'',true),'''')::uuid)',t);
 END LOOP;
END $$;
REVOKE ALL ON workflow_schedules,workflow_schedule_occurrences,workflow_schedule_inputs FROM PUBLIC;
GRANT SELECT,INSERT,UPDATE ON workflow_schedules TO freightctl_runtime;
GRANT SELECT,INSERT ON workflow_schedule_occurrences,workflow_schedule_inputs TO freightctl_runtime;
CREATE FUNCTION freightctl_schedule_owner(t uuid,p uuid,a uuid,g text[]) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT (t,p,a)=(nullif(current_setting('freightctl.tenant_id',true),'')::uuid,nullif(current_setting('freightctl.partner_id',true),'')::uuid,nullif(current_setting('freightctl.actor_id',true),'')::uuid) AND EXISTS(SELECT 1 FROM credentials c WHERE (c.tenant_id,c.partner_id,c.actor_id)=(t,p,a) AND c.namespace_root='/' AND c.permissions @> g AND c.revoked_at IS NULL AND (c.expires_at IS NULL OR c.expires_at>clock_timestamp()))
$$;
CREATE FUNCTION freightctl_calendar_due(c jsonb,at timestamptz) RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE r jsonb;wall timestamp;candidate timestamptz;first_at timestamptz;last_at timestamptz;n integer:=0;
BEGIN
 IF at<(c->>'starts_at')::timestamptz OR at>=(c->>'ends_at')::timestamptz OR date_trunc('second',at)<>at THEN RETURN false;END IF;
 SELECT value INTO r FROM jsonb_array_elements(c->'offset_rules') WHERE at>=(value->>'from')::timestamptz AND at<(value->>'until')::timestamptz;
 IF r IS NULL THEN RETURN false;END IF;
 wall:=(at AT TIME ZONE 'UTC')+make_interval(secs=>(r->>'offset_seconds')::integer);
 IF NOT (c->'local_times' ? to_char(wall,'HH24:MI:SS')) OR NOT (c->'weekdays' @> jsonb_build_array(extract(dow FROM wall)::integer)) OR c->'holidays' ? to_char(wall,'YYYY-MM-DD') THEN RETURN false;END IF;
 FOR r IN SELECT value FROM jsonb_array_elements(c->'offset_rules') LOOP
  candidate:=(wall-make_interval(secs=>(r->>'offset_seconds')::integer)) AT TIME ZONE 'UTC';
  IF candidate>=(r->>'from')::timestamptz AND candidate<(r->>'until')::timestamptz THEN n:=n+1;first_at:=least(first_at,candidate);last_at:=greatest(last_at,candidate);END IF;
 END LOOP;
 RETURN n>0 AND (n=1 OR c->>'fold_policy'='both' OR (c->>'fold_policy'='first' AND at=first_at) OR (c->>'fold_policy'='second' AND at=last_at));
END $$;
CREATE FUNCTION freightctl_schedule_effects_current(t uuid,p uuid,a uuid,d jsonb) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT EXISTS(SELECT 1 FROM workflow_revisions w WHERE (w.tenant_id,w.partner_id,w.actor_id,w.workflow_id,w.version,w.definition_hash,w.state,w.approval_authority)=(t,p,a,(d->'workflow'->>'id')::uuid,(d->'workflow'->>'version')::integer,d->'workflow'->>'hash','approved',(d->>'authority_revision')::bigint)
 AND jsonb_array_length(d->'effects')=jsonb_array_length(w.definition->'steps') AND NOT EXISTS(
 SELECT 1 FROM jsonb_array_elements(w.definition->'steps') WITH ORDINALITY step(value,ordinal)
 LEFT JOIN connection_revisions c ON (c.tenant_id,c.partner_id,c.actor_id,c.connection_id,c.version)=(t,p,a,(step.value->'connection'->>'id')::uuid,(step.value->'connection'->>'version')::integer)
 LEFT JOIN pgp_keys k ON (k.tenant_id,k.partner_id,k.key_id,k.version)=(t,p,(step.value->'encryption'->'key'->>'id')::uuid,(step.value->'encryption'->'key'->>'version')::integer)
 WHERE c.connection_id IS NULL OR c.state<>'active' OR c.definition_hash IS DISTINCT FROM step.value->'connection'->>'hash'
 OR d->'effects'->(step.ordinal::integer-1) IS DISTINCT FROM jsonb_strip_nulls(jsonb_build_object('step_id',step.value->>'id','connection',step.value->'connection','address',c.definition->'destination'->>'address','directory',c.definition->>'directory','final_name_pattern','<delivery UUID>-'||(step.value->>'filename'),'host_fingerprint',c.definition->'destination'->'host'->>'Fingerprint','encryption',step.value->'encryption','recipient_fingerprint',CASE WHEN step.value ? 'encryption' THEN k.definition->>'fingerprint' ELSE NULL END,'encryption_fingerprint',CASE WHEN step.value ? 'encryption' THEN k.definition->'recipient'->>'encryption_fingerprint' ELSE NULL END))))
$$;
CREATE FUNCTION freightctl_calendar_latest(c jsonb,before_at timestamptz) RETURNS timestamptz LANGUAGE sql IMMUTABLE AS $$
 SELECT max(candidate.at) FROM generate_series(date_trunc('day',before_at AT TIME ZONE 'UTC')-interval '8 days',date_trunc('day',before_at AT TIME ZONE 'UTC')+interval '2 days',interval '1 day') civil(day)
 CROSS JOIN jsonb_array_elements_text(c->'local_times') clock(value)
 CROSS JOIN jsonb_array_elements(c->'offset_rules') rule(value)
 CROSS JOIN LATERAL(SELECT ((civil.day::date+clock.value::time)-make_interval(secs=>(rule.value->>'offset_seconds')::integer)) AT TIME ZONE 'UTC' AS at) candidate
 WHERE candidate.at<=before_at AND candidate.at>=(rule.value->>'from')::timestamptz AND candidate.at<(rule.value->>'until')::timestamptz AND freightctl_calendar_due(c,candidate.at)
$$;
CREATE FUNCTION freightctl_workflow_schedule_guard() RETURNS trigger LANGUAGE plpgsql AS $$
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
  IF ARRAY(SELECT jsonb_object_keys(d) ORDER BY 1) IS DISTINCT FROM ARRAY['authority_revision','calendar','effects','execution_deadline_seconds','late_start_grace_seconds','max_active_runs','max_catch_up','max_files_per_occurrence','missed_run_policy','name','namespace_root','schema_version','source','storage_id','workflow']::text[] OR d->>'schema_version'<>'1' OR d->>'authority_revision'<>authority::text OR d->>'namespace_root'<>'/' OR freightctl_schedule_effects_current(NEW.tenant_id,NEW.partner_id,NEW.actor_id,d) IS NOT TRUE OR d->>'missed_run_policy' NOT IN ('skip','latest','all') OR (d->>'max_catch_up')::integer NOT BETWEEN 1 AND 100 OR (d->>'max_active_runs')::integer NOT BETWEEN 1 AND 64 OR (d->>'max_files_per_occurrence')::integer NOT BETWEEN 1 AND 64 OR (d->>'execution_deadline_seconds')::integer NOT BETWEEN 1 AND 604800 OR (d->>'late_start_grace_seconds')::integer NOT BETWEEN 1 AND 3600 OR (d->>'late_start_grace_seconds')::integer>(d->>'execution_deadline_seconds')::integer OR d->'calendar'->>'gap_policy'<>'skip' OR d->'calendar'->>'fold_policy' NOT IN ('first','second','both') OR jsonb_array_length(d->'calendar'->'offset_rules') NOT BETWEEN 1 AND 64 OR jsonb_array_length(d->'calendar'->'local_times') NOT BETWEEN 1 AND 96 OR jsonb_array_length(d->'calendar'->'holidays')>512 OR d->'source'->>'filename_pattern' !~ '^[A-Za-z0-9._*?-]{1,128}$' OR d->'source'->>'filename_regex' IS DISTINCT FROM '^'||replace(replace(replace(d->'source'->>'filename_pattern','.','[.]'),'*','.*'),'?','.')||'$' THEN RAISE EXCEPTION 'invalid typed schedule definition' USING ERRCODE='23514';END IF;
 ELSE
  IF (NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.schedule_id,NEW.version,NEW.definition,NEW.definition_hash,NEW.created_at) IS DISTINCT FROM (OLD.tenant_id,OLD.partner_id,OLD.actor_id,OLD.schedule_id,OLD.version,OLD.definition,OLD.definition_hash,OLD.created_at) OR NEW.revision<>OLD.revision+1 OR OLD.state='revoked' THEN RAISE EXCEPTION 'schedule definition and history are immutable' USING ERRCODE='23514';END IF;
  IF NEW.state=OLD.state THEN
   IF OLD.state<>'active' OR NEW.approval_authority<>OLD.approval_authority OR NOT freightctl_schedule_owner(NEW.tenant_id,NEW.partner_id,NEW.actor_id,ARRAY['workflow_execute','list','read','deliver']) OR OLD.next_due IS NULL OR (NEW.next_due IS NOT NULL AND NEW.next_due<=OLD.next_due) THEN RAISE EXCEPTION 'cursor advances only under current scheduler authority' USING ERRCODE='23514';END IF;
  ELSE
   IF NOT freightctl_schedule_owner(NEW.tenant_id,NEW.partner_id,NEW.actor_id,ARRAY['workflow_approve']) OR NOT ((NEW.state='active' AND OLD.state IN ('draft','suspended') AND NEW.approval_authority=authority AND d->>'authority_revision'=authority::text) OR (NEW.state IN ('suspended','revoked') AND OLD.state IN ('draft','active','suspended') AND NEW.approval_authority=OLD.approval_authority AND NEW.next_due IS NOT DISTINCT FROM OLD.next_due)) THEN RAISE EXCEPTION 'schedule control requires exact current approval' USING ERRCODE='42501';END IF;
  END IF;
 END IF;RETURN NEW;
END $$;
CREATE TRIGGER workflow_schedule_guard BEFORE INSERT OR UPDATE OR DELETE ON workflow_schedules FOR EACH ROW EXECUTE FUNCTION freightctl_workflow_schedule_guard();
CREATE FUNCTION freightctl_workflow_schedule_occurrence_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE e jsonb;s workflow_schedules%ROWTYPE;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'schedule occurrences are immutable' USING ERRCODE='23514';END IF;
 IF NOT pg_try_advisory_xact_lock(hashtextextended(NEW.tenant_id::text||':'||NEW.partner_id::text||':workflow-schedules',0)) THEN RAISE EXCEPTION 'schedule admission guard busy' USING ERRCODE='40001';END IF;
 SELECT * INTO s FROM workflow_schedules WHERE (tenant_id,partner_id,actor_id,schedule_id,version)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.schedule_id,NEW.schedule_version);
 SELECT payload INTO e FROM events WHERE (tenant_id,partner_id,actor_id,event_id,resource_id,kind)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.event_id,NEW.occurrence_id,'WorkflowScheduleOccurrence');
 IF e IS NULL OR e->>'id' IS DISTINCT FROM NEW.occurrence_id::text OR e->>'schedule_id' IS DISTINCT FROM NEW.schedule_id::text OR e->>'schedule_version' IS DISTINCT FROM NEW.schedule_version::text OR (e->>'due_at')::timestamptz IS DISTINCT FROM NEW.due_at OR (e->>'deadline_at')::timestamptz IS DISTINCT FROM NEW.deadline_at OR e->>'kind' IS DISTINCT FROM NEW.kind OR (e->>'skipped_until')::timestamptz IS DISTINCT FROM NEW.skipped_until OR e->>'input_count' IS DISTINCT FROM NEW.input_count::text THEN RAISE EXCEPTION 'occurrence requires its exact journal record' USING ERRCODE='23514';END IF;
 IF s.state<>'active' OR s.approval_authority IS DISTINCT FROM (s.definition->>'authority_revision')::bigint OR NOT freightctl_schedule_owner(NEW.tenant_id,NEW.partner_id,NEW.actor_id,ARRAY['workflow_execute','list','read','deliver']) OR NOT freightctl_calendar_due(s.definition->'calendar',NEW.due_at) OR NEW.due_at>clock_timestamp() OR NEW.deadline_at<>NEW.due_at+make_interval(secs=>(s.definition->>'execution_deadline_seconds')::integer) OR (NEW.kind IN ('queued','empty') AND (NEW.deadline_at<=clock_timestamp() OR (s.definition->>'missed_run_policy'='skip' AND NEW.due_at+make_interval(secs=>(s.definition->>'late_start_grace_seconds')::integer)<clock_timestamp()) OR (s.definition->>'missed_run_policy'='latest' AND NEW.due_at IS DISTINCT FROM freightctl_calendar_latest(s.definition->'calendar',clock_timestamp())))) OR ((NEW.kind='queued') IS DISTINCT FROM (NEW.input_count>0)) OR (NEW.kind='missed' AND NEW.deadline_at>clock_timestamp()) OR (NEW.kind='skipped' AND (NEW.skipped_until IS NULL OR NEW.skipped_until<=NEW.due_at)) OR (NEW.kind<>'skipped' AND NEW.skipped_until IS NOT NULL) THEN RAISE EXCEPTION 'occurrence requires due calendar and exact active policy' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER workflow_schedule_occurrence_guard BEFORE INSERT OR UPDATE OR DELETE ON workflow_schedule_occurrences FOR EACH ROW EXECUTE FUNCTION freightctl_workflow_schedule_occurrence_guard();
CREATE FUNCTION freightctl_scheduled_run_status(t uuid,p uuid,a uuid,id uuid) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT NOT EXISTS(SELECT 1 FROM workflow_schedule_inputs WHERE (tenant_id,partner_id,actor_id,run_id)=(t,p,a,id)) OR EXISTS(SELECT 1 FROM workflow_schedule_inputs i JOIN workflow_schedules s ON (s.tenant_id,s.partner_id,s.actor_id,s.schedule_id,s.version)=(i.tenant_id,i.partner_id,i.actor_id,i.schedule_id,i.schedule_version) JOIN workflow_schedule_occurrences o ON (o.tenant_id,o.partner_id,o.occurrence_id)=(i.tenant_id,i.partner_id,i.occurrence_id) JOIN credentials c ON (c.tenant_id,c.partner_id,c.actor_id)=(i.tenant_id,i.partner_id,i.actor_id) WHERE (i.tenant_id,i.partner_id,i.actor_id,i.run_id)=(t,p,a,id) AND s.state='active' AND c.authority_revision=s.approval_authority AND s.approval_authority=(s.definition->>'authority_revision')::bigint AND c.namespace_root='/' AND c.permissions @> ARRAY['workflow_execute','list','read','deliver']::text[] AND c.revoked_at IS NULL AND (c.expires_at IS NULL OR c.expires_at>clock_timestamp()) AND o.deadline_at>clock_timestamp() AND o.kind='queued' AND freightctl_schedule_effects_current(t,p,a,s.definition))
$$;
CREATE FUNCTION freightctl_scheduled_run_current(t uuid,p uuid,a uuid,id uuid) RETURNS boolean LANGUAGE plpgsql VOLATILE AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM workflow_schedule_inputs WHERE (tenant_id,partner_id,actor_id,run_id)=(t,p,a,id)) THEN RETURN true;END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended(t::text||':'||p::text||':workflow-schedules',0));
 RETURN freightctl_scheduled_run_status(t,p,a,id);
END $$;
CREATE FUNCTION freightctl_workflow_schedule_input_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE e jsonb;s workflow_schedules%ROWTYPE;o workflow_schedule_occurrences%ROWTYPE;n integer;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'schedule input claims cannot be erased' USING ERRCODE='23514';END IF;
 IF NOT pg_try_advisory_xact_lock(hashtextextended(NEW.tenant_id::text||':'||NEW.partner_id::text||':workflow-schedules',0)) THEN RAISE EXCEPTION 'schedule admission guard busy' USING ERRCODE='40001';END IF;
 SELECT * INTO s FROM workflow_schedules WHERE (tenant_id,partner_id,actor_id,schedule_id,version)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.schedule_id,NEW.schedule_version);
 SELECT * INTO o FROM workflow_schedule_occurrences WHERE (tenant_id,partner_id,occurrence_id,schedule_id,schedule_version,actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.occurrence_id,NEW.schedule_id,NEW.schedule_version,NEW.actor_id);
 SELECT payload INTO e FROM events WHERE (tenant_id,partner_id,actor_id,event_id,resource_id,kind)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.event_id,NEW.run_id,'WorkflowScheduleInput');
 IF e IS NULL OR e->>'schedule_id' IS DISTINCT FROM NEW.schedule_id::text OR e->>'schedule_version' IS DISTINCT FROM NEW.schedule_version::text OR e->>'occurrence_id' IS DISTINCT FROM NEW.occurrence_id::text OR e->>'file_id' IS DISTINCT FROM NEW.file_id::text OR e->>'run_id' IS DISTINCT FROM NEW.run_id::text OR s.state<>'active' OR o.kind<>'queued' OR o.deadline_at<=clock_timestamp() OR NOT freightctl_schedule_owner(NEW.tenant_id,NEW.partner_id,NEW.actor_id,ARRAY['workflow_execute','list','read','deliver']) THEN RAISE EXCEPTION 'input requires its due approved schedule and exact event' USING ERRCODE='23514';END IF;
 IF NOT EXISTS(SELECT 1 FROM workflow_runs r JOIN files f USING(tenant_id,partner_id,file_id) JOIN events accepted ON (accepted.tenant_id,accepted.partner_id,accepted.event_id)=(f.tenant_id,f.partner_id,f.accepted_event_id) WHERE (r.tenant_id,r.partner_id,r.actor_id,r.run_id,r.file_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.run_id,NEW.file_id) AND r.workflow_id=(s.definition->'workflow'->>'id')::uuid AND r.workflow_version=(s.definition->'workflow'->>'version')::integer AND r.workflow_hash=s.definition->'workflow'->>'hash' AND r.authority_revision=s.approval_authority AND r.storage_id=(s.definition->>'storage_id')::uuid AND accepted.happened_at<=o.due_at AND freightctl_file_available(r.tenant_id,r.partner_id,r.file_id) AND EXISTS(SELECT 1 FROM namespace_entries n WHERE (n.tenant_id,n.partner_id,n.file_id)=(r.tenant_id,r.partner_id,r.file_id) AND n.kind='file' AND NOT n.deleted AND (EXISTS(SELECT 1 FROM credentials owner_credential WHERE (owner_credential.tenant_id,owner_credential.partner_id,owner_credential.actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id) AND 'admin'=ANY(owner_credential.permissions)) OR (((n.owner_actor_id=NEW.actor_id AND (n.mode & 256)=256) OR (n.owner_actor_id<>NEW.actor_id AND (n.mode & 32)=32)) AND NOT EXISTS(SELECT 1 FROM namespace_entries ancestor WHERE NOT ancestor.deleted AND ancestor.kind='dir' AND (ancestor.path='/' OR starts_with(n.path,ancestor.path||'/')) AND ((ancestor.owner_actor_id=NEW.actor_id AND (ancestor.mode & 320)<>320) OR (ancestor.owner_actor_id<>NEW.actor_id AND (ancestor.mode & 40)<>40))))) AND EXISTS(SELECT 1 FROM events publication WHERE (publication.tenant_id,publication.partner_id,publication.event_id)=(n.tenant_id,n.partner_id,n.changed_event_id) AND publication.happened_at<=o.due_at) AND n.path !~ '(^|/)[.]freightctl-' AND ((s.definition->'source'->>'recursive')::boolean AND starts_with(n.path,rtrim(s.definition->'source'->>'directory','/')||'/') OR n.parent_path=s.definition->'source'->>'directory') AND regexp_replace(n.path,'^.*/','') ~ (s.definition->'source'->>'filename_regex'))) THEN RAISE EXCEPTION 'input must be complete authorized accepted revision under exact source policy' USING ERRCODE='23514';END IF;
 SELECT count(*) INTO n FROM workflow_schedule_inputs i JOIN workflow_schedule_occurrences prior_occurrence USING(tenant_id,partner_id,occurrence_id) JOIN workflow_runs r USING(tenant_id,partner_id,run_id) WHERE (i.tenant_id,i.partner_id,i.actor_id,i.schedule_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.schedule_id) AND i.schedule_version=NEW.schedule_version AND prior_occurrence.deadline_at>clock_timestamp() AND r.state NOT IN ('succeeded','cancelled');
 IF n>=(s.definition->>'max_active_runs')::integer THEN RAISE EXCEPTION 'schedule concurrency budget exhausted' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER workflow_schedule_input_guard BEFORE INSERT OR UPDATE OR DELETE ON workflow_schedule_inputs FOR EACH ROW EXECUTE FUNCTION freightctl_workflow_schedule_input_guard();
CREATE FUNCTION freightctl_schedule_event_complete() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.kind='WorkflowScheduleChanged' AND NOT EXISTS(SELECT 1 FROM workflow_schedules s WHERE (s.tenant_id,s.partner_id,s.changed_event_id)=(NEW.tenant_id,NEW.partner_id,NEW.event_id)) THEN RAISE EXCEPTION 'schedule event requires projection' USING ERRCODE='23514';END IF;
 IF NEW.kind='WorkflowScheduleOccurrence' AND NOT EXISTS(SELECT 1 FROM workflow_schedule_occurrences o WHERE (o.tenant_id,o.partner_id,o.event_id)=(NEW.tenant_id,NEW.partner_id,NEW.event_id) AND o.input_count=(SELECT count(*) FROM workflow_schedule_inputs i WHERE (i.tenant_id,i.partner_id,i.occurrence_id)=(o.tenant_id,o.partner_id,o.occurrence_id))) THEN RAISE EXCEPTION 'occurrence requires exact input claims' USING ERRCODE='23514';END IF;
 IF NEW.kind='WorkflowScheduleInput' AND NOT EXISTS(SELECT 1 FROM workflow_schedule_inputs i WHERE (i.tenant_id,i.partner_id,i.event_id)=(NEW.tenant_id,NEW.partner_id,NEW.event_id)) THEN RAISE EXCEPTION 'input event requires projection' USING ERRCODE='23514';END IF;RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER schedule_event_complete AFTER INSERT ON events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION freightctl_schedule_event_complete();
CREATE FUNCTION freightctl_schedule_effect_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE run_id uuid;
BEGIN
 IF TG_TABLE_NAME='delivery_ciphertexts' THEN SELECT (definition->'workflow_binding'->>'run_id')::uuid INTO run_id FROM delivery_intents WHERE (tenant_id,partner_id,delivery_id)=(NEW.tenant_id,NEW.partner_id,NEW.delivery_id);
 ELSE
  run_id:=(NEW.definition->'workflow_binding'->>'run_id')::uuid;
  IF NEW.state NOT IN ('staging','publishing','succeeded') THEN RETURN NEW;END IF;
  IF TG_OP='UPDATE' AND OLD.state='ambiguous' AND NEW.state='succeeded' AND NEW.observation->>'code'='remote_file_integrity_observed' AND NEW.observation->>'reconciled'='true' THEN RETURN NEW;END IF;
 END IF;
 IF run_id IS NOT NULL AND NOT freightctl_scheduled_run_current(NEW.tenant_id,NEW.partner_id,NEW.actor_id,run_id) THEN RAISE EXCEPTION 'current schedule and execution deadline required' USING ERRCODE='23514';END IF;RETURN NEW;
END $$;
-- Alphabetical trigger order is part of the shared lock order:
-- onboarding approval -> schedule -> outbound dispatch approval.
CREATE TRIGGER outbound_a_schedule_effect_guard BEFORE INSERT OR UPDATE ON delivery_intents FOR EACH ROW EXECUTE FUNCTION freightctl_schedule_effect_guard();
CREATE TRIGGER outbound_a_schedule_ciphertext_guard BEFORE INSERT ON delivery_ciphertexts FOR EACH ROW EXECUTE FUNCTION freightctl_schedule_effect_guard();
CREATE FUNCTION freightctl_schedule_authority_lock() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id::text||':'||NEW.partner_id::text||':workflow-schedules',0));RETURN NEW;END $$;
CREATE TRIGGER onboarding_schedule_authority_lock BEFORE UPDATE ON credentials FOR EACH ROW EXECUTE FUNCTION freightctl_schedule_authority_lock();
