-- Approved owned processing calendars reuse immutable occurrences and claims.
-- No delivery authority is inherited;legacy schema1 keeps its exact contract.

CREATE FUNCTION freightctl_processing_schedule_current(t uuid,p uuid,a uuid,d jsonb) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT coalesce(EXISTS(SELECT 1 FROM workflow_revisions w JOIN credentials c ON (c.tenant_id,c.partner_id,c.actor_id)=(w.tenant_id,w.partner_id,w.actor_id)
 WHERE (w.tenant_id,w.partner_id,w.actor_id,w.workflow_id,w.version,w.definition_hash,w.state,w.approval_authority)=(t,p,a,(d->'workflow'->>'id')::uuid,(d->'workflow'->>'version')::integer,d->'workflow'->>'hash','approved',(d->>'authority_revision')::bigint)
 AND a=nullif(current_setting('freightctl.actor_id',true),'')::uuid AND c.revoked_at IS NULL AND (c.expires_at IS NULL OR c.expires_at>clock_timestamp()) AND c.namespace_root='/' AND c.authority_revision=w.approval_authority
 AND c.permissions @> ARRAY['read','write','check_run','workflow_execute','list']::text[]
 AND d->>'schema_version'='2' AND d->>'namespace_root'='/' AND d->'source'->>'kind'='owned_released_records' AND NOT (d ? 'collection') AND d->'effects'='[]'::jsonb
 AND ARRAY(SELECT jsonb_object_keys(d->'processing') ORDER BY 1)=ARRAY['profile','task']::text[] AND d->'processing'->>'profile'='owned-record-processing-schedule-v1'
 AND w.definition->>'schema_version'='3' AND w.definition->'steps'='[]'::jsonb AND NOT (w.definition ? 'source') AND d->'processing'->'task'=w.definition->'processing'
 AND freightctl_processing_review_current(t,p,a,w.workflow_id,w.version,w.definition_hash)
 AND EXISTS(SELECT 1 FROM intake_policies i WHERE (i.tenant_id,i.partner_id,i.policy_id,i.version,i.definition_hash)=(t,p,(w.definition->'processing'->'output_policy'->>'id')::uuid,(w.definition->'processing'->'output_policy'->>'version')::integer,w.definition->'processing'->'output_policy'->>'hash')
 AND ((i.state='active' AND NOT EXISTS(SELECT 1 FROM intake_policies newer WHERE (newer.tenant_id,newer.partner_id)=(t,p) AND newer.state IN ('active','retired','revoked') AND newer.version>i.version))
 OR (i.state='output_active' AND i.revision=1 AND EXISTS(SELECT 1 FROM processing_output_policies b WHERE (b.tenant_id,b.partner_id,b.policy_id,b.policy_version,b.producer_id)=(t,p,i.policy_id,i.version,a) AND b.binding->>'policy_hash'=i.definition_hash AND freightctl_processing_output_producer_current(t,p,b.binding)))) )),false)
$$;
REVOKE ALL ON FUNCTION freightctl_processing_schedule_current(uuid,uuid,uuid,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION freightctl_processing_schedule_current(uuid,uuid,uuid,jsonb) TO freightctl_runtime;

CREATE OR REPLACE FUNCTION freightctl_schedule_effects_current_default(t uuid,p uuid,a uuid,d jsonb) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT EXISTS(SELECT 1 FROM workflow_revisions w WHERE (w.tenant_id,w.partner_id,w.actor_id,w.workflow_id,w.version,w.definition_hash,w.state,w.approval_authority)=(t,p,a,(d->'workflow'->>'id')::uuid,(d->'workflow'->>'version')::integer,d->'workflow'->>'hash','approved',(d->>'authority_revision')::bigint)
 AND jsonb_array_length(d->'effects')=jsonb_array_length(w.definition->'steps') AND NOT EXISTS(
 SELECT 1 FROM jsonb_array_elements(w.definition->'steps') WITH ORDINALITY step(value,ordinal)
 LEFT JOIN connection_revisions c ON (c.tenant_id,c.partner_id,c.actor_id,c.connection_id,c.version)=(t,p,a,(step.value->'connection'->>'id')::uuid,(step.value->'connection'->>'version')::integer)
 LEFT JOIN pgp_keys k ON (k.tenant_id,k.partner_id,k.key_id,k.version)=(t,p,(step.value->'encryption'->'key'->>'id')::uuid,(step.value->'encryption'->'key'->>'version')::integer)
 WHERE c.connection_id IS NULL OR c.state<>'active' OR c.definition_hash IS DISTINCT FROM step.value->'connection'->>'hash'
 OR CASE step.value->>'kind' WHEN 'sftp.deliver' THEN c.definition->>'schema_version'='1' AND NOT c.definition ? 'ftps' WHEN 'ftps.deliver' THEN c.definition->>'schema_version'='2' AND c.definition ? 'ftps' ELSE false END IS NOT TRUE
 OR d->'effects'->(step.ordinal::integer-1) IS DISTINCT FROM jsonb_strip_nulls(jsonb_build_object('step_id',step.value->>'id','connection',step.value->'connection',
 'address',freightctl_collection_connection_view(c)->>'address','directory',c.definition->>'directory','final_name_pattern','<delivery UUID>-'||(step.value->>'filename'),'host_fingerprint',freightctl_collection_connection_view(c)->>'host_fingerprint',
 'encryption',step.value->'encryption','recipient_fingerprint',CASE WHEN step.value ? 'encryption' THEN k.definition->>'fingerprint' ELSE NULL END,'encryption_fingerprint',CASE WHEN step.value ? 'encryption' THEN k.definition->'recipient'->>'encryption_fingerprint' ELSE NULL END,
 'protocol',CASE WHEN step.value->>'kind'='ftps.deliver' THEN 'ftps' ELSE NULL END,'user',CASE WHEN step.value->>'kind'='ftps.deliver' THEN c.definition->'ftps'->'destination'->>'user' ELSE NULL END,'ftps',CASE WHEN step.value->>'kind'='ftps.deliver' THEN freightctl_collection_connection_view(c)->'ftps' ELSE NULL END))))
$$;

CREATE OR REPLACE FUNCTION freightctl_schedule_effects_current(t uuid,p uuid,a uuid,d jsonb) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT CASE WHEN d->>'schema_version'='2' THEN coalesce((freightctl_processing_schedule_current(t,p,a,d)),false)
 ELSE coalesce(d->>'schema_version'='1' AND NOT (d ? 'processing') AND NOT EXISTS(SELECT 1 FROM workflow_revisions w WHERE (w.tenant_id,w.partner_id,w.actor_id,w.workflow_id,w.version)=(t,p,a,(d->'workflow'->>'id')::uuid,(d->'workflow'->>'version')::integer) AND w.definition->>'schema_version'='3') AND freightctl_schedule_effects_current_default(t,p,a,d),false) END
$$;
REVOKE ALL ON FUNCTION freightctl_schedule_effects_current_default(uuid,uuid,uuid,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION freightctl_schedule_effects_current_default(uuid,uuid,uuid,jsonb) TO freightctl_runtime;

CREATE OR REPLACE FUNCTION freightctl_schedule_execution_owner_default(t uuid,p uuid,a uuid,d jsonb) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT freightctl_schedule_owner(t,p,a,ARRAY['workflow_execute','list','read']) AND
 CASE WHEN d ? 'collection' THEN freightctl_schedule_owner(t,p,a,ARRAY['write']) AND (jsonb_array_length(d->'effects')=0 OR freightctl_schedule_owner(t,p,a,ARRAY['deliver'])) ELSE freightctl_schedule_owner(t,p,a,ARRAY['deliver']) END
$$;

CREATE OR REPLACE FUNCTION freightctl_schedule_execution_owner(t uuid,p uuid,a uuid,d jsonb) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT CASE WHEN d->>'schema_version'='2' THEN coalesce((freightctl_schedule_owner(t,p,a,ARRAY['workflow_execute','list','read','write','check_run']) AND freightctl_processing_schedule_current(t,p,a,d)),false)
 ELSE coalesce(d->>'schema_version'='1' AND NOT (d ? 'processing') AND freightctl_schedule_execution_owner_default(t,p,a,d),false) END
$$;
REVOKE ALL ON FUNCTION freightctl_schedule_execution_owner_default(uuid,uuid,uuid,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION freightctl_schedule_execution_owner_default(uuid,uuid,uuid,jsonb) TO freightctl_runtime;

CREATE OR REPLACE FUNCTION freightctl_schedule_collection_config_default(t uuid,p uuid,a uuid,d jsonb) RETURNS boolean LANGUAGE sql STABLE AS $$
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
 AND d->'source'->>'kind'=d->'collection'->'source'->>'kind' AND d->'source'->>'kind' IN ('sftp.collect','ftps.collect') AND d->'source'->>'recursive'='false' AND d->'source'->>'filename_regex'=''
 AND d->'source'->>'directory'=d->'collection'->'source'->>'target_directory' AND d->'source'->>'filename_pattern'=d->'collection'->'source'->>'manifest'
 AND d->>'max_files_per_occurrence'=d->'collection'->'source'->>'max_files'
 AND EXISTS(SELECT 1 FROM workflow_revisions w JOIN connection_revisions c ON (c.tenant_id,c.partner_id,c.actor_id,c.connection_id,c.version,c.definition_hash,c.state)=(t,p,a,(d->'collection'->'source'->'connection'->>'id')::uuid,(d->'collection'->'source'->'connection'->>'version')::integer,d->'collection'->'source'->'connection'->>'hash','active')
 WHERE (w.tenant_id,w.partner_id,w.actor_id,w.workflow_id,w.version,w.definition_hash,w.state,w.approval_authority)=(t,p,a,(d->'workflow'->>'id')::uuid,(d->'workflow'->>'version')::integer,d->'workflow'->>'hash','approved',(d->>'authority_revision')::bigint)
 AND freightctl_collection_protocol_matches(d->'collection'->'source',c) AND w.definition->'source'=d->'collection'->'source' AND w.definition->'source'->>'completion_contract'='immutable-files-sha256-scheduled-manifest-v1'
 AND freightctl_collection_manifest_pattern(w.definition->'source'->>'completion_contract',w.definition->'source'->>'manifest')
 AND freightctl_collection_target_writable(t,p,a,w.definition->'source'->>'target_directory')
 AND d->'collection'->'source_connection'=freightctl_collection_connection_view(c)) END
$$;

CREATE OR REPLACE FUNCTION freightctl_schedule_collection_config(t uuid,p uuid,a uuid,d jsonb) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT CASE WHEN d->>'schema_version'='2' THEN coalesce((freightctl_processing_schedule_current(t,p,a,d) AND ARRAY(SELECT jsonb_object_keys(d->'source') ORDER BY 1)=ARRAY['directory','filename_pattern','filename_regex','kind','recursive']::text[]),false)
 ELSE coalesce(d->>'schema_version'='1' AND NOT (d ? 'processing') AND freightctl_schedule_collection_config_default(t,p,a,d),false) END
$$;
REVOKE ALL ON FUNCTION freightctl_schedule_collection_config_default(uuid,uuid,uuid,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION freightctl_schedule_collection_config_default(uuid,uuid,uuid,jsonb) TO freightctl_runtime;

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
  IF ARRAY(SELECT key FROM jsonb_object_keys(d) key WHERE key NOT IN ('collection','processing') ORDER BY 1) IS DISTINCT FROM ARRAY['authority_revision','calendar','effects','execution_deadline_seconds','late_start_grace_seconds','max_active_runs','max_catch_up','max_files_per_occurrence','missed_run_policy','name','namespace_root','schema_version','source','storage_id','workflow']::text[] OR (d->>'schema_version' NOT IN ('1','2') OR ((d->>'schema_version'='2') IS DISTINCT FROM (d ? 'processing'))) OR d->>'authority_revision'<>authority::text OR d->>'namespace_root'<>'/' OR freightctl_schedule_effects_current(NEW.tenant_id,NEW.partner_id,NEW.actor_id,d) IS NOT TRUE OR d->>'missed_run_policy' NOT IN ('skip','latest','all') OR (d->>'max_catch_up')::integer NOT BETWEEN 1 AND 100 OR (d->>'max_active_runs')::integer NOT BETWEEN 1 AND 64 OR (d->>'max_files_per_occurrence')::integer NOT BETWEEN 1 AND 64 OR (d->>'execution_deadline_seconds')::integer NOT BETWEEN 1 AND 604800 OR (d->>'late_start_grace_seconds')::integer NOT BETWEEN 1 AND 3600 OR (d->>'late_start_grace_seconds')::integer>(d->>'execution_deadline_seconds')::integer OR d->'calendar'->>'gap_policy'<>'skip' OR d->'calendar'->>'fold_policy' NOT IN ('first','second','both') OR jsonb_array_length(d->'calendar'->'offset_rules') NOT BETWEEN 1 AND 64 OR jsonb_array_length(d->'calendar'->'local_times') NOT BETWEEN 1 AND 96 OR jsonb_array_length(d->'calendar'->'holidays')>512 OR freightctl_schedule_collection_config(NEW.tenant_id,NEW.partner_id,NEW.actor_id,d) IS NOT TRUE OR (NOT (d ? 'collection') AND (d->'source'->>'filename_pattern' !~ '^[A-Za-z0-9._*?-]{1,128}$' OR d->'source'->>'filename_regex' IS DISTINCT FROM '^'||replace(replace(replace(d->'source'->>'filename_pattern','.','[.]'),'*','.*'),'?','.')||'$')) THEN RAISE EXCEPTION 'invalid typed schedule definition' USING ERRCODE='23514';END IF;
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

CREATE OR REPLACE FUNCTION freightctl_workflow_schedule_input_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE e jsonb;s workflow_schedules%ROWTYPE;o workflow_schedule_occurrences%ROWTYPE;n integer;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'schedule input claims cannot be erased' USING ERRCODE='23514';END IF;
 IF NOT pg_try_advisory_xact_lock(hashtextextended(NEW.tenant_id::text||':'||NEW.partner_id::text||':workflow-schedules',0)) THEN RAISE EXCEPTION 'schedule admission guard busy' USING ERRCODE='40001';END IF;
 SELECT * INTO s FROM workflow_schedules WHERE (tenant_id,partner_id,actor_id,schedule_id,version)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.schedule_id,NEW.schedule_version);
 SELECT * INTO o FROM workflow_schedule_occurrences WHERE (tenant_id,partner_id,occurrence_id,schedule_id,schedule_version,actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.occurrence_id,NEW.schedule_id,NEW.schedule_version,NEW.actor_id);
 SELECT payload INTO e FROM events WHERE (tenant_id,partner_id,actor_id,event_id,resource_id,kind)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.event_id,NEW.run_id,'WorkflowScheduleInput');
 IF e IS NULL OR e->>'schedule_id' IS DISTINCT FROM NEW.schedule_id::text OR e->>'schedule_version' IS DISTINCT FROM NEW.schedule_version::text OR e->>'occurrence_id' IS DISTINCT FROM NEW.occurrence_id::text OR e->>'file_id' IS DISTINCT FROM NEW.file_id::text OR e->>'run_id' IS DISTINCT FROM NEW.run_id::text OR s.state<>'active' OR o.kind<>'queued' OR o.deadline_at<=clock_timestamp() OR NOT freightctl_schedule_execution_owner(NEW.tenant_id,NEW.partner_id,NEW.actor_id,s.definition) THEN RAISE EXCEPTION 'input requires its due approved schedule and exact event' USING ERRCODE='23514';END IF;
 IF NOT EXISTS(SELECT 1 FROM workflow_runs r JOIN files f USING(tenant_id,partner_id,file_id) JOIN events accepted ON (accepted.tenant_id,accepted.partner_id,accepted.event_id)=(f.tenant_id,f.partner_id,f.accepted_event_id) WHERE (r.tenant_id,r.partner_id,r.actor_id,r.run_id,r.file_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.run_id,NEW.file_id) AND r.workflow_id=(s.definition->'workflow'->>'id')::uuid AND r.workflow_version=(s.definition->'workflow'->>'version')::integer AND r.workflow_hash=s.definition->'workflow'->>'hash' AND r.authority_revision=s.approval_authority AND r.storage_id=(s.definition->>'storage_id')::uuid AND accepted.happened_at<=o.due_at AND (s.definition->>'schema_version'<>'2' OR (accepted.actor_id=NEW.actor_id AND freightctl_controlled_policy_hash(f.policy)=s.definition->'processing'->'task'->'definition'->>'source_policy_hash' AND EXISTS(SELECT 1 FROM workflow_processing b JOIN record_projections rp USING(tenant_id,partner_id,actor_id,projection_id) WHERE (b.tenant_id,b.partner_id,b.actor_id,b.run_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.run_id) AND rp.source_file_id=NEW.file_id AND rp.definition_hash=b.definition_hash AND rp.definition->'workflow'->>'run_id'=NEW.run_id::text AND rp.definition->'plan'->'projection'=s.definition->'processing'->'task'->'definition'))) AND freightctl_file_available(r.tenant_id,r.partner_id,r.file_id) AND EXISTS(SELECT 1 FROM namespace_entries n WHERE (n.tenant_id,n.partner_id,n.file_id)=(r.tenant_id,r.partner_id,r.file_id) AND n.kind='file' AND NOT n.deleted AND (EXISTS(SELECT 1 FROM credentials owner_credential WHERE (owner_credential.tenant_id,owner_credential.partner_id,owner_credential.actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id) AND 'admin'=ANY(owner_credential.permissions)) OR (((n.owner_actor_id=NEW.actor_id AND (n.mode & 256)=256) OR (n.owner_actor_id<>NEW.actor_id AND (n.mode & 32)=32)) AND NOT EXISTS(SELECT 1 FROM namespace_entries ancestor WHERE NOT ancestor.deleted AND ancestor.kind='dir' AND (ancestor.path='/' OR starts_with(n.path,ancestor.path||'/')) AND ((ancestor.owner_actor_id=NEW.actor_id AND (ancestor.mode & 320)<>320) OR (ancestor.owner_actor_id<>NEW.actor_id AND (ancestor.mode & 40)<>40))))) AND EXISTS(SELECT 1 FROM events publication WHERE (publication.tenant_id,publication.partner_id,publication.event_id)=(n.tenant_id,n.partner_id,n.changed_event_id) AND publication.happened_at<=o.due_at) AND n.path !~ '(^|/)[.]freightctl-' AND ((s.definition->'source'->>'recursive')::boolean AND starts_with(n.path,rtrim(s.definition->'source'->>'directory','/')||'/') OR n.parent_path=s.definition->'source'->>'directory') AND regexp_replace(n.path,'^.*/','') ~ (s.definition->'source'->>'filename_regex'))) THEN RAISE EXCEPTION 'input must be complete authorized accepted revision under exact source policy' USING ERRCODE='23514';END IF;
 SELECT count(*) INTO n FROM workflow_schedule_inputs i JOIN workflow_schedule_occurrences prior_occurrence USING(tenant_id,partner_id,occurrence_id) JOIN workflow_runs r USING(tenant_id,partner_id,run_id) WHERE (i.tenant_id,i.partner_id,i.actor_id,i.schedule_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.schedule_id) AND i.schedule_version=NEW.schedule_version AND prior_occurrence.deadline_at>clock_timestamp() AND r.state NOT IN ('succeeded','cancelled');
 IF n>=(s.definition->>'max_active_runs')::integer THEN RAISE EXCEPTION 'schedule concurrency budget exhausted' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION freightctl_scheduled_run_status_default(t uuid,p uuid,a uuid,id uuid) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT NOT EXISTS(SELECT 1 FROM workflow_schedule_inputs WHERE (tenant_id,partner_id,actor_id,run_id)=(t,p,a,id)) OR EXISTS(SELECT 1 FROM workflow_schedule_inputs i JOIN workflow_schedules s ON (s.tenant_id,s.partner_id,s.actor_id,s.schedule_id,s.version)=(i.tenant_id,i.partner_id,i.actor_id,i.schedule_id,i.schedule_version) JOIN workflow_schedule_occurrences o ON (o.tenant_id,o.partner_id,o.occurrence_id)=(i.tenant_id,i.partner_id,i.occurrence_id) JOIN credentials c ON (c.tenant_id,c.partner_id,c.actor_id)=(i.tenant_id,i.partner_id,i.actor_id) WHERE (i.tenant_id,i.partner_id,i.actor_id,i.run_id)=(t,p,a,id) AND s.state='active' AND c.authority_revision=s.approval_authority AND s.approval_authority=(s.definition->>'authority_revision')::bigint AND c.namespace_root='/' AND c.permissions @> ARRAY['workflow_execute','list','read','deliver']::text[] AND c.revoked_at IS NULL AND (c.expires_at IS NULL OR c.expires_at>clock_timestamp()) AND o.deadline_at>clock_timestamp() AND o.kind='queued' AND freightctl_schedule_effects_current(t,p,a,s.definition))
$$;

CREATE OR REPLACE FUNCTION freightctl_scheduled_run_status(t uuid,p uuid,a uuid,id uuid) RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE d jsonb;approval bigint;deadline timestamptz;kind text;
BEGIN
 SELECT s.definition,s.approval_authority,o.deadline_at,o.kind INTO d,approval,deadline,kind FROM workflow_schedule_inputs i
 JOIN workflow_schedules s ON (s.tenant_id,s.partner_id,s.actor_id,s.schedule_id,s.version)=(i.tenant_id,i.partner_id,i.actor_id,i.schedule_id,i.schedule_version)
 JOIN workflow_schedule_occurrences o ON (o.tenant_id,o.partner_id,o.actor_id,o.occurrence_id,o.schedule_id,o.schedule_version)=(i.tenant_id,i.partner_id,i.actor_id,i.occurrence_id,i.schedule_id,i.schedule_version)
 WHERE (i.tenant_id,i.partner_id,i.actor_id,i.run_id)=(t,p,a,id);
 IF d IS NULL THEN RETURN NOT EXISTS(SELECT 1 FROM workflow_schedule_inputs WHERE (tenant_id,partner_id,actor_id,run_id)=(t,p,a,id));END IF;
 IF d->>'schema_version'<>'2' THEN RETURN freightctl_scheduled_run_status_default(t,p,a,id);END IF;
 RETURN coalesce(deadline>clock_timestamp() AND kind='queued' AND approval=(d->>'authority_revision')::bigint
 AND freightctl_schedule_execution_owner(t,p,a,d) AND EXISTS(SELECT 1 FROM workflow_schedule_inputs i JOIN workflow_schedules s ON (s.tenant_id,s.partner_id,s.actor_id,s.schedule_id,s.version)=(i.tenant_id,i.partner_id,i.actor_id,i.schedule_id,i.schedule_version)
 WHERE (i.tenant_id,i.partner_id,i.actor_id,i.run_id,s.state)=(t,p,a,id,'active')),false);
END $$;
REVOKE ALL ON FUNCTION freightctl_scheduled_run_status_default(uuid,uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION freightctl_scheduled_run_status_default(uuid,uuid,uuid,uuid) TO freightctl_runtime;

CREATE FUNCTION freightctl_processing_schedule_effect_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.definition->>'schema_version' IN ('2','3','4') AND NEW.definition ? 'workflow' AND NEW.state NOT IN ('failed','cancelled')
 AND freightctl_scheduled_run_current(NEW.tenant_id,NEW.partner_id,NEW.actor_id,(NEW.definition->'workflow'->>'run_id')::uuid) IS DISTINCT FROM true
 THEN RAISE EXCEPTION 'processing effect requires current approved calendar and unexpired occurrence' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER record_projection_a_schedule_guard BEFORE INSERT OR UPDATE ON record_projections FOR EACH ROW EXECUTE FUNCTION freightctl_processing_schedule_effect_guard();
REVOKE ALL ON FUNCTION freightctl_processing_schedule_effect_guard() FROM PUBLIC;
