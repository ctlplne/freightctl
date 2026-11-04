-- Read-only FTPS collection uses the existing immutable producer batch,
-- custody, arrival, lease/fencing and RLS guards. Historical migration bytes,
-- tables, grants and the retained estate are unchanged.
CREATE FUNCTION freightctl_collection_protocol_matches(source jsonb,c connection_revisions) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
 SELECT coalesce(CASE WHEN jsonb_typeof(source->'connection')='object'
 THEN ARRAY(SELECT jsonb_object_keys(source->'connection') ORDER BY 1)=ARRAY['hash','id','version']::text[] ELSE false END
 AND CASE WHEN c.definition->>'schema_version'='1' AND NOT c.definition ? 'ftps' THEN source->>'kind'='sftp.collect'
 WHEN c.definition->>'schema_version'='2' AND c.definition ? 'ftps' THEN source->>'kind'='ftps.collect' ELSE false END,false)
$$;

CREATE FUNCTION freightctl_collection_connection_view(c connection_revisions) RETURNS jsonb LANGUAGE sql IMMUTABLE AS $$
 SELECT CASE WHEN c.definition->>'schema_version'='1' AND NOT c.definition ? 'ftps' THEN
 jsonb_build_object('id',c.connection_id,'version',c.version,'definition_hash',c.definition_hash,'state',c.state,'revision',c.revision,'address',c.definition->'destination'->>'address','user',c.definition->'destination'->>'user','directory',c.definition->>'directory','host_fingerprint',c.definition->'destination'->'host'->>'Fingerprint','key_fingerprint',c.definition->'destination'->>'key_fingerprint')
 WHEN c.definition->>'schema_version'='2' AND c.definition ? 'ftps' THEN
 jsonb_build_object('id',c.connection_id,'version',c.version,'definition_hash',c.definition_hash,'state',c.state,'revision',c.revision,'address',c.definition->'ftps'->'destination'->>'address','user',c.definition->'ftps'->'destination'->>'user','directory',c.definition->>'directory','host_fingerprint','','key_fingerprint','','protocol','ftps',
 'ftps',jsonb_build_object('mode',c.definition->'ftps'->'destination'->>'mode','server_name',c.definition->'ftps'->'destination'->>'server_name','ca_sha256',c.definition->'ftps'->'destination'->>'ca_sha256','ca_reference_sha256',encode(sha256(convert_to(c.definition->'ftps'->'destination'->>'ca_reference','UTF8')),'hex'),'password_reference_sha256',encode(sha256(convert_to(c.definition->'ftps'->'destination'->>'password_reference','UTF8')),'hex'),'staging_directory',c.definition->'ftps'->>'staging_directory','receiver_contract',c.definition->'ftps'->'receiver_contract')) END
$$;


-- Calendar and collection effects bind the same exact protocol metadata as
-- ordinary workflow preview. A protocol change cannot reuse an SSH-only view.
CREATE OR REPLACE FUNCTION freightctl_schedule_effects_current(t uuid,p uuid,a uuid,d jsonb) RETURNS boolean LANGUAGE sql STABLE AS $$
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

CREATE OR REPLACE FUNCTION freightctl_scheduled_source_shape(source jsonb) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
 SELECT coalesce(ARRAY(SELECT jsonb_object_keys(source) ORDER BY 1)=ARRAY['completion_contract','connection','kind','manifest','max_file_bytes','max_files','max_total_bytes','target_directory']::text[]
 AND ARRAY(SELECT jsonb_object_keys(source->'connection') ORDER BY 1)=ARRAY['hash','id','version']::text[]
 AND source->>'kind' IN ('sftp.collect','ftps.collect') AND source->>'completion_contract'='immutable-files-sha256-scheduled-manifest-v1'
 AND freightctl_collection_manifest_pattern(source->>'completion_contract',source->>'manifest')
 AND jsonb_typeof(source->'max_files')='number' AND (source->>'max_files')::integer BETWEEN 1 AND 64
 AND jsonb_typeof(source->'max_file_bytes')='number' AND (source->>'max_file_bytes')::bigint BETWEEN 1 AND 1073741824
 AND jsonb_typeof(source->'max_total_bytes')='number' AND (source->>'max_total_bytes')::bigint BETWEEN 1 AND (source->>'max_files')::bigint*(source->>'max_file_bytes')::bigint,false)
$$;

CREATE OR REPLACE FUNCTION freightctl_schedule_collection_config(t uuid,p uuid,a uuid,d jsonb) RETURNS boolean LANGUAGE sql STABLE AS $$
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
 AND w.definition->'source'=d->'source' AND freightctl_collection_protocol_matches(d->'source',c) AND freightctl_collection_manifest_pattern(d->'source'->>'completion_contract',d->'source'->>'manifest')
 AND ARRAY(SELECT jsonb_object_keys(d->'source') ORDER BY 1)=ARRAY['completion_contract','connection','kind','manifest','max_file_bytes','max_files','max_total_bytes','target_directory']::text[]

 AND (d->'source'->>'max_files')::integer BETWEEN 1 AND 64 AND (d->'source'->>'max_file_bytes')::bigint BETWEEN 1 AND 1073741824
 AND (d->'source'->>'max_total_bytes')::bigint BETWEEN 1 AND (d->'source'->>'max_files')::bigint*(d->'source'->>'max_file_bytes')::bigint
 AND d->>'source_identity'=encode(sha256(convert_to(c.connection_id::text||':'||(c.definition->>'directory'),'UTF8')),'hex')
 AND d->'source_connection'=freightctl_collection_connection_view(c))
$$;
