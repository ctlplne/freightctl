-- Extend read-only local sources to the ordinary approved calendar/arrival
-- contract. Retain exact UTC manifest binding,current RLS/authority,original
-- processing dispatch,leases/fencing,intents,events and byte/capture guards.

CREATE OR REPLACE FUNCTION freightctl_collection_protocol_matches(source jsonb,c connection_revisions) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
 SELECT coalesce(CASE WHEN jsonb_typeof(source->'connection')='object'
 THEN ARRAY(SELECT jsonb_object_keys(source->'connection') ORDER BY 1)=ARRAY['hash','id','version']::text[] ELSE false END
 AND CASE WHEN c.definition->>'schema_version'='1' AND NOT c.definition ? 'ftps' AND NOT c.definition ? 'local' THEN source->>'kind'='sftp.collect'
 WHEN c.definition->>'schema_version'='2' AND c.definition ? 'ftps' AND NOT c.definition ? 'local' THEN source->>'kind'='ftps.collect'
 WHEN freightctl_local_collection_connection(c.definition) THEN source->>'kind'='local.collect' AND source->>'completion_contract' IN ('immutable-files-sha256-manifest-v1','immutable-files-sha256-scheduled-manifest-v1')
 ELSE false END,false)
$$;

CREATE OR REPLACE FUNCTION freightctl_scheduled_source_shape(source jsonb) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
 SELECT coalesce(ARRAY(SELECT jsonb_object_keys(source) ORDER BY 1)=ARRAY['completion_contract','connection','kind','manifest','max_file_bytes','max_files','max_total_bytes','target_directory']::text[]
 AND ARRAY(SELECT jsonb_object_keys(source->'connection') ORDER BY 1)=ARRAY['hash','id','version']::text[]
 AND source->>'kind' IN ('sftp.collect','ftps.collect','local.collect') AND source->>'completion_contract'='immutable-files-sha256-scheduled-manifest-v1'
 AND freightctl_collection_manifest_pattern(source->>'completion_contract',source->>'manifest')
 AND jsonb_typeof(source->'max_files')='number' AND (source->>'max_files')::integer BETWEEN 1 AND 64
 AND jsonb_typeof(source->'max_file_bytes')='number' AND (source->>'max_file_bytes')::bigint BETWEEN 1 AND 1073741824
 AND jsonb_typeof(source->'max_total_bytes')='number' AND (source->>'max_total_bytes')::bigint BETWEEN 1 AND (source->>'max_files')::bigint*(source->>'max_file_bytes')::bigint,false)
$$;

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
 AND d->'source'->>'kind'=d->'collection'->'source'->>'kind' AND d->'source'->>'kind' IN ('sftp.collect','ftps.collect','local.collect') AND d->'source'->>'recursive'='false' AND d->'source'->>'filename_regex'=''
 AND d->'source'->>'directory'=d->'collection'->'source'->>'target_directory' AND d->'source'->>'filename_pattern'=d->'collection'->'source'->>'manifest'
 AND d->>'max_files_per_occurrence'=d->'collection'->'source'->>'max_files'
 AND EXISTS(SELECT 1 FROM workflow_revisions w JOIN connection_revisions c ON (c.tenant_id,c.partner_id,c.actor_id,c.connection_id,c.version,c.definition_hash,c.state)=(t,p,a,(d->'collection'->'source'->'connection'->>'id')::uuid,(d->'collection'->'source'->'connection'->>'version')::integer,d->'collection'->'source'->'connection'->>'hash','active')
 WHERE (w.tenant_id,w.partner_id,w.actor_id,w.workflow_id,w.version,w.definition_hash,w.state,w.approval_authority)=(t,p,a,(d->'workflow'->>'id')::uuid,(d->'workflow'->>'version')::integer,d->'workflow'->>'hash','approved',(d->>'authority_revision')::bigint)
 AND freightctl_collection_protocol_matches(d->'collection'->'source',c) AND w.definition->'source'=d->'collection'->'source' AND w.definition->'source'->>'completion_contract'='immutable-files-sha256-scheduled-manifest-v1'
 AND freightctl_collection_manifest_pattern(w.definition->'source'->>'completion_contract',w.definition->'source'->>'manifest')
 AND freightctl_collection_target_writable(t,p,a,w.definition->'source'->>'target_directory')
 AND d->'collection'->'source_connection'=freightctl_collection_connection_view(c)) END
$$;

-- Retain the original SSH/FTPS guard;admit only validated local source schema3.
CREATE OR REPLACE FUNCTION freightctl_ftps_connection_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE d jsonb:=NEW.definition;f jsonb;dest jsonb;c jsonb;
BEGIN
 -- Only the exact read-only local shape may enter the existing connection registry.
 IF freightctl_local_collection_connection(d) THEN RETURN NEW;END IF;
 IF d->>'schema_version'='1' AND NOT d ? 'ftps' THEN RETURN NEW;END IF;
 IF d->>'schema_version' IS DISTINCT FROM '2' THEN RAISE EXCEPTION 'unsupported delivery protocol definition' USING ERRCODE='23514';END IF;
 f:=d->'ftps';dest:=f->'destination';c:=f->'receiver_contract';
 IF ARRAY(SELECT jsonb_object_keys(d) ORDER BY 1) IS DISTINCT FROM ARRAY['destination','directory','ftps','schema_version']::text[]
 OR d->'destination' IS DISTINCT FROM '{"address":"","user":"","host":{"Wire":null,"Fingerprint":""},"key_reference":"","key_fingerprint":""}'::jsonb
 OR ARRAY(SELECT jsonb_object_keys(f) ORDER BY 1) IS DISTINCT FROM ARRAY['destination','receiver_contract','staging_directory']::text[]
 OR ARRAY(SELECT jsonb_object_keys(dest) ORDER BY 1) IS DISTINCT FROM ARRAY['address','ca_reference','ca_sha256','mode','password_reference','password_sha256','server_name','user']::text[]
 OR coalesce(dest->>'mode','') NOT IN ('explicit','implicit')
 OR coalesce(dest->>'ca_sha256','') !~ '^[0-9a-f]{64}$' OR coalesce(dest->>'password_sha256','') !~ '^[0-9a-f]{64}$'
 OR coalesce(c->>'document_sha256','') !~ '^[0-9a-f]{64}$'
 OR c IS DISTINCT FROM jsonb_build_object('schema_version',1,'document_sha256',c->>'document_sha256','staging_visibility','receiver-private','rename','may-replace','duplicates','receiver-deduplicates-delivery-id','receipt','exact-readback')
 OR coalesce(f->>'staging_directory','')='' OR coalesce(d->>'directory','')='' OR f->>'staging_directory'=d->>'directory'
 THEN RAISE EXCEPTION 'invalid distinct FTPS receiver contract' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
