-- Local collection reuses existing actor/tenant/partner RLS,immutable events,
-- batch/custody/idempotency,approval and lease/fencing guards. No table or grant
-- is removed. Local connections are read-only sources,never delivery endpoints.
CREATE FUNCTION freightctl_local_collection_connection(d jsonb) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
 SELECT CASE WHEN jsonb_typeof(d)='object' AND jsonb_typeof(d->'local')='object' THEN coalesce(
 ARRAY(SELECT jsonb_object_keys(d) ORDER BY 1)=ARRAY['destination','directory','local','schema_version']::text[]
 AND jsonb_typeof(d->'schema_version')='number' AND d->>'schema_version'='3' AND d->>'directory'='/'
 AND d->'destination'='{"address":"","user":"","host":{"Wire":null,"Fingerprint":""},"key_reference":"","key_fingerprint":""}'::jsonb
 AND ARRAY(SELECT jsonb_object_keys(d->'local') ORDER BY 1)=ARRAY['configuration_sha256','root_fingerprint','root_reference','schema_version']::text[]
 AND jsonb_typeof(d->'local'->'schema_version')='number' AND d->'local'->>'schema_version'='1'
 AND jsonb_typeof(d->'local'->'root_reference')='string'
 AND octet_length(d->'local'->>'root_reference') BETWEEN 1 AND 4096
 AND (left(d->'local'->>'root_reference',1)='/' OR
  (substring(d->'local'->>'root_reference',1,1) ~ '^[A-Za-z]$'
   AND substring(d->'local'->>'root_reference',2,1)=':'
   AND substring(d->'local'->>'root_reference',3,1) IN ('/',chr(92))))
 AND position(chr(10) in d->'local'->>'root_reference')=0
 AND position(chr(13) in d->'local'->>'root_reference')=0
 AND jsonb_typeof(d->'local'->'configuration_sha256')='string'
 AND d->'local'->>'configuration_sha256' ~ '^[0-9a-f]{64}$'
 AND jsonb_typeof(d->'local'->'root_fingerprint')='string'
 AND d->'local'->>'root_fingerprint' ~ '^[0-9a-f]{64}$',false)
 ELSE false END
$$;
ALTER TABLE connection_revisions ADD CONSTRAINT local_collection_connection_shape
 CHECK(CASE WHEN definition ? 'local' OR definition->>'schema_version'='3'
 THEN freightctl_local_collection_connection(definition) ELSE true END);

CREATE OR REPLACE FUNCTION freightctl_collection_protocol_matches(source jsonb,c connection_revisions) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
 SELECT coalesce(CASE WHEN jsonb_typeof(source->'connection')='object'
 THEN ARRAY(SELECT jsonb_object_keys(source->'connection') ORDER BY 1)=ARRAY['hash','id','version']::text[] ELSE false END
 AND CASE WHEN c.definition->>'schema_version'='1' AND NOT c.definition ? 'ftps' AND NOT c.definition ? 'local' THEN source->>'kind'='sftp.collect'
 WHEN c.definition->>'schema_version'='2' AND c.definition ? 'ftps' AND NOT c.definition ? 'local' THEN source->>'kind'='ftps.collect'
 WHEN freightctl_local_collection_connection(c.definition) THEN source->>'kind'='local.collect' AND source->>'completion_contract'='immutable-files-sha256-manifest-v1'
 ELSE false END,false)
$$;

CREATE FUNCTION freightctl_collection_source_identity(c connection_revisions) RETURNS text LANGUAGE sql IMMUTABLE AS $$
 SELECT encode(sha256(convert_to(CASE WHEN freightctl_local_collection_connection(c.definition)
 THEN 'local-root-v1:'||c.connection_id::text||':'||(c.definition->'local'->>'root_fingerprint')
 ELSE c.connection_id::text||':'||(c.definition->>'directory') END,'UTF8')),'hex')
$$;

CREATE OR REPLACE FUNCTION freightctl_collection_connection_view(c connection_revisions) RETURNS jsonb LANGUAGE sql IMMUTABLE AS $$
 SELECT CASE WHEN c.definition->>'schema_version'='1' AND NOT c.definition ? 'ftps' AND NOT c.definition ? 'local' THEN
 jsonb_build_object('id',c.connection_id,'version',c.version,'definition_hash',c.definition_hash,'state',c.state,'revision',c.revision,'address',c.definition->'destination'->>'address','user',c.definition->'destination'->>'user','directory',c.definition->>'directory','host_fingerprint',c.definition->'destination'->'host'->>'Fingerprint','key_fingerprint',c.definition->'destination'->>'key_fingerprint')
 WHEN c.definition->>'schema_version'='2' AND c.definition ? 'ftps' AND NOT c.definition ? 'local' THEN
 jsonb_build_object('id',c.connection_id,'version',c.version,'definition_hash',c.definition_hash,'state',c.state,'revision',c.revision,'address',c.definition->'ftps'->'destination'->>'address','user',c.definition->'ftps'->'destination'->>'user','directory',c.definition->>'directory','host_fingerprint','','key_fingerprint','','protocol','ftps',
 'ftps',jsonb_build_object('mode',c.definition->'ftps'->'destination'->>'mode','server_name',c.definition->'ftps'->'destination'->>'server_name','ca_sha256',c.definition->'ftps'->'destination'->>'ca_sha256','ca_reference_sha256',encode(sha256(convert_to(c.definition->'ftps'->'destination'->>'ca_reference','UTF8')),'hex'),'password_reference_sha256',encode(sha256(convert_to(c.definition->'ftps'->'destination'->>'password_reference','UTF8')),'hex'),'staging_directory',c.definition->'ftps'->>'staging_directory','receiver_contract',c.definition->'ftps'->'receiver_contract'))
 WHEN freightctl_local_collection_connection(c.definition) THEN
 jsonb_build_object('id',c.connection_id,'version',c.version,'definition_hash',c.definition_hash,'state',c.state,'revision',c.revision,'address','','user','','directory','/','host_fingerprint','','key_fingerprint','','protocol','local',
 'local',jsonb_build_object('profile','freightctl-local-collection-source-v1','root_reference_sha256',encode(sha256(convert_to(c.definition->'local'->>'root_reference','UTF8')),'hex'),'configuration_sha256',c.definition->'local'->>'configuration_sha256','root_fingerprint',c.definition->'local'->>'root_fingerprint','read_only',true)) END
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
 AND d->>'source_identity'=freightctl_collection_source_identity(c)
 AND d->'source_connection'=freightctl_collection_connection_view(c))
$$;

REVOKE ALL ON FUNCTION freightctl_local_collection_connection(jsonb),freightctl_collection_source_identity(connection_revisions) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION freightctl_local_collection_connection(jsonb),freightctl_collection_source_identity(connection_revisions) TO freightctl_runtime;
