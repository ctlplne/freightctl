-- Explicit Basic credentials add a distinct read-only DAV source profile.
-- Preserve migration64 bearer semantics;no existing row,grant,table or RLS
-- scope is removed. Existing delivery/calendar/custody/event/lease guards stay.
CREATE FUNCTION freightctl_bearer_dav_collection_connection(d jsonb) RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE v jsonb; a text; h text; p text; ip inet; n text;
BEGIN
 IF jsonb_typeof(d) IS DISTINCT FROM 'object' OR jsonb_typeof(d->'dav') IS DISTINCT FROM 'object' THEN RETURN false;END IF;
 IF ARRAY(SELECT jsonb_object_keys(d) ORDER BY 1)<>ARRAY['dav','destination','directory','schema_version']::text[]
 OR jsonb_typeof(d->'schema_version') IS DISTINCT FROM 'number' OR d->>'schema_version'<>'4'
 OR d->'destination'<>'{"address":"","user":"","host":{"Wire":null,"Fingerprint":""},"key_reference":"","key_fingerprint":""}'::jsonb
 OR jsonb_typeof(d->'directory') IS DISTINCT FROM 'string' OR octet_length(d->>'directory') NOT BETWEEN 1 AND 1024
 OR left(d->>'directory',1)<>'/' OR (d->>'directory'<>'/' AND right(d->>'directory',1)='/')
 OR d->>'directory' ~ '(^|/)[.]{1,2}(/|$)|//|[[:cntrl:]:\\]'
 OR ARRAY(SELECT jsonb_object_keys(d->'dav') ORDER BY 1)<>ARRAY['destination','schema_version']::text[]
 OR jsonb_typeof(d->'dav'->'schema_version') IS DISTINCT FROM 'number' OR d->'dav'->>'schema_version'<>'1'
 OR jsonb_typeof(d->'dav'->'destination') IS DISTINCT FROM 'object' THEN RETURN false;END IF;
 v:=d->'dav'->'destination';
 IF ARRAY(SELECT jsonb_object_keys(v) ORDER BY 1)<>ARRAY['address','ca_reference','ca_sha256','server_name','token_reference','token_sha256']::text[]
 OR EXISTS(SELECT 1 FROM jsonb_each(v) x WHERE jsonb_typeof(x.value)<>'string')
 OR v->>'ca_sha256' !~ '^[0-9a-f]{64}$' OR v->>'token_sha256' !~ '^[0-9a-f]{64}$' THEN RETURN false;END IF;
 FOREACH n IN ARRAY ARRAY['ca_reference','token_reference'] LOOP
  IF octet_length(v->>n) NOT BETWEEN 1 AND 1024 OR v->>n ~ '[[:cntrl:]]'
  OR NOT(left(v->>n,1)='/' OR (substring(v->>n,1,1) ~ '^[A-Za-z]$' AND substring(v->>n,2,1)=':' AND substring(v->>n,3,1) IN ('/',chr(92)))) THEN RETURN false;END IF;
 END LOOP;
 a:=v->>'address';
 IF left(a,1)='[' THEN h:=substring(a FROM '^\[([^]]+)\]:[0-9]+$');p:=substring(a FROM '\]:([0-9]+)$');
 ELSE h:=substring(a FROM '^([^:]+):[0-9]+$');p:=substring(a FROM ':([0-9]+)$');END IF;
 IF h IS NULL OR p IS NULL OR p::integer NOT BETWEEN 1 AND 65535 OR (p::integer)::text<>p THEN RETURN false;END IF;
 ip:=h::inet;
 IF host(ip)<>h OR h IN ('0.0.0.0','::') OR (family(ip)=4 AND ip<<='224.0.0.0/4'::inet) OR (family(ip)=6 AND ip<<='ff00::/8'::inet) THEN RETURN false;END IF;
 n:=v->>'server_name';
 IF octet_length(n) NOT BETWEEN 1 AND 253 THEN RETURN false;END IF;
 IF position(':' in n)>0 THEN
  IF host(n::inet)<>n THEN RETURN false;END IF;
 ELSE
  IF n !~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$' THEN RETURN false;END IF;
 END IF;
 RETURN true;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN RETURN false;
END $$;
REVOKE ALL ON FUNCTION freightctl_bearer_dav_collection_connection(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION freightctl_bearer_dav_collection_connection(jsonb) TO freightctl_runtime;

CREATE OR REPLACE FUNCTION freightctl_dav_collection_connection(d jsonb) RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE v jsonb; candidate jsonb;
BEGIN
 IF d->'dav'->>'schema_version'='1' THEN RETURN freightctl_bearer_dav_collection_connection(d);END IF;
 IF jsonb_typeof(d) IS DISTINCT FROM 'object' OR jsonb_typeof(d->'dav') IS DISTINCT FROM 'object'
 OR jsonb_typeof(d->'dav'->'schema_version') IS DISTINCT FROM 'number' OR d->'dav'->>'schema_version' IS DISTINCT FROM '2'
 OR jsonb_typeof(d->'dav'->'destination') IS DISTINCT FROM 'object' THEN RETURN false;END IF;
 v:=d->'dav'->'destination';
 IF ARRAY(SELECT jsonb_object_keys(v) ORDER BY 1)<>ARRAY['address','authentication','ca_reference','ca_sha256','password_reference','password_sha256','server_name','user']::text[]
 OR EXISTS(SELECT 1 FROM jsonb_each(v) x WHERE jsonb_typeof(x.value)<>'string')
 OR v->>'authentication'<>'basic' OR octet_length(v->>'user') NOT BETWEEN 1 AND 256
 OR v->>'user' ~ '[[:cntrl:]:]' THEN RETURN false;END IF;
 candidate:=jsonb_set(d,'{dav,schema_version}','1'::jsonb);
 candidate:=jsonb_set(candidate,'{dav,destination}',jsonb_build_object('address',v->>'address','server_name',v->>'server_name','ca_reference',v->>'ca_reference','ca_sha256',v->>'ca_sha256','token_reference',v->>'password_reference','token_sha256',v->>'password_sha256'));
 RETURN freightctl_bearer_dav_collection_connection(candidate);
END $$;

CREATE OR REPLACE FUNCTION freightctl_collection_connection_view(c connection_revisions) RETURNS jsonb LANGUAGE sql IMMUTABLE AS $$
 SELECT CASE WHEN c.definition->>'schema_version'='1' AND NOT c.definition ? 'ftps' AND NOT c.definition ? 'local' AND NOT c.definition ? 'dav' THEN
 jsonb_build_object('id',c.connection_id,'version',c.version,'definition_hash',c.definition_hash,'state',c.state,'revision',c.revision,'address',c.definition->'destination'->>'address','user',c.definition->'destination'->>'user','directory',c.definition->>'directory','host_fingerprint',c.definition->'destination'->'host'->>'Fingerprint','key_fingerprint',c.definition->'destination'->>'key_fingerprint')
 WHEN c.definition->>'schema_version'='2' AND c.definition ? 'ftps' AND NOT c.definition ? 'local' AND NOT c.definition ? 'dav' THEN
 jsonb_build_object('id',c.connection_id,'version',c.version,'definition_hash',c.definition_hash,'state',c.state,'revision',c.revision,'address',c.definition->'ftps'->'destination'->>'address','user',c.definition->'ftps'->'destination'->>'user','directory',c.definition->>'directory','host_fingerprint','','key_fingerprint','','protocol','ftps',
 'ftps',jsonb_build_object('mode',c.definition->'ftps'->'destination'->>'mode','server_name',c.definition->'ftps'->'destination'->>'server_name','ca_sha256',c.definition->'ftps'->'destination'->>'ca_sha256','ca_reference_sha256',encode(sha256(convert_to(c.definition->'ftps'->'destination'->>'ca_reference','UTF8')),'hex'),'password_reference_sha256',encode(sha256(convert_to(c.definition->'ftps'->'destination'->>'password_reference','UTF8')),'hex'),'staging_directory',c.definition->'ftps'->>'staging_directory','receiver_contract',c.definition->'ftps'->'receiver_contract'))
 WHEN NOT c.definition ? 'dav' AND freightctl_local_collection_connection(c.definition) THEN
 jsonb_build_object('id',c.connection_id,'version',c.version,'definition_hash',c.definition_hash,'state',c.state,'revision',c.revision,'address','','user','','directory','/','host_fingerprint','','key_fingerprint','','protocol','local',
 'local',jsonb_build_object('profile','freightctl-local-collection-source-v1','root_reference_sha256',encode(sha256(convert_to(c.definition->'local'->>'root_reference','UTF8')),'hex'),'configuration_sha256',c.definition->'local'->>'configuration_sha256','root_fingerprint',c.definition->'local'->>'root_fingerprint','read_only',true))
 WHEN c.definition->'dav'->>'schema_version'='2' AND freightctl_dav_collection_connection(c.definition) THEN
 jsonb_build_object('id',c.connection_id,'version',c.version,'definition_hash',c.definition_hash,'state',c.state,'revision',c.revision,'address',c.definition->'dav'->'destination'->>'address','user',c.definition->'dav'->'destination'->>'user','directory',c.definition->>'directory','host_fingerprint','','key_fingerprint','','protocol','webdav',
 'dav',jsonb_build_object('profile','freightctl-webdav-basic-collection-source-v1','server_name',c.definition->'dav'->'destination'->>'server_name','ca_sha256',c.definition->'dav'->'destination'->>'ca_sha256','ca_reference_sha256',encode(sha256(convert_to(c.definition->'dav'->'destination'->>'ca_reference','UTF8')),'hex'),'read_only',true,'authentication','basic','password_reference_sha256',encode(sha256(convert_to(c.definition->'dav'->'destination'->>'password_reference','UTF8')),'hex')))
 WHEN freightctl_bearer_dav_collection_connection(c.definition) THEN
 jsonb_build_object('id',c.connection_id,'version',c.version,'definition_hash',c.definition_hash,'state',c.state,'revision',c.revision,'address',c.definition->'dav'->'destination'->>'address','user','','directory',c.definition->>'directory','host_fingerprint','','key_fingerprint','','protocol','webdav',
 'dav',jsonb_build_object('profile','freightctl-webdav-collection-source-v1','server_name',c.definition->'dav'->'destination'->>'server_name','ca_sha256',c.definition->'dav'->'destination'->>'ca_sha256','ca_reference_sha256',encode(sha256(convert_to(c.definition->'dav'->'destination'->>'ca_reference','UTF8')),'hex'),'token_reference_sha256',encode(sha256(convert_to(c.definition->'dav'->'destination'->>'token_reference','UTF8')),'hex'),'read_only',true)) END
$$;
