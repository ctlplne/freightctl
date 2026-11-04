-- Recipient encryption uses the existing sealed artifact and key guards.
-- Schema32 already binds policy to the exact selected execution-plan step.
-- Registered FTPS workflows retain exact immutable revisions, source, intents
-- and dispatch consent. No historical migration, role, grant or table changes.
CREATE OR REPLACE FUNCTION freightctl_outbound_dispatch_expected_effect(original delivery_intents,recipient text) RETURNS jsonb LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE d jsonb:=original.definition;dest jsonb;expected jsonb;
BEGIN
 IF d->>'schema_version'='2' THEN
  dest:=d->'ftps'->'destination';
  expected:=jsonb_build_object('protocol','ftps','address',dest->>'address','user',dest->>'user','directory',d->>'directory','filename',d->>'filename','final_path',rtrim(d->>'directory','/')||'/'||original.delivery_id::text||'-'||(d->>'filename'),'host_fingerprint','','key_fingerprint','','key_reference_sha256','','recipient_fingerprint',recipient,
   'ftps',jsonb_build_object('mode',dest->>'mode','server_name',dest->>'server_name','ca_sha256',dest->>'ca_sha256','ca_reference_sha256',encode(sha256(convert_to(dest->>'ca_reference','UTF8')),'hex'),'password_reference_sha256',encode(sha256(convert_to(dest->>'password_reference','UTF8')),'hex'),'staging_path',rtrim(d->'ftps'->>'staging_directory','/')||'/.freightctl-'||original.delivery_id::text||'.partial','receiver_contract',d->'ftps'->'receiver_contract'));
 ELSE
  expected:=jsonb_build_object('protocol','sftp','address',d->'destination'->>'address','user',d->'destination'->>'user','directory',d->>'directory','filename',d->>'filename','final_path',rtrim(d->>'directory','/')||'/'||original.delivery_id::text||'-'||(d->>'filename'),'host_fingerprint',d->'destination'->'host'->>'Fingerprint','key_fingerprint',d->'destination'->>'key_fingerprint','key_reference_sha256',encode(sha256(convert_to(d->'destination'->>'key_reference','UTF8')),'hex'),'recipient_fingerprint',recipient);
 END IF;
 IF d ? 'encryption' THEN expected:=expected||jsonb_build_object('encryption',d->'encryption');END IF;
 IF d ? 'workflow_binding' THEN expected:=expected||jsonb_build_object('workflow_binding',d->'workflow_binding');END IF;
 RETURN expected;
END $$;

CREATE OR REPLACE FUNCTION freightctl_ftps_delivery_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE d jsonb:=NEW.definition;f jsonb;dest jsonb;c jsonb;
BEGIN
 IF d->>'schema_version'='1' AND NOT d ? 'ftps' THEN RETURN NEW;END IF;
 IF d->>'schema_version' IS DISTINCT FROM '2' THEN RAISE EXCEPTION 'unsupported delivery protocol definition' USING ERRCODE='23514';END IF;
 f:=d->'ftps';dest:=f->'destination';c:=f->'receiver_contract';
 IF ARRAY(SELECT jsonb_object_keys(d-'dispatch_approval_policy'-'workflow_binding'-'encryption') ORDER BY 1) IS DISTINCT FROM ARRAY['authority_revision','destination','directory','filename','ftps','namespace_root','schema_version','source','storage_id']::text[]
 OR d->'destination' IS DISTINCT FROM '{"address":"","user":"","host":{"Wire":null,"Fingerprint":""},"key_reference":"","key_fingerprint":""}'::jsonb
 OR ARRAY(SELECT jsonb_object_keys(f) ORDER BY 1) IS DISTINCT FROM ARRAY['destination','receiver_contract','staging_directory']::text[]
 OR ARRAY(SELECT jsonb_object_keys(dest) ORDER BY 1) IS DISTINCT FROM ARRAY['address','ca_reference','ca_sha256','mode','password_reference','password_sha256','server_name','user']::text[]
 OR coalesce(dest->>'mode','') NOT IN ('explicit','implicit')
 OR coalesce(dest->>'ca_sha256','') !~ '^[0-9a-f]{64}$' OR coalesce(dest->>'password_sha256','') !~ '^[0-9a-f]{64}$'
 OR coalesce(c->>'document_sha256','') !~ '^[0-9a-f]{64}$'
 OR c IS DISTINCT FROM jsonb_build_object('schema_version',1,'document_sha256',c->>'document_sha256','staging_visibility','receiver-private','rename','may-replace','duplicates','receiver-deduplicates-delivery-id','receipt','exact-readback')
 OR coalesce(f->>'staging_directory','')='' OR coalesce(d->>'directory','')='' OR f->>'staging_directory'=d->>'directory'
 THEN RAISE EXCEPTION 'invalid distinct FTPS receiver contract' USING ERRCODE='23514';END IF;
 IF d ? 'encryption' AND (NOT d ? 'workflow_binding'
 OR jsonb_typeof(d->'encryption') IS DISTINCT FROM 'object'
 OR d->'encryption' IS DISTINCT FROM jsonb_build_object('key',d->'encryption'->'key','profile',d->'encryption'->>'profile')
 OR d->'encryption'->'key' IS DISTINCT FROM jsonb_build_object('id',d->'encryption'->'key'->>'id','version',(d->'encryption'->'key'->>'version')::integer,'hash',d->'encryption'->'key'->>'hash')
 OR coalesce(d->'encryption'->>'profile','') NOT IN ('seipd-v1-aes256','seipd-v2-aes256-ocb')
 OR coalesce(d->'encryption'->'key'->>'hash','') !~ '^[0-9a-f]{64}$'
 OR coalesce((d->'encryption'->'key'->>'version')::integer,0)<1
 OR coalesce(d->'encryption'->'key'->>'id','') !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') THEN
  RAISE EXCEPTION 'FTPS encryption requires exact workflow recipient policy' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;

