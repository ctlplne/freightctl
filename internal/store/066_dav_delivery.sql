-- Distinct direct schema3 DAV delivery. Existing SFTP/FTPS canonical meanings,
-- custody,event,approval,lease/fence and RLS guards remain enforced.
CREATE FUNCTION freightctl_dav_delivery_path(p text) RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE part text; base text;
BEGIN
 IF p IS NULL OR octet_length(p) NOT BETWEEN 1 AND 768 OR left(p,1)<>'/' OR p<>normalize(p,NFC) THEN RETURN false;END IF;
 IF p='/' THEN RETURN true;END IF;
 FOREACH part IN ARRAY string_to_array(substring(p FROM 2),'/') LOOP
  base:=upper(split_part(part,'.',1));
  IF part IN ('','.','..','.freightctl') OR octet_length(part)>255 OR right(part,1) IN ('.',' ')
  OR part ~ '[[:cntrl:]]' OR position(':' in part)>0 OR position(chr(92) in part)>0
  OR base ~ '^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$' THEN RETURN false;END IF;
 END LOOP;
 RETURN true;
END $$;
REVOKE ALL ON FUNCTION freightctl_dav_delivery_path(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION freightctl_dav_delivery_path(text) TO freightctl_runtime;

CREATE FUNCTION freightctl_dav_delivery_definition(d jsonb) RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE f jsonb; dest jsonb; c jsonb; stage text; final text; candidate jsonb;
BEGIN
 IF jsonb_typeof(d) IS DISTINCT FROM 'object' OR d->'schema_version' IS DISTINCT FROM '3'::jsonb
 OR d->>'namespace_root' IS DISTINCT FROM '/'
 OR ARRAY(SELECT jsonb_object_keys(d-'dispatch_approval_policy') ORDER BY 1) IS DISTINCT FROM ARRAY['authority_revision','dav','destination','directory','filename','namespace_root','schema_version','source','storage_id']::text[]
 OR d->'destination' IS DISTINCT FROM '{"address":"","user":"","host":{"Wire":null,"Fingerprint":""},"key_reference":"","key_fingerprint":""}'::jsonb
 OR jsonb_typeof(d->'dav') IS DISTINCT FROM 'object' OR jsonb_typeof(d->'directory') IS DISTINCT FROM 'string'
 OR jsonb_typeof(d->'filename') IS DISTINCT FROM 'string' OR coalesce(d->>'filename','') !~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$' OR right(d->>'filename',1)='.' THEN RETURN false;END IF;
 f:=d->'dav';dest:=f->'destination';c:=f->'receiver_contract';stage:=f->>'staging_directory';final:=d->>'directory';
 IF ARRAY(SELECT jsonb_object_keys(f) ORDER BY 1) IS DISTINCT FROM ARRAY['destination','receiver_contract','staging_directory']::text[]
 OR jsonb_typeof(f->'staging_directory') IS DISTINCT FROM 'string' OR jsonb_typeof(dest) IS DISTINCT FROM 'object' OR jsonb_typeof(c) IS DISTINCT FROM 'object'
 OR NOT freightctl_dav_delivery_path(stage) OR NOT freightctl_dav_delivery_path(final)
 OR stage='/' OR final='/' OR stage=final OR left(stage,length(final)+1)=final||'/' OR left(final,length(stage)+1)=stage||'/'
 OR coalesce(c->>'document_sha256','') !~ '^[0-9a-f]{64}$'
 OR c IS DISTINCT FROM jsonb_build_object('schema_version',1,'document_sha256',c->>'document_sha256','staging_visibility','receiver-private','put','exclusive-create','move','source-etag-no-overwrite','duplicates','receiver-deduplicates-delivery-id','receipt','exact-readback') THEN RETURN false;END IF;
 -- Reuse only exact pinned endpoint,trust and credential shape validation.
 -- This constructed value grants no collection or forwarding capability.
 candidate:=jsonb_build_object('schema_version',4,'destination',d->'destination','directory',final,'dav',jsonb_build_object('schema_version',CASE WHEN dest->>'authentication'='basic' THEN 2 ELSE 1 END,'destination',dest));
 RETURN freightctl_dav_collection_connection(candidate);
EXCEPTION WHEN invalid_parameter_value OR invalid_text_representation OR numeric_value_out_of_range THEN RETURN false;
END $$;
REVOKE ALL ON FUNCTION freightctl_dav_delivery_definition(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION freightctl_dav_delivery_definition(jsonb) TO freightctl_runtime;

CREATE OR REPLACE FUNCTION freightctl_ftps_delivery_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE d jsonb:=NEW.definition;f jsonb;dest jsonb;c jsonb;
BEGIN
 IF d->>'schema_version'='3' THEN
  IF NOT freightctl_dav_delivery_definition(d) THEN RAISE EXCEPTION 'invalid distinct DAV delivery contract' USING ERRCODE='23514';END IF;
  IF NOT EXISTS(SELECT 1 FROM files f WHERE (f.tenant_id,f.partner_id,f.file_id)=(NEW.tenant_id,NEW.partner_id,NEW.file_id) AND d->'source'=jsonb_build_object('id',f.file_id::text,'size_bytes',f.size_bytes,'sha256',f.sha256,'policy',f.policy,'accepted_event_id',f.accepted_event_id::text)) THEN RAISE EXCEPTION 'DAV delivery source must equal exact accepted custody' USING ERRCODE='23514';END IF;
  RETURN NEW;
 END IF;
 IF d ? 'dav' THEN RAISE EXCEPTION 'DAV authority cannot enter a legacy delivery' USING ERRCODE='23514';END IF;
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

CREATE OR REPLACE FUNCTION freightctl_outbound_dispatch_expected_effect(original delivery_intents,recipient text) RETURNS jsonb LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE d jsonb:=original.definition;dest jsonb;expected jsonb;
BEGIN
 IF d->>'schema_version'='3' THEN
  dest:=d->'dav'->'destination';
  expected:=jsonb_build_object('protocol','webdav','address',dest->>'address','user',coalesce(dest->>'user',''),'directory',d->>'directory','filename',d->>'filename','final_path',rtrim(d->>'directory','/')||'/'||original.delivery_id::text||'-'||(d->>'filename'),'host_fingerprint','','key_fingerprint','','key_reference_sha256','','recipient_fingerprint','',
   'dav',jsonb_build_object('profile','freightctl-webdav-delivery-v1','authentication',CASE WHEN dest->>'authentication'='basic' THEN 'basic' ELSE 'bearer' END,'server_name',dest->>'server_name','ca_sha256',dest->>'ca_sha256','ca_reference_sha256',encode(sha256(convert_to(dest->>'ca_reference','UTF8')),'hex'),'staging_path',rtrim(d->'dav'->>'staging_directory','/')||'/.freightctl-'||original.delivery_id::text||'.partial','receiver_contract',d->'dav'->'receiver_contract')
    || CASE WHEN dest->>'authentication'='basic' THEN jsonb_build_object('password_reference_sha256',encode(sha256(convert_to(dest->>'password_reference','UTF8')),'hex')) ELSE jsonb_build_object('token_reference_sha256',encode(sha256(convert_to(dest->>'token_reference','UTF8')),'hex')) END);
 ELSIF d->>'schema_version'='2' THEN
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

CREATE OR REPLACE FUNCTION freightctl_outbound_dispatch_review_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE e jsonb;d jsonb;a uuid;original delivery_intents%ROWTYPE;expected jsonb;recipient text;pending integer;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'outbound dispatch reviews cannot be deleted' USING ERRCODE='23514';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id::text||':'||NEW.partner_id::text||':accounts',0));
 IF TG_OP='UPDATE' THEN PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id::text||':'||NEW.partner_id::text||':outbound-dispatch-policy',0));END IF;
 a:=nullif(current_setting('freightctl.actor_id',true),'')::uuid;d:=NEW.definition;
 SELECT payload INTO e FROM events WHERE (tenant_id,partner_id,event_id,actor_id,resource_id,kind)=(NEW.tenant_id,NEW.partner_id,NEW.changed_event_id,a,NEW.review_id,'OutboundDispatchReviewChanged');
 IF e IS NULL OR e->>'id' IS DISTINCT FROM NEW.review_id::text OR e->>'author_id' IS DISTINCT FROM NEW.actor_id::text OR e->>'reviewer_id' IS DISTINCT FROM NEW.reviewer_id::text OR e->>'delivery_id' IS DISTINCT FROM NEW.delivery_id::text OR e->'definition' IS DISTINCT FROM d OR e->>'definition_hash' IS DISTINCT FROM NEW.definition_hash OR e->>'state' IS DISTINCT FROM NEW.state OR e->>'revision' IS DISTINCT FROM NEW.revision::text OR (e->>'created_at')::timestamptz IS DISTINCT FROM NEW.created_at THEN RAISE EXCEPTION 'outbound review requires exact immutable journal record' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN
  SELECT count(*) INTO pending FROM outbound_dispatch_reviews WHERE tenant_id=NEW.tenant_id AND partner_id=NEW.partner_id AND actor_id=NEW.actor_id AND state='pending';IF pending>=128 THEN RAISE EXCEPTION 'outbound review admission full' USING ERRCODE='23514';END IF;
  IF a<>NEW.actor_id OR NEW.state<>'pending' OR NEW.revision<>1 OR NOT EXISTS(SELECT 1 FROM credentials c WHERE (c.tenant_id,c.partner_id,c.actor_id)=(NEW.tenant_id,NEW.partner_id,a) AND c.namespace_root='/' AND c.permissions @> ARRAY['read','deliver']::text[] AND c.authority_revision::text=d->>'authority_revision' AND c.revoked_at IS NULL AND (c.expires_at IS NULL OR c.expires_at>clock_timestamp())) THEN RAISE EXCEPTION 'dispatch review starts with authorized owner proposal' USING ERRCODE='42501';END IF;
  IF ARRAY(SELECT jsonb_object_keys(d) ORDER BY 1) IS DISTINCT FROM ARRAY['attempt_limit','author_id','authority_revision','delivery_hash','delivery_id','delivery_revision','effect','namespace_root','policy','reviewer_authority_revision','reviewer_id','schema_version','source','storage_id']::text[] OR coalesce(d->>'schema_version','') NOT IN ('1','2','3') OR d->>'attempt_limit' IS DISTINCT FROM '8' OR d->>'namespace_root' IS DISTINCT FROM '/' OR d->>'author_id' IS DISTINCT FROM NEW.actor_id::text OR d->>'reviewer_id' IS DISTINCT FROM NEW.reviewer_id::text OR d->>'delivery_id' IS DISTINCT FROM NEW.delivery_id::text OR d->'policy' IS DISTINCT FROM freightctl_outbound_dispatch_policy_binding(NEW.tenant_id,NEW.partner_id) OR d->'policy'->>'mode' IS DISTINCT FROM 'independent' OR d->'policy'->>'revision' IS DISTINCT FROM NEW.policy_revision::text THEN RAISE EXCEPTION 'invalid exact dispatch review binding' USING ERRCODE='23514';END IF;
  IF NOT EXISTS(SELECT 1 FROM credentials c WHERE (c.tenant_id,c.partner_id,c.actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.reviewer_id) AND c.namespace_root='/' AND c.permissions @> ARRAY['inspect','workflow_approve']::text[] AND c.authority_revision::text=d->>'reviewer_authority_revision' AND c.revoked_at IS NULL AND (c.expires_at IS NULL OR c.expires_at>clock_timestamp())) THEN RAISE EXCEPTION 'dispatch reviewer lacks current authority' USING ERRCODE='42501';END IF;
  SELECT * INTO original FROM delivery_intents WHERE (tenant_id,partner_id,actor_id,delivery_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.delivery_id);
  IF d->>'schema_version' IS DISTINCT FROM original.definition->>'schema_version' THEN RAISE EXCEPTION 'dispatch schema must equal exact intent' USING ERRCODE='23514';END IF;
  IF original.delivery_id IS NULL OR original.state NOT IN ('draft','queued') OR original.attempts<>0 OR original.fence<>0 OR original.lease_owner IS NOT NULL OR original.revision::text IS DISTINCT FROM d->>'delivery_revision' OR original.definition_hash IS DISTINCT FROM d->>'delivery_hash' OR original.definition->'source' IS DISTINCT FROM d->'source' OR original.definition->>'storage_id' IS DISTINCT FROM d->>'storage_id' OR original.definition->>'authority_revision' IS DISTINCT FROM d->>'authority_revision' OR original.definition->>'namespace_root' IS DISTINCT FROM d->>'namespace_root' OR original.definition->'dispatch_approval_policy' IS DISTINCT FROM d->'policy' OR EXISTS(SELECT 1 FROM delivery_ciphertexts WHERE (tenant_id,partner_id,actor_id,delivery_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.delivery_id)) OR NOT freightctl_file_available(NEW.tenant_id,NEW.partner_id,original.file_id) THEN RAISE EXCEPTION 'review requires exact untouched authorized delivery' USING ERRCODE='23514';END IF;
  IF NOT EXISTS(SELECT 1 FROM files f WHERE (f.tenant_id,f.partner_id,f.file_id)=(NEW.tenant_id,NEW.partner_id,original.file_id) AND d->'source'=jsonb_build_object('id',f.file_id::text,'size_bytes',f.size_bytes,'sha256',f.sha256,'policy',f.policy,'accepted_event_id',f.accepted_event_id::text)) THEN RAISE EXCEPTION 'dispatch source must equal accepted file' USING ERRCODE='23514';END IF;
  recipient:='';IF original.definition ? 'encryption' THEN SELECT definition->>'fingerprint' INTO recipient FROM pgp_keys WHERE (tenant_id,partner_id,key_id,version)=(NEW.tenant_id,NEW.partner_id,(original.definition->'encryption'->'key'->>'id')::uuid,(original.definition->'encryption'->'key'->>'version')::integer) AND state='active' AND definition_hash=original.definition->'encryption'->'key'->>'hash' AND (valid_until IS NULL OR valid_until>clock_timestamp());IF recipient IS NULL THEN RAISE EXCEPTION 'dispatch recipient changed' USING ERRCODE='23514';END IF;END IF;
  expected:=freightctl_outbound_dispatch_expected_effect(original,recipient);
  IF d->'effect' IS DISTINCT FROM expected THEN RAISE EXCEPTION 'dispatch effects must equal exact intent' USING ERRCODE='23514';END IF;
 ELSE
  IF (NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.review_id,NEW.reviewer_id,NEW.delivery_id,NEW.definition,NEW.definition_hash,NEW.created_at,NEW.policy_revision) IS DISTINCT FROM (OLD.tenant_id,OLD.partner_id,OLD.actor_id,OLD.review_id,OLD.reviewer_id,OLD.delivery_id,OLD.definition,OLD.definition_hash,OLD.created_at,OLD.policy_revision) OR NEW.revision<>OLD.revision+1 THEN RAISE EXCEPTION 'dispatch review identity is immutable' USING ERRCODE='23514';END IF;
  IF NEW.state='withdrawn' AND OLD.state IN ('pending','approved') THEN IF a<>NEW.actor_id AND a<>NEW.reviewer_id THEN RAISE EXCEPTION 'only owner or named reviewer can withdraw' USING ERRCODE='42501';END IF;
  ELSIF NEW.state IN ('approved','rejected') AND OLD.state='pending' THEN
   IF a<>NEW.reviewer_id OR a=NEW.actor_id OR d->'policy' IS DISTINCT FROM freightctl_outbound_dispatch_policy_binding(NEW.tenant_id,NEW.partner_id) OR NOT EXISTS(SELECT 1 FROM credentials c WHERE (c.tenant_id,c.partner_id,c.actor_id)=(NEW.tenant_id,NEW.partner_id,a) AND c.authority_revision::text=d->>'reviewer_authority_revision' AND c.permissions @> ARRAY['inspect','workflow_approve']::text[] AND c.namespace_root='/' AND c.revoked_at IS NULL AND (c.expires_at IS NULL OR c.expires_at>clock_timestamp())) THEN RAISE EXCEPTION 'approval requires exact current independent dispatch reviewer' USING ERRCODE='42501';END IF;
   IF NOT EXISTS(SELECT 1 FROM credentials c WHERE (c.tenant_id,c.partner_id,c.actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id) AND c.authority_revision::text=d->>'authority_revision' AND c.revoked_at IS NULL AND (c.expires_at IS NULL OR c.expires_at>clock_timestamp())) THEN RAISE EXCEPTION 'dispatch author authority changed' USING ERRCODE='42501';END IF;
  ELSE RAISE EXCEPTION 'invalid dispatch review transition' USING ERRCODE='23514';END IF;
 END IF;RETURN NEW;
END $$;
