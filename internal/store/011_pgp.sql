ALTER TABLE credentials DROP CONSTRAINT credential_permissions_valid;
ALTER TABLE credentials ADD CONSTRAINT credential_permissions_valid CHECK(cardinality(permissions)<=19 AND permissions <@ ARRAY['read','write','list','manage_paths','inspect','audit_read','admin','connections_manage','deliver','workflow_manage','workflow_approve','workflow_execute','ai_manage','ai_use','ai_disclose','intake_manage','check_run','check_release','pgp_manage']::text[]);
ALTER TABLE credentials ALTER COLUMN permissions SET DEFAULT ARRAY['read','write','list','manage_paths','inspect','audit_read','admin','connections_manage','deliver','workflow_manage','workflow_approve','workflow_execute','ai_manage','ai_use','ai_disclose','intake_manage','check_run','check_release','pgp_manage']::text[];
CREATE TABLE pgp_keys (
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,actor_id uuid NOT NULL,key_id uuid NOT NULL,version integer NOT NULL CHECK(version>0),
 definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object' AND octet_length(definition::text)<=24576),definition_hash text NOT NULL CHECK(definition_hash ~ '^[0-9a-f]{64}$'),
 valid_until timestamptz,state text NOT NULL CHECK(state IN ('active','revoked')),revision bigint NOT NULL CHECK(revision>0),changed_event_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,key_id,version),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,changed_event_id) REFERENCES events(tenant_id,partner_id,event_id)
);
CREATE TABLE file_signatures (
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,actor_id uuid NOT NULL,file_id uuid NOT NULL,
 object_id uuid NOT NULL,storage_id uuid NOT NULL,size_bytes bigint NOT NULL CHECK(size_bytes BETWEEN 1 AND 32768),sha256 text NOT NULL CHECK(sha256 ~ '^[0-9a-f]{64}$'),
 data_sha256 text NOT NULL CHECK(data_sha256 ~ '^[0-9a-f]{64}$'),policy_hash text NOT NULL CHECK(policy_hash ~ '^[0-9a-f]{64}$'),
 key_id uuid NOT NULL,key_version integer NOT NULL,key_hash text NOT NULL CHECK(key_hash ~ '^[0-9a-f]{64}$'),attached_event_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,file_id),UNIQUE(tenant_id,partner_id,object_id),
 FOREIGN KEY(tenant_id,partner_id,file_id) REFERENCES file_checks(tenant_id,partner_id,file_id),
 FOREIGN KEY(tenant_id,partner_id,key_id,key_version) REFERENCES pgp_keys(tenant_id,partner_id,key_id,version),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,attached_event_id) REFERENCES events(tenant_id,partner_id,event_id)
);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['pgp_keys','file_signatures'] LOOP
  EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',t);EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('CREATE POLICY scope ON %I USING(tenant_id=nullif(current_setting(''freightctl.tenant_id'',true),'''')::uuid AND partner_id=nullif(current_setting(''freightctl.partner_id'',true),'''')::uuid) WITH CHECK(tenant_id=nullif(current_setting(''freightctl.tenant_id'',true),'''')::uuid AND partner_id=nullif(current_setting(''freightctl.partner_id'',true),'''')::uuid)',t);
 END LOOP;
END $$;
CREATE POLICY signature_identity ON file_signatures AS RESTRICTIVE FOR SELECT USING(actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid OR EXISTS(SELECT 1 FROM credentials c WHERE c.actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid AND c.namespace_root='/' AND 'inspect'=ANY(c.permissions) AND c.revoked_at IS NULL));
CREATE POLICY signature_writer ON file_signatures AS RESTRICTIVE FOR INSERT WITH CHECK(actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid);
GRANT SELECT,INSERT,UPDATE ON pgp_keys TO freightctl_runtime;
GRANT SELECT,INSERT ON file_signatures TO freightctl_runtime;
CREATE FUNCTION freightctl_pgp_key_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE p jsonb; maximum integer;
BEGIN
 SELECT payload INTO p FROM events WHERE (tenant_id,partner_id,event_id)=(NEW.tenant_id,NEW.partner_id,NEW.changed_event_id) AND actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid AND resource_id=NEW.key_id AND kind='PGPKeyChanged';
 IF p IS NULL OR p->>'id' IS DISTINCT FROM NEW.key_id::text OR p->>'version' IS DISTINCT FROM NEW.version::text OR p->'definition' IS DISTINCT FROM NEW.definition OR p->>'definition_hash' IS DISTINCT FROM NEW.definition_hash OR p->>'state' IS DISTINCT FROM NEW.state OR p->>'revision' IS DISTINCT FROM NEW.revision::text OR (NEW.definition->>'valid_until')::timestamptz IS DISTINCT FROM NEW.valid_until THEN RAISE EXCEPTION 'PGP key requires its exact event and validity' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN
  SELECT coalesce(max(version),0) INTO maximum FROM pgp_keys WHERE tenant_id=NEW.tenant_id AND partner_id=NEW.partner_id AND key_id=NEW.key_id;
  IF NEW.version<>maximum+1 OR NEW.state<>'active' OR NEW.revision<>1 OR (NEW.valid_until IS NOT NULL AND NEW.valid_until<=clock_timestamp()) THEN RAISE EXCEPTION 'invalid PGP key registration' USING ERRCODE='23514';END IF;
 ELSE
  IF (NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.key_id,NEW.version,NEW.definition,NEW.definition_hash,NEW.valid_until) IS DISTINCT FROM (OLD.tenant_id,OLD.partner_id,OLD.actor_id,OLD.key_id,OLD.version,OLD.definition,OLD.definition_hash,OLD.valid_until) OR NEW.revision<>OLD.revision+1 OR OLD.state<>'active' OR NEW.state<>'revoked' THEN RAISE EXCEPTION 'PGP key material is immutable' USING ERRCODE='23514';END IF;
 END IF;RETURN NEW;
END $$;
CREATE TRIGGER pgp_key_guard BEFORE INSERT OR UPDATE ON pgp_keys FOR EACH ROW EXECUTE FUNCTION freightctl_pgp_key_guard();
CREATE FUNCTION freightctl_signature_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE p jsonb;c file_checks;i intake_policies;
BEGIN
 SELECT payload INTO p FROM events WHERE (tenant_id,partner_id,event_id)=(NEW.tenant_id,NEW.partner_id,NEW.attached_event_id) AND actor_id=NEW.actor_id AND resource_id=NEW.file_id AND kind='FileSignatureAttached';
 IF p IS NULL OR p->>'file_id' IS DISTINCT FROM NEW.file_id::text OR p->>'object_id' IS DISTINCT FROM NEW.object_id::text OR p->>'storage_id' IS DISTINCT FROM NEW.storage_id::text OR p->>'size_bytes' IS DISTINCT FROM NEW.size_bytes::text OR p->>'sha256' IS DISTINCT FROM NEW.sha256 OR p->>'data_sha256' IS DISTINCT FROM NEW.data_sha256 OR p->>'policy_hash' IS DISTINCT FROM NEW.policy_hash OR p->'key' IS DISTINCT FROM jsonb_build_object('id',NEW.key_id::text,'version',NEW.key_version,'hash',NEW.key_hash) THEN RAISE EXCEPTION 'signature attachment requires exact immutable event' USING ERRCODE='23514';END IF;
 SELECT * INTO c FROM file_checks WHERE (tenant_id,partner_id,file_id,actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.file_id,NEW.actor_id);
 SELECT * INTO i FROM intake_policies WHERE (tenant_id,partner_id,policy_id,version)=(c.tenant_id,c.partner_id,c.policy_id,c.policy_version);
 IF c.file_id IS NULL OR c.state<>'held' OR c.attempts<>0 OR c.policy_hash<>NEW.policy_hash OR c.binding->'file'->>'sha256'<>NEW.data_sha256 OR c.binding->>'storage_id'<>NEW.storage_id::text OR i.state<>'active' OR i.definition->'signature'->'key' IS DISTINCT FROM p->'key' OR NOT EXISTS(SELECT 1 FROM pgp_keys k WHERE (k.tenant_id,k.partner_id,k.key_id,k.version,k.definition_hash,k.state)=(NEW.tenant_id,NEW.partner_id,NEW.key_id,NEW.key_version,NEW.key_hash,'active') AND (k.valid_until IS NULL OR k.valid_until>clock_timestamp())) THEN RAISE EXCEPTION 'signature must bind current held data, policy, storage and key' USING ERRCODE='23514';END IF;RETURN NEW;
END $$;
CREATE TRIGGER signature_guard BEFORE INSERT ON file_signatures FOR EACH ROW EXECUTE FUNCTION freightctl_signature_guard();
CREATE FUNCTION freightctl_signature_policy_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.definition ? 'signature' AND NEW.definition->'signature'<>'null'::jsonb AND NOT EXISTS(SELECT 1 FROM pgp_keys k WHERE (k.tenant_id,k.partner_id,k.key_id,k.version,k.definition_hash,k.state)=(NEW.tenant_id,NEW.partner_id,(NEW.definition->'signature'->'key'->>'id')::uuid,(NEW.definition->'signature'->'key'->>'version')::integer,NEW.definition->'signature'->'key'->>'hash','active') AND (k.valid_until IS NULL OR k.valid_until>clock_timestamp())) THEN RAISE EXCEPTION 'signature policy requires current approved key version' USING ERRCODE='23514';END IF;RETURN NEW;
END $$;
CREATE TRIGGER signature_policy_guard BEFORE INSERT ON intake_policies FOR EACH ROW EXECUTE FUNCTION freightctl_signature_policy_guard();
CREATE FUNCTION freightctl_signature_verdict_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE i intake_policies;s file_signatures;ref jsonb;
BEGIN
 SELECT * INTO i FROM intake_policies WHERE (tenant_id,partner_id,policy_id,version)=(NEW.tenant_id,NEW.partner_id,NEW.policy_id,NEW.policy_version);ref:=i.definition->'signature'->'key';
 IF NEW.state IN ('passed','released') AND ref IS NOT NULL AND ref<>'null'::jsonb THEN
  SELECT * INTO s FROM file_signatures WHERE (tenant_id,partner_id,file_id,actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.file_id,NEW.actor_id);
  IF s.file_id IS NULL OR NEW.report->'signature'->'key' IS DISTINCT FROM ref OR NEW.report->'signature'->>'object_id' IS DISTINCT FROM s.object_id::text OR NEW.report->'signature'->>'sha256' IS DISTINCT FROM s.sha256 OR NEW.report->'signature'->'verification'->>'signature_sha256' IS DISTINCT FROM s.sha256 OR NOT EXISTS(SELECT 1 FROM pgp_keys k WHERE (k.tenant_id,k.partner_id,k.key_id,k.version,k.definition_hash,k.state)=(NEW.tenant_id,NEW.partner_id,s.key_id,s.key_version,s.key_hash,'active') AND (k.valid_until IS NULL OR k.valid_until>clock_timestamp()) AND k.definition->>'fingerprint'=NEW.report->'signature'->'verification'->>'primary_fingerprint') OR ((NEW.report->'signature'->'verification'->>'valid_until')::timestamptz IS NOT NULL AND (NEW.report->'signature'->'verification'->>'valid_until')::timestamptz<=clock_timestamp()) THEN RAISE EXCEPTION 'passing signature verdict requires its exact current attachment and signer' USING ERRCODE='23514';END IF;
 END IF;RETURN NEW;
END $$;
CREATE TRIGGER signature_verdict_guard BEFORE INSERT OR UPDATE ON file_checks FOR EACH ROW EXECUTE FUNCTION freightctl_signature_verdict_guard();
ALTER TABLE file_releases ADD COLUMN pgp_key_id uuid,ADD COLUMN pgp_key_version integer,ADD COLUMN pgp_key_hash text,ADD COLUMN signature_sha256 text,ADD COLUMN signature_expires_at timestamptz;
ALTER TABLE file_releases ADD CONSTRAINT release_signer_fk FOREIGN KEY(tenant_id,partner_id,pgp_key_id,pgp_key_version) REFERENCES pgp_keys(tenant_id,partner_id,key_id,version);
ALTER TABLE file_releases ADD CONSTRAINT release_signer_complete CHECK((pgp_key_id IS NULL AND pgp_key_version IS NULL AND pgp_key_hash IS NULL AND signature_sha256 IS NULL AND signature_expires_at IS NULL) OR (pgp_key_id IS NOT NULL AND pgp_key_version IS NOT NULL AND pgp_key_hash IS NOT NULL AND signature_sha256 IS NOT NULL AND pgp_key_hash ~ '^[0-9a-f]{64}$' AND signature_sha256 ~ '^[0-9a-f]{64}$'));
CREATE OR REPLACE FUNCTION freightctl_file_release_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE c file_checks;proof jsonb;
BEGIN
 SELECT * INTO c FROM file_checks WHERE (tenant_id,partner_id,file_id,actor_id,policy_id,policy_version,policy_hash,report_hash,changed_event_id,state)=(NEW.tenant_id,NEW.partner_id,NEW.file_id,NEW.actor_id,NEW.policy_id,NEW.policy_version,NEW.policy_hash,NEW.report_hash,NEW.released_event_id,'released');
 IF c.file_id IS NULL THEN RAISE EXCEPTION 'release proof requires exact authorized checked transition' USING ERRCODE='23514';END IF;
 proof:=c.report->'signature';
 IF (proof->'key'->>'id')::uuid IS DISTINCT FROM NEW.pgp_key_id OR (proof->'key'->>'version')::integer IS DISTINCT FROM NEW.pgp_key_version OR proof->'key'->>'hash' IS DISTINCT FROM NEW.pgp_key_hash OR proof->>'sha256' IS DISTINCT FROM NEW.signature_sha256 OR (proof->'verification'->>'valid_until')::timestamptz IS DISTINCT FROM NEW.signature_expires_at THEN RAISE EXCEPTION 'release signer proof must match the approved report' USING ERRCODE='23514';END IF;RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION freightctl_file_available(t uuid,p uuid,f uuid) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT EXISTS(SELECT 1 FROM files v WHERE (v.tenant_id,v.partner_id,v.file_id)=(t,p,f) AND (v.policy='integrity-only-v1' OR EXISTS(SELECT 1 FROM file_releases c JOIN intake_policies i ON (i.tenant_id,i.partner_id,i.policy_id,i.version)=(c.tenant_id,c.partner_id,c.policy_id,c.policy_version) WHERE (c.tenant_id,c.partner_id,c.file_id,i.state)=(t,p,f,'active') AND v.policy='intake-csv-v1:'||c.policy_hash AND c.policy_hash=i.definition_hash AND ((NOT (i.definition ? 'signature') OR i.definition->'signature'='null'::jsonb) OR EXISTS(SELECT 1 FROM pgp_keys k WHERE (k.tenant_id,k.partner_id,k.key_id,k.version,k.definition_hash,k.state)=(c.tenant_id,c.partner_id,c.pgp_key_id,c.pgp_key_version,c.pgp_key_hash,'active') AND (k.valid_until IS NULL OR k.valid_until>clock_timestamp()) AND (c.signature_expires_at IS NULL OR c.signature_expires_at>clock_timestamp()))))))
$$;
REVOKE ALL ON FUNCTION freightctl_pgp_key_guard(),freightctl_signature_guard(),freightctl_signature_policy_guard(),freightctl_signature_verdict_guard() FROM PUBLIC;
