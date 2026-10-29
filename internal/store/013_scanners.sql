ALTER TABLE credentials DROP CONSTRAINT credential_permissions_valid;
ALTER TABLE credentials ADD CONSTRAINT credential_permissions_valid CHECK(cardinality(permissions)<=20 AND permissions <@ ARRAY['read','write','list','manage_paths','inspect','audit_read','admin','connections_manage','deliver','workflow_manage','workflow_approve','workflow_execute','ai_manage','ai_use','ai_disclose','intake_manage','check_run','check_release','pgp_manage','scanner_manage']::text[]);
ALTER TABLE credentials ALTER COLUMN permissions SET DEFAULT ARRAY['read','write','list','manage_paths','inspect','audit_read','admin','connections_manage','deliver','workflow_manage','workflow_approve','workflow_execute','ai_manage','ai_use','ai_disclose','intake_manage','check_run','check_release','pgp_manage','scanner_manage']::text[];
CREATE TABLE scanner_profiles(
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,actor_id uuid NOT NULL,scanner_id uuid NOT NULL,version integer NOT NULL CHECK(version>0),definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object' AND octet_length(definition::text)<=8192),definition_hash text NOT NULL CHECK(definition_hash ~ '^[0-9a-f]{64}$'),valid_until timestamptz NOT NULL,state text NOT NULL CHECK(state IN ('active','revoked')),revision bigint NOT NULL CHECK(revision>0),changed_event_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,scanner_id,version),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,changed_event_id) REFERENCES events(tenant_id,partner_id,event_id)
);
ALTER TABLE scanner_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE scanner_profiles FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON scanner_profiles USING(tenant_id=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND partner_id=nullif(current_setting('freightctl.partner_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND partner_id=nullif(current_setting('freightctl.partner_id',true),'')::uuid);
GRANT SELECT,INSERT,UPDATE ON scanner_profiles TO freightctl_runtime;
CREATE FUNCTION freightctl_scanner_profile_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE p jsonb;maximum integer;
BEGIN
 SELECT payload INTO p FROM events WHERE (tenant_id,partner_id,event_id)=(NEW.tenant_id,NEW.partner_id,NEW.changed_event_id) AND actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid AND resource_id=NEW.scanner_id AND kind='ScannerProfileChanged';
 IF p IS NULL OR p->>'id' IS DISTINCT FROM NEW.scanner_id::text OR p->>'version' IS DISTINCT FROM NEW.version::text OR p->'definition' IS DISTINCT FROM NEW.definition OR p->>'definition_hash' IS DISTINCT FROM NEW.definition_hash OR p->>'state' IS DISTINCT FROM NEW.state OR p->>'revision' IS DISTINCT FROM NEW.revision::text OR (NEW.definition->>'valid_until')::timestamptz IS DISTINCT FROM NEW.valid_until THEN RAISE EXCEPTION 'scanner profile requires its exact event and expiry' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN
  SELECT coalesce(max(version),0) INTO maximum FROM scanner_profiles WHERE tenant_id=NEW.tenant_id AND partner_id=NEW.partner_id AND scanner_id=NEW.scanner_id;
  IF NEW.version<>maximum+1 OR NEW.state<>'active' OR NEW.revision<>1 OR NEW.valid_until<=clock_timestamp() OR NEW.valid_until>clock_timestamp()+interval '72 hours' OR NEW.definition->>'kind' IS DISTINCT FROM 'clamd-instream-v1' THEN RAISE EXCEPTION 'invalid scanner profile creation' USING ERRCODE='23514';END IF;
 ELSE
  IF (NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.scanner_id,NEW.version,NEW.definition,NEW.definition_hash,NEW.valid_until) IS DISTINCT FROM (OLD.tenant_id,OLD.partner_id,OLD.actor_id,OLD.scanner_id,OLD.version,OLD.definition,OLD.definition_hash,OLD.valid_until) OR NEW.revision<>OLD.revision+1 OR OLD.state<>'active' OR NEW.state<>'revoked' THEN RAISE EXCEPTION 'scanner profile definition is immutable' USING ERRCODE='23514';END IF;
 END IF;RETURN NEW;
END $$;
CREATE TRIGGER scanner_profile_guard BEFORE INSERT OR UPDATE ON scanner_profiles FOR EACH ROW EXECUTE FUNCTION freightctl_scanner_profile_guard();
CREATE FUNCTION freightctl_scanner_policy_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.definition ? 'scanner' AND NEW.definition->'scanner'<>'null'::jsonb AND NOT EXISTS(SELECT 1 FROM scanner_profiles s WHERE (s.tenant_id,s.partner_id,s.scanner_id,s.version,s.definition_hash,s.state)=(NEW.tenant_id,NEW.partner_id,(NEW.definition->'scanner'->>'id')::uuid,(NEW.definition->'scanner'->>'version')::integer,NEW.definition->'scanner'->>'hash','active') AND s.valid_until>clock_timestamp()) THEN RAISE EXCEPTION 'scan policy requires exact active scanner profile' USING ERRCODE='23514';END IF;RETURN NEW;
END $$;
CREATE TRIGGER scanner_policy_guard BEFORE INSERT ON intake_policies FOR EACH ROW EXECUTE FUNCTION freightctl_scanner_policy_guard();
CREATE FUNCTION freightctl_scanner_verdict_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE p intake_policies;ref jsonb;proof jsonb;
BEGIN
 SELECT * INTO p FROM intake_policies WHERE (tenant_id,partner_id,policy_id,version)=(NEW.tenant_id,NEW.partner_id,NEW.policy_id,NEW.policy_version);ref:=p.definition->'scanner';proof:=NEW.report->'scanner';
 IF NEW.state IN ('passed','released') AND ref IS NOT NULL AND ref<>'null'::jsonb THEN
  IF proof->'profile' IS DISTINCT FROM ref OR proof->'result'->>'verdict' IS DISTINCT FROM 'clean' OR proof->'result'->>'backend' IS DISTINCT FROM 'clamd-instream-v1' OR proof->'result'->>'sha256' IS DISTINCT FROM NEW.binding->'file'->>'sha256' OR proof->'result'->>'bytes_scanned' IS DISTINCT FROM NEW.binding->'file'->>'size_bytes' OR proof->>'valid_until' IS NULL OR (proof->>'valid_until')::timestamptz<=clock_timestamp() OR NOT EXISTS(SELECT 1 FROM scanner_profiles s WHERE (s.tenant_id,s.partner_id,s.scanner_id,s.version,s.definition_hash,s.state)=(NEW.tenant_id,NEW.partner_id,(ref->>'id')::uuid,(ref->>'version')::integer,ref->>'hash','active') AND s.valid_until>clock_timestamp() AND proof->'result'->>'configuration_sha256'=s.definition->>'configuration_sha256' AND proof->'result'->'version'=jsonb_build_object('engine_version',substring(split_part(s.definition->>'expected_version','/',1) FROM 8),'database_version',split_part(s.definition->>'expected_version','/',2)::bigint,'database_date',split_part(s.definition->>'expected_version','/',3)) AND (proof->>'valid_until')::timestamptz<=s.valid_until) THEN RAISE EXCEPTION 'passing scan verdict requires exact clean current source and profile proof' USING ERRCODE='23514';END IF;
 END IF;RETURN NEW;
END $$;
CREATE TRIGGER scanner_verdict_guard BEFORE INSERT OR UPDATE ON file_checks FOR EACH ROW EXECUTE FUNCTION freightctl_scanner_verdict_guard();
ALTER TABLE file_releases ADD COLUMN scanner_id uuid,ADD COLUMN scanner_version integer,ADD COLUMN scanner_hash text,ADD COLUMN scan_expires_at timestamptz;
ALTER TABLE file_releases ADD CONSTRAINT release_scanner_fk FOREIGN KEY(tenant_id,partner_id,scanner_id,scanner_version) REFERENCES scanner_profiles(tenant_id,partner_id,scanner_id,version);
ALTER TABLE file_releases ADD CONSTRAINT release_scanner_complete CHECK((scanner_id IS NULL AND scanner_version IS NULL AND scanner_hash IS NULL AND scan_expires_at IS NULL) OR (scanner_id IS NOT NULL AND scanner_version IS NOT NULL AND scanner_version>0 AND scanner_hash IS NOT NULL AND scanner_hash ~ '^[0-9a-f]{64}$' AND scan_expires_at IS NOT NULL));
CREATE FUNCTION freightctl_scan_release_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE proof jsonb;
BEGIN
 SELECT report->'scanner' INTO proof FROM file_checks WHERE (tenant_id,partner_id,file_id,report_hash,state)=(NEW.tenant_id,NEW.partner_id,NEW.file_id,NEW.report_hash,'released');
 IF (proof->'profile'->>'id')::uuid IS DISTINCT FROM NEW.scanner_id OR (proof->'profile'->>'version')::integer IS DISTINCT FROM NEW.scanner_version OR proof->'profile'->>'hash' IS DISTINCT FROM NEW.scanner_hash OR (proof->>'valid_until')::timestamptz IS DISTINCT FROM NEW.scan_expires_at THEN RAISE EXCEPTION 'release scan proof must match approved report' USING ERRCODE='23514';END IF;RETURN NEW;
END $$;
CREATE TRIGGER scan_release_guard BEFORE INSERT ON file_releases FOR EACH ROW EXECUTE FUNCTION freightctl_scan_release_guard();
CREATE OR REPLACE FUNCTION freightctl_file_available(t uuid,p uuid,f uuid) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT EXISTS(SELECT 1 FROM files v WHERE (v.tenant_id,v.partner_id,v.file_id)=(t,p,f) AND (v.policy='integrity-only-v1' OR EXISTS(SELECT 1 FROM file_releases c JOIN intake_policies i ON (i.tenant_id,i.partner_id,i.policy_id,i.version)=(c.tenant_id,c.partner_id,c.policy_id,c.policy_version) WHERE (c.tenant_id,c.partner_id,c.file_id,i.state)=(t,p,f,'active') AND v.policy='intake-csv-v1:'||c.policy_hash AND c.policy_hash=i.definition_hash AND ((NOT (i.definition ? 'signature') OR i.definition->'signature'='null'::jsonb) OR EXISTS(SELECT 1 FROM pgp_keys k WHERE (k.tenant_id,k.partner_id,k.key_id,k.version,k.definition_hash,k.state)=(c.tenant_id,c.partner_id,c.pgp_key_id,c.pgp_key_version,c.pgp_key_hash,'active') AND (k.valid_until IS NULL OR k.valid_until>clock_timestamp()) AND (c.signature_expires_at IS NULL OR c.signature_expires_at>clock_timestamp()))) AND ((NOT (i.definition ? 'scanner') OR i.definition->'scanner'='null'::jsonb) OR EXISTS(SELECT 1 FROM scanner_profiles s WHERE (s.tenant_id,s.partner_id,s.scanner_id,s.version,s.definition_hash,s.state)=(c.tenant_id,c.partner_id,c.scanner_id,c.scanner_version,c.scanner_hash,'active') AND s.valid_until>clock_timestamp() AND c.scan_expires_at>clock_timestamp())))))
$$;
REVOKE ALL ON FUNCTION freightctl_scanner_profile_guard(),freightctl_scanner_policy_guard(),freightctl_scanner_verdict_guard(),freightctl_scan_release_guard() FROM PUBLIC;
