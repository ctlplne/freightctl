CREATE TABLE delivery_ciphertexts (
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,actor_id uuid NOT NULL,delivery_id uuid NOT NULL,
 object_id uuid NOT NULL,storage_id uuid NOT NULL,size_bytes bigint NOT NULL CHECK(size_bytes>0),sha256 text NOT NULL CHECK(sha256 ~ '^[0-9a-f]{64}$'),
 source_file_id uuid NOT NULL,source_sha256 text NOT NULL CHECK(source_sha256 ~ '^[0-9a-f]{64}$'),definition_hash text NOT NULL CHECK(definition_hash ~ '^[0-9a-f]{64}$'),
 encryption jsonb NOT NULL CHECK(jsonb_typeof(encryption)='object' AND octet_length(encryption::text)<=1024),proof jsonb NOT NULL CHECK(jsonb_typeof(proof)='object' AND octet_length(proof::text)<=2048),
 prepared_fence bigint NOT NULL CHECK(prepared_fence>0),prepared_owner uuid NOT NULL,prepared_event_id uuid NOT NULL,
 key_id uuid GENERATED ALWAYS AS ((encryption->'key'->>'id')::uuid) STORED NOT NULL,
 key_version integer GENERATED ALWAYS AS ((encryption->'key'->>'version')::integer) STORED NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,delivery_id),UNIQUE(tenant_id,partner_id,object_id),
 FOREIGN KEY(tenant_id,partner_id,delivery_id) REFERENCES delivery_intents(tenant_id,partner_id,delivery_id),
 FOREIGN KEY(tenant_id,partner_id,source_file_id) REFERENCES files(tenant_id,partner_id,file_id),
 FOREIGN KEY(tenant_id,partner_id,key_id,key_version) REFERENCES pgp_keys(tenant_id,partner_id,key_id,version),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,prepared_event_id) REFERENCES events(tenant_id,partner_id,event_id)
);
ALTER TABLE delivery_ciphertexts ENABLE ROW LEVEL SECURITY;
ALTER TABLE delivery_ciphertexts FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON delivery_ciphertexts USING(tenant_id=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND partner_id=nullif(current_setting('freightctl.partner_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND partner_id=nullif(current_setting('freightctl.partner_id',true),'')::uuid);
CREATE POLICY ciphertext_identity ON delivery_ciphertexts AS RESTRICTIVE FOR SELECT USING(actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid OR EXISTS(SELECT 1 FROM credentials c WHERE c.actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid AND c.namespace_root='/' AND 'inspect'=ANY(c.permissions) AND c.revoked_at IS NULL));
CREATE POLICY ciphertext_writer ON delivery_ciphertexts AS RESTRICTIVE FOR INSERT WITH CHECK(actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid);
GRANT SELECT,INSERT ON delivery_ciphertexts TO freightctl_runtime;
CREATE FUNCTION freightctl_ciphertext_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE p jsonb;d delivery_intents;k pgp_keys;
BEGIN
 SELECT payload INTO p FROM events WHERE (tenant_id,partner_id,event_id)=(NEW.tenant_id,NEW.partner_id,NEW.prepared_event_id) AND actor_id=NEW.actor_id AND resource_id=NEW.delivery_id AND kind='DeliveryCiphertextPrepared';
 IF p IS NULL OR p->>'delivery_id' IS DISTINCT FROM NEW.delivery_id::text OR p->>'object_id' IS DISTINCT FROM NEW.object_id::text OR p->>'storage_id' IS DISTINCT FROM NEW.storage_id::text OR p->>'size_bytes' IS DISTINCT FROM NEW.size_bytes::text OR p->>'sha256' IS DISTINCT FROM NEW.sha256 OR p->>'source_file_id' IS DISTINCT FROM NEW.source_file_id::text OR p->>'source_sha256' IS DISTINCT FROM NEW.source_sha256 OR p->>'definition_hash' IS DISTINCT FROM NEW.definition_hash OR p->'encryption' IS DISTINCT FROM NEW.encryption OR p->'proof' IS DISTINCT FROM NEW.proof OR p->>'prepared_fence' IS DISTINCT FROM NEW.prepared_fence::text OR p->>'prepared_owner' IS DISTINCT FROM NEW.prepared_owner::text THEN RAISE EXCEPTION 'ciphertext requires its exact event' USING ERRCODE='23514';END IF;
 SELECT * INTO d FROM delivery_intents WHERE (tenant_id,partner_id,delivery_id,actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.delivery_id,NEW.actor_id);
 SELECT * INTO k FROM pgp_keys WHERE (tenant_id,partner_id,key_id,version)=(NEW.tenant_id,NEW.partner_id,(NEW.encryption->'key'->>'id')::uuid,(NEW.encryption->'key'->>'version')::integer);
 IF d.delivery_id IS NULL OR d.state<>'staging' OR d.lease_owner<>NEW.prepared_owner OR d.fence<>NEW.prepared_fence OR d.lease_until<=clock_timestamp() OR d.file_id<>NEW.source_file_id OR d.definition_hash<>NEW.definition_hash OR d.definition->'source'->>'sha256'<>NEW.source_sha256 OR d.definition->>'storage_id'<>NEW.storage_id::text OR d.definition->'encryption' IS DISTINCT FROM NEW.encryption OR NEW.size_bytes>(d.definition->'source'->>'size_bytes')::bigint+(d.definition->'source'->>'size_bytes')::bigint/128+65536 OR k.key_id IS NULL OR k.state<>'active' OR k.definition_hash IS DISTINCT FROM NEW.encryption->'key'->>'hash' OR k.definition->>'purpose' IS DISTINCT FROM 'encrypt' OR (k.valid_until IS NOT NULL AND k.valid_until<=clock_timestamp()) OR NEW.proof->>'primary_fingerprint' IS DISTINCT FROM k.definition->>'fingerprint' OR NEW.proof->>'encryption_fingerprint' IS DISTINCT FROM k.definition->'recipient'->>'encryption_fingerprint' OR NEW.proof->>'profile' IS DISTINCT FROM NEW.encryption->>'profile' OR NEW.proof->>'backend' IS DISTINCT FROM 'ProtonMail/go-crypto/v1.5.2/openpgp/v2' OR NEW.proof->>'cipher' IS DISTINCT FROM 'AES-256' OR NEW.proof->>'compression' IS DISTINCT FROM 'none' OR (NEW.proof->>'valid_until')::timestamptz IS DISTINCT FROM k.valid_until OR NEW.proof->>'encrypted_at' IS NULL OR (NEW.proof->>'encrypted_at')::timestamptz>clock_timestamp() OR NOT (k.definition->'recipient'->'profiles' ? (NEW.encryption->>'profile')) THEN RAISE EXCEPTION 'ciphertext must bind live worker, exact source and approved recipient' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER ciphertext_guard BEFORE INSERT ON delivery_ciphertexts FOR EACH ROW EXECUTE FUNCTION freightctl_ciphertext_guard();
CREATE FUNCTION freightctl_encrypted_delivery_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.definition ? 'workflow_binding' AND NOT EXISTS(SELECT 1 FROM workflow_steps s JOIN workflow_runs r USING(tenant_id,partner_id,run_id) JOIN workflow_revisions w ON (w.tenant_id,w.partner_id,w.workflow_id,w.version)=(r.tenant_id,r.partner_id,r.workflow_id,r.workflow_version) WHERE (s.tenant_id,s.partner_id,s.delivery_id)=(NEW.tenant_id,NEW.partner_id,NEW.delivery_id) AND NEW.definition->'encryption' IS NOT DISTINCT FROM w.definition->'steps'->(s.ordinal-1)->'encryption') THEN RAISE EXCEPTION 'delivery encryption must match approved workflow step' USING ERRCODE='23514';END IF;
 IF NEW.definition ? 'encryption' THEN
  IF NEW.state IN ('draft','queued','staging','publishing') AND NOT EXISTS(SELECT 1 FROM pgp_keys k WHERE (k.tenant_id,k.partner_id,k.key_id,k.version,k.definition_hash,k.state)=(NEW.tenant_id,NEW.partner_id,(NEW.definition->'encryption'->'key'->>'id')::uuid,(NEW.definition->'encryption'->'key'->>'version')::integer,NEW.definition->'encryption'->'key'->>'hash','active') AND k.definition->>'purpose'='encrypt' AND (k.valid_until IS NULL OR k.valid_until>clock_timestamp()) AND k.definition->'recipient'->'profiles' ? (NEW.definition->'encryption'->>'profile')) THEN RAISE EXCEPTION 'delivery requires exact live encryption recipient' USING ERRCODE='23514';END IF;
  IF NEW.state IN ('publishing','succeeded') AND NOT EXISTS(SELECT 1 FROM delivery_ciphertexts c WHERE (c.tenant_id,c.partner_id,c.actor_id,c.delivery_id,c.definition_hash,c.source_file_id,c.source_sha256)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.delivery_id,NEW.definition_hash,NEW.file_id,NEW.definition->'source'->>'sha256') AND c.encryption=NEW.definition->'encryption' AND (NEW.state<>'succeeded' OR (NEW.observation->>'sha256'=c.sha256 AND NEW.observation->>'size_bytes'=c.size_bytes::text))) THEN RAISE EXCEPTION 'encrypted publication requires exact durable ciphertext proof' USING ERRCODE='23514';END IF;
 END IF;RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER encrypted_delivery_guard AFTER INSERT OR UPDATE ON delivery_intents DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION freightctl_encrypted_delivery_guard();
REVOKE ALL ON FUNCTION freightctl_ciphertext_guard(),freightctl_encrypted_delivery_guard() FROM PUBLIC;
