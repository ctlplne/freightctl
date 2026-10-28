ALTER TABLE credentials ADD COLUMN permissions text[] NOT NULL
    DEFAULT ARRAY['read','write','list','manage_paths','inspect','audit_read','admin']::text[];
ALTER TABLE credentials ADD COLUMN namespace_root text NOT NULL DEFAULT '/';
ALTER TABLE credentials ADD COLUMN authority_revision bigint NOT NULL DEFAULT 1 CHECK (authority_revision>0);
ALTER TABLE credentials ADD CONSTRAINT credential_permissions_valid CHECK (
    cardinality(permissions)<=7 AND permissions <@ ARRAY['read','write','list','manage_paths','inspect','audit_read','admin']::text[]);
ALTER TABLE credentials ADD CONSTRAINT credential_root_bounded CHECK (left(namespace_root,1)='/' AND octet_length(namespace_root)<=1024);
CREATE FUNCTION freightctl_credential_revision() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (NEW.permissions,NEW.namespace_root,NEW.revoked_at) IS DISTINCT FROM (OLD.permissions,OLD.namespace_root,OLD.revoked_at) THEN
        NEW.authority_revision:=OLD.authority_revision+1;
    ELSIF NEW.authority_revision<>OLD.authority_revision THEN
        RAISE EXCEPTION 'authority revision cannot be assigned independently' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER credential_revision BEFORE UPDATE ON credentials FOR EACH ROW EXECUTE FUNCTION freightctl_credential_revision();

ALTER TABLE idempotency ADD COLUMN actor_id uuid;
UPDATE idempotency i SET actor_id=e.actor_id FROM files f JOIN events e
 ON (e.tenant_id,e.partner_id,e.event_id)=(f.tenant_id,f.partner_id,f.accepted_event_id)
 WHERE (i.tenant_id,i.partner_id,i.file_id)=(f.tenant_id,f.partner_id,f.file_id);
ALTER TABLE idempotency ALTER COLUMN actor_id SET NOT NULL;
ALTER TABLE idempotency ADD FOREIGN KEY (tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id);
ALTER TABLE idempotency DROP CONSTRAINT idempotency_pkey;
ALTER TABLE idempotency ADD PRIMARY KEY(tenant_id,partner_id,actor_id,request_key);
CREATE POLICY identity_scope ON idempotency AS RESTRICTIVE
 USING(actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid)
 WITH CHECK(actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid);
CREATE OR REPLACE FUNCTION freightctl_check_idempotency_event() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM files f JOIN events e ON (e.tenant_id,e.partner_id,e.event_id)=(f.tenant_id,f.partner_id,f.accepted_event_id)
 WHERE (f.tenant_id,f.partner_id,f.file_id,e.actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.file_id,NEW.actor_id)
 AND ((e.payload->>'request_key'=NEW.request_key AND e.payload->>'request_hash'=NEW.request_hash)
 OR EXISTS(SELECT 1 FROM events c,jsonb_array_elements(CASE WHEN jsonb_typeof(c.payload->'keys')='array' THEN c.payload->'keys' ELSE '[]'::jsonb END) k
 WHERE (c.tenant_id,c.partner_id,c.resource_id)=(NEW.tenant_id,NEW.partner_id,NEW.file_id) AND c.kind='FileIdempotencyCheckpointed'
 AND k->>'key'=NEW.request_key AND k->>'request_hash'=NEW.request_hash))) THEN
 RAISE EXCEPTION 'idempotency requires its actor and exact journaled meaning' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;

CREATE TABLE namespace_entries (
    tenant_id uuid NOT NULL,
    partner_id uuid NOT NULL,
    entry_id uuid NOT NULL,
    path text COLLATE "C" NOT NULL,
    parent_path text COLLATE "C" NOT NULL,
    kind text NOT NULL CHECK (kind IN ('file','dir')),
    file_id uuid,
    owner_actor_id uuid NOT NULL,
    mode integer NOT NULL CHECK (mode BETWEEN 0 AND 511),
    modified_at timestamptz NOT NULL,
    revision bigint NOT NULL CHECK (revision>0),
    deleted boolean NOT NULL DEFAULT false,
    changed_event_id uuid NOT NULL,
    PRIMARY KEY (tenant_id,partner_id,entry_id),
    FOREIGN KEY (tenant_id,partner_id,owner_actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
    FOREIGN KEY (tenant_id,partner_id,file_id) REFERENCES files(tenant_id,partner_id,file_id),
    FOREIGN KEY (tenant_id,partner_id,changed_event_id) REFERENCES events(tenant_id,partner_id,event_id),
    CHECK ((kind='file')=(file_id IS NOT NULL)),
    CHECK (path<>'/' AND left(path,1)='/' AND right(path,1)<>'/' AND octet_length(path)<=1024),
    CHECK (position('//' IN path)=0 AND path !~ '(^|/)[.]{1,2}(/|$)' AND path !~ '[[:cntrl:]:\\]')
);
CREATE UNIQUE INDEX namespace_live_path ON namespace_entries(tenant_id,partner_id,path) WHERE NOT deleted;
CREATE INDEX namespace_parent ON namespace_entries(tenant_id,partner_id,parent_path,path) WHERE NOT deleted;
CREATE TABLE namespace_revisions (
    tenant_id uuid NOT NULL,
    partner_id uuid NOT NULL,
    entry_id uuid NOT NULL,
    revision bigint NOT NULL,
    file_id uuid NOT NULL,
    published_event_id uuid NOT NULL,
    PRIMARY KEY (tenant_id,partner_id,entry_id,revision),
    FOREIGN KEY (tenant_id,partner_id,entry_id) REFERENCES namespace_entries(tenant_id,partner_id,entry_id),
    FOREIGN KEY (tenant_id,partner_id,file_id) REFERENCES files(tenant_id,partner_id,file_id),
    FOREIGN KEY (tenant_id,partner_id,published_event_id) REFERENCES events(tenant_id,partner_id,event_id)
);
CREATE INDEX namespace_file_revisions ON namespace_revisions(tenant_id,partner_id,file_id);
CREATE TABLE namespace_commands (
    tenant_id uuid NOT NULL,
    partner_id uuid NOT NULL,
    actor_id uuid NOT NULL,
    request_key text NOT NULL CHECK (length(request_key) BETWEEN 1 AND 128),
    request_hash text NOT NULL CHECK (request_hash ~ '^[0-9a-f]{64}$'),
    result jsonb NOT NULL,
    completed_event_id uuid NOT NULL,
    PRIMARY KEY (tenant_id,partner_id,actor_id,request_key),
    FOREIGN KEY (tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
    FOREIGN KEY (tenant_id,partner_id,completed_event_id) REFERENCES events(tenant_id,partner_id,event_id)
);
CREATE TABLE ssh_keys (
    tenant_id uuid NOT NULL,
    partner_id uuid NOT NULL,
    key_id uuid NOT NULL,
    actor_id uuid NOT NULL,
    fingerprint text NOT NULL CHECK (length(fingerprint) BETWEEN 8 AND 100),
    public_wire bytea NOT NULL CHECK (octet_length(public_wire) BETWEEN 16 AND 16384),
    revoked_at timestamptz,
    changed_event_id uuid NOT NULL,
    PRIMARY KEY (tenant_id,partner_id,key_id),
    UNIQUE (tenant_id,partner_id,fingerprint),
    FOREIGN KEY (tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
    FOREIGN KEY (tenant_id,partner_id,changed_event_id) REFERENCES events(tenant_id,partner_id,event_id)
);

DO $$ DECLARE t text; BEGIN
    FOREACH t IN ARRAY ARRAY['namespace_entries','namespace_revisions','namespace_commands','ssh_keys'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',t);
        EXECUTE format('CREATE POLICY scope ON %I USING (tenant_id=nullif(current_setting(''freightctl.tenant_id'',true),'''')::uuid AND partner_id=nullif(current_setting(''freightctl.partner_id'',true),'''')::uuid) WITH CHECK (tenant_id=nullif(current_setting(''freightctl.tenant_id'',true),'''')::uuid AND partner_id=nullif(current_setting(''freightctl.partner_id'',true),'''')::uuid)',t);
    END LOOP;
END $$;
CREATE POLICY identity_scope ON namespace_commands AS RESTRICTIVE
 USING(actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid)
 WITH CHECK(actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid);
GRANT SELECT ON namespace_entries,namespace_revisions,namespace_commands,ssh_keys TO freightctl_runtime;
GRANT INSERT,UPDATE ON namespace_entries TO freightctl_runtime;
GRANT INSERT ON namespace_revisions,namespace_commands TO freightctl_runtime;

CREATE FUNCTION freightctl_namespace_event() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE event_kind text;
BEGIN
    SELECT kind INTO event_kind FROM events WHERE (tenant_id,partner_id,event_id)=(NEW.tenant_id,NEW.partner_id,NEW.changed_event_id);
    IF TG_OP='INSERT' AND (NEW.revision<>1 OR NEW.deleted OR event_kind<>CASE WHEN NEW.kind='file' THEN 'PathPublished' ELSE 'PathCreated' END) THEN
        RAISE EXCEPTION 'invalid namespace creation event' USING ERRCODE='23514';
    END IF;
    IF TG_OP='UPDATE' AND (NEW.entry_id<>OLD.entry_id OR NEW.owner_actor_id<>OLD.owner_actor_id OR NEW.revision<>OLD.revision+1) THEN
        RAISE EXCEPTION 'namespace revision or ownership changed without a valid transition' USING ERRCODE='23514';
    END IF;
    IF TG_OP='UPDATE' AND (OLD.deleted OR NEW.kind<>OLD.kind OR
        (event_kind='PathRemoved' AND (NOT NEW.deleted OR NEW.path<>OLD.path OR NEW.file_id IS DISTINCT FROM OLD.file_id OR NEW.mode<>OLD.mode OR NEW.modified_at<>OLD.modified_at)) OR
        (event_kind='PathMoved' AND (NEW.deleted OR NEW.file_id IS DISTINCT FROM OLD.file_id OR NEW.mode<>OLD.mode OR NEW.modified_at<>OLD.modified_at)) OR
        (event_kind='PathAttrsChanged' AND (NEW.deleted OR NEW.path<>OLD.path OR NEW.file_id IS DISTINCT FROM OLD.file_id)) OR
        (event_kind='PathPublished' AND (NEW.deleted OR NEW.path<>OLD.path OR NEW.kind<>'file')) OR
        event_kind NOT IN ('PathRemoved','PathMoved','PathAttrsChanged','PathPublished')) THEN
        RAISE EXCEPTION 'invalid namespace transition event' USING ERRCODE='23514';
    END IF;
    IF NEW.parent_path<>coalesce(nullif(regexp_replace(NEW.path,'/[^/]+$',''),''),'/') OR NOT EXISTS (
        SELECT 1 FROM events e WHERE (e.tenant_id,e.partner_id,e.event_id)=(NEW.tenant_id,NEW.partner_id,NEW.changed_event_id)
          AND e.resource_id=NEW.entry_id AND e.kind IN ('PathCreated','PathPublished','PathMoved','PathAttrsChanged','PathRemoved')
          AND e.payload->>'path'=NEW.path AND e.payload->>'kind'=NEW.kind
          AND e.payload->>'file_id'=coalesce(NEW.file_id::text,'')
          AND e.payload->>'owner_actor_id'=NEW.owner_actor_id::text
          AND e.payload->>'mode'=NEW.mode::text AND e.payload->>'revision'=NEW.revision::text
          AND e.payload->>'deleted'=NEW.deleted::text
          AND e.payload->>'modified_unix_us'=(extract(epoch FROM NEW.modified_at)*1000000)::bigint::text
    ) THEN
        RAISE EXCEPTION 'namespace projection requires its exact journal event' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER namespace_event BEFORE INSERT OR UPDATE ON namespace_entries FOR EACH ROW EXECUTE FUNCTION freightctl_namespace_event();

CREATE FUNCTION freightctl_namespace_revision() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.kind='file' AND NOT NEW.deleted AND EXISTS(SELECT 1 FROM events WHERE tenant_id=NEW.tenant_id AND event_id=NEW.changed_event_id AND kind='PathPublished') THEN
        INSERT INTO namespace_revisions VALUES(NEW.tenant_id,NEW.partner_id,NEW.entry_id,NEW.revision,NEW.file_id,NEW.changed_event_id);
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER namespace_revision AFTER INSERT OR UPDATE ON namespace_entries FOR EACH ROW EXECUTE FUNCTION freightctl_namespace_revision();
CREATE FUNCTION freightctl_namespace_history_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS(SELECT 1 FROM namespace_entries n JOIN events e ON (e.tenant_id,e.partner_id,e.event_id)=(n.tenant_id,n.partner_id,n.changed_event_id)
      WHERE (n.tenant_id,n.partner_id,n.entry_id,n.revision,n.file_id,n.changed_event_id)=(NEW.tenant_id,NEW.partner_id,NEW.entry_id,NEW.revision,NEW.file_id,NEW.published_event_id) AND e.kind='PathPublished') THEN
        RAISE EXCEPTION 'namespace history requires its publication event' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER namespace_history_guard BEFORE INSERT ON namespace_revisions FOR EACH ROW EXECUTE FUNCTION freightctl_namespace_history_guard();
CREATE FUNCTION freightctl_namespace_command_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS(SELECT 1 FROM events e WHERE (e.tenant_id,e.partner_id,e.event_id)=(NEW.tenant_id,NEW.partner_id,NEW.completed_event_id)
      AND e.actor_id=NEW.actor_id AND e.kind='NamespaceCommandCompleted' AND e.payload->>'request_key'=NEW.request_key AND e.payload->>'request_hash'=NEW.request_hash AND e.payload->'result'=NEW.result) THEN
        RAISE EXCEPTION 'namespace receipt requires its exact journal event' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER namespace_command_guard BEFORE INSERT ON namespace_commands FOR EACH ROW EXECUTE FUNCTION freightctl_namespace_command_guard();
CREATE FUNCTION freightctl_ssh_key_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='UPDATE' AND (NEW.key_id<>OLD.key_id OR NEW.actor_id<>OLD.actor_id OR NEW.public_wire<>OLD.public_wire OR NEW.fingerprint<>OLD.fingerprint OR OLD.revoked_at IS NOT NULL) THEN
        RAISE EXCEPTION 'SSH key identity is immutable' USING ERRCODE='23514';
    END IF;
    IF NOT EXISTS(SELECT 1 FROM events e WHERE (e.tenant_id,e.partner_id,e.event_id)=(NEW.tenant_id,NEW.partner_id,NEW.changed_event_id)
      AND e.resource_id=NEW.key_id AND e.kind=CASE WHEN NEW.revoked_at IS NULL THEN 'SSHKeyEnrolled' ELSE 'SSHKeyRevoked' END
      AND e.payload->>'actor_id'=NEW.actor_id::text AND e.payload->>'fingerprint'=NEW.fingerprint
      AND e.payload->>'public_sha256'=encode(sha256(NEW.public_wire),'hex')) THEN
        RAISE EXCEPTION 'SSH key state requires its exact journal event' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER ssh_key_guard BEFORE INSERT OR UPDATE ON ssh_keys FOR EACH ROW EXECUTE FUNCTION freightctl_ssh_key_guard();
REVOKE ALL ON FUNCTION freightctl_credential_revision(),freightctl_namespace_event(),freightctl_namespace_revision(),freightctl_namespace_history_guard(),freightctl_namespace_command_guard(),freightctl_ssh_key_guard() FROM PUBLIC;
