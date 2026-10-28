CREATE TABLE tenants (
    tenant_id uuid PRIMARY KEY
);
CREATE TABLE partners (
    tenant_id uuid NOT NULL REFERENCES tenants(tenant_id),
    partner_id uuid NOT NULL,
    PRIMARY KEY (tenant_id, partner_id)
);
CREATE TABLE credentials (
    tenant_id uuid NOT NULL,
    partner_id uuid NOT NULL,
    actor_id uuid NOT NULL,
    token_hash text NOT NULL CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    revoked_at timestamptz,
    PRIMARY KEY (tenant_id, partner_id, actor_id),
    UNIQUE (tenant_id, partner_id, token_hash),
    FOREIGN KEY (tenant_id, partner_id) REFERENCES partners(tenant_id, partner_id)
);
CREATE TABLE events (
    tenant_id uuid NOT NULL,
    partner_id uuid NOT NULL,
    event_id uuid NOT NULL,
    actor_id uuid NOT NULL,
    kind text NOT NULL,
    resource_id uuid NOT NULL,
    payload jsonb NOT NULL,
    happened_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, event_id),
    UNIQUE (tenant_id, partner_id, event_id),
    FOREIGN KEY (tenant_id, partner_id, actor_id) REFERENCES credentials(tenant_id, partner_id, actor_id)
);
CREATE TABLE files (
    tenant_id uuid NOT NULL,
    partner_id uuid NOT NULL,
    file_id uuid NOT NULL,
    size_bytes bigint NOT NULL CHECK (size_bytes >= 0),
    sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    policy text NOT NULL CHECK (policy = 'integrity-only-v1'),
    accepted_event_id uuid NOT NULL,
    PRIMARY KEY (tenant_id, partner_id, file_id),
    FOREIGN KEY (tenant_id, partner_id, accepted_event_id) REFERENCES events(tenant_id, partner_id, event_id)
);
CREATE TABLE idempotency (
    tenant_id uuid NOT NULL,
    partner_id uuid NOT NULL,
    request_key text NOT NULL CHECK (length(request_key) BETWEEN 1 AND 128),
    request_hash text NOT NULL CHECK (request_hash ~ '^[0-9a-f]{64}$'),
    file_id uuid NOT NULL,
    PRIMARY KEY (tenant_id, partner_id, request_key),
    FOREIGN KEY (tenant_id, partner_id, file_id) REFERENCES files(tenant_id, partner_id, file_id)
);
CREATE INDEX events_scope_time ON events(tenant_id, partner_id, happened_at, event_id);

ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON tenants USING (tenant_id = nullif(current_setting('freightctl.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('freightctl.tenant_id', true), '')::uuid);

DO $$ DECLARE t text; BEGIN
    FOREACH t IN ARRAY ARRAY['partners','credentials','events','files','idempotency'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY scope ON %I USING (tenant_id = nullif(current_setting(''freightctl.tenant_id'', true), '''')::uuid AND partner_id = nullif(current_setting(''freightctl.partner_id'', true), '''')::uuid) WITH CHECK (tenant_id = nullif(current_setting(''freightctl.tenant_id'', true), '''')::uuid AND partner_id = nullif(current_setting(''freightctl.partner_id'', true), '''')::uuid)', t);
    END LOOP;
END $$;

REVOKE ALL ON tenants,partners,credentials,events,files,idempotency FROM PUBLIC;
GRANT SELECT ON tenants,partners,credentials,events,files,idempotency TO freightctl_runtime;
GRANT INSERT ON events,files,idempotency TO freightctl_runtime;
