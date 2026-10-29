CREATE TABLE browser_sessions (
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,actor_id uuid NOT NULL,session_id uuid NOT NULL,
 secret_hash text NOT NULL CHECK(secret_hash ~ '^[0-9a-f]{64}$'),credential_hash text NOT NULL CHECK(credential_hash ~ '^[0-9a-f]{64}$'),
 request_key text NOT NULL CHECK(request_key ~ '^[A-Za-z0-9._:-]{1,128}$'),
 namespace_root text NOT NULL,authority_revision bigint NOT NULL CHECK(authority_revision>0),
 lifetime_seconds integer NOT NULL CHECK(lifetime_seconds BETWEEN 1 AND 600),expires_at timestamptz NOT NULL,state text NOT NULL CHECK(state IN ('active','revoked')),
 revision bigint NOT NULL CHECK(revision>0),changed_event_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,session_id),
 UNIQUE(tenant_id,partner_id,secret_hash),UNIQUE(tenant_id,partner_id,actor_id,request_key),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,changed_event_id) REFERENCES events(tenant_id,partner_id,event_id)
);
CREATE INDEX browser_session_admission ON browser_sessions(tenant_id,partner_id,actor_id,expires_at) WHERE state='active';
CREATE INDEX browser_upload_listing ON upload_sessions(tenant_id,partner_id,actor_id,authority_revision,namespace_root,upload_id);
ALTER TABLE browser_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE browser_sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON browser_sessions USING(tenant_id=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND partner_id=nullif(current_setting('freightctl.partner_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND partner_id=nullif(current_setting('freightctl.partner_id',true),'')::uuid);
CREATE POLICY browser_session_reader ON browser_sessions AS RESTRICTIVE FOR SELECT USING(actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid OR secret_hash=nullif(current_setting('freightctl.browser_session_hash',true),''));
CREATE POLICY browser_session_writer ON browser_sessions AS RESTRICTIVE FOR INSERT WITH CHECK(actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid);
CREATE POLICY browser_session_update ON browser_sessions AS RESTRICTIVE FOR UPDATE USING(actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid) WITH CHECK(actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid);
GRANT SELECT,INSERT,UPDATE ON browser_sessions TO freightctl_runtime;
CREATE FUNCTION freightctl_browser_session_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE p jsonb; e events; active_count integer;
BEGIN
 SELECT * INTO e FROM events WHERE (tenant_id,partner_id,event_id)=(NEW.tenant_id,NEW.partner_id,NEW.changed_event_id) AND actor_id=NEW.actor_id AND actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid AND resource_id=NEW.session_id AND kind='BrowserSessionChanged';p:=e.payload;
 IF p IS NULL OR p->>'id' IS DISTINCT FROM NEW.session_id::text OR p->>'secret_sha256' IS DISTINCT FROM NEW.secret_hash OR p->>'credential_sha256' IS DISTINCT FROM NEW.credential_hash OR p->>'request_key' IS DISTINCT FROM NEW.request_key OR p->>'namespace_root' IS DISTINCT FROM NEW.namespace_root OR p->>'authority_revision' IS DISTINCT FROM NEW.authority_revision::text OR p->>'lifetime_seconds' IS DISTINCT FROM NEW.lifetime_seconds::text OR (p->>'expires_at')::timestamptz IS DISTINCT FROM NEW.expires_at OR p->>'state' IS DISTINCT FROM NEW.state OR p->>'revision' IS DISTINCT FROM NEW.revision::text THEN RAISE EXCEPTION 'browser session requires exact event proof' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN
  PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id::text||':'||NEW.partner_id::text||':'||NEW.actor_id::text||':browser-sessions',0));
  SELECT count(*) INTO active_count FROM browser_sessions WHERE (tenant_id,partner_id,actor_id,state)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,'active') AND expires_at>clock_timestamp();
  IF NEW.state<>'active' OR NEW.revision<>1 OR NEW.expires_at<=clock_timestamp() OR NEW.expires_at>e.happened_at+make_interval(secs=>NEW.lifetime_seconds) OR active_count>=8 OR NOT EXISTS(SELECT 1 FROM credentials c WHERE (c.tenant_id,c.partner_id,c.actor_id,c.namespace_root,c.authority_revision,c.token_hash)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.namespace_root,NEW.authority_revision,NEW.credential_hash) AND c.revoked_at IS NULL) THEN RAISE EXCEPTION 'invalid browser session admission' USING ERRCODE='23514';END IF;
 ELSE
  IF (NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.session_id,NEW.secret_hash,NEW.credential_hash,NEW.request_key,NEW.namespace_root,NEW.authority_revision,NEW.lifetime_seconds,NEW.expires_at) IS DISTINCT FROM (OLD.tenant_id,OLD.partner_id,OLD.actor_id,OLD.session_id,OLD.secret_hash,OLD.credential_hash,OLD.request_key,OLD.namespace_root,OLD.authority_revision,OLD.lifetime_seconds,OLD.expires_at) OR OLD.state<>'active' OR NEW.state<>'revoked' OR NEW.revision<>OLD.revision+1 THEN RAISE EXCEPTION 'browser session authority and expiry are immutable' USING ERRCODE='23514';END IF;
 END IF;RETURN NEW;
END $$;
CREATE TRIGGER browser_session_guard BEFORE INSERT OR UPDATE ON browser_sessions FOR EACH ROW EXECUTE FUNCTION freightctl_browser_session_guard();
REVOKE ALL ON FUNCTION freightctl_browser_session_guard() FROM PUBLIC;
