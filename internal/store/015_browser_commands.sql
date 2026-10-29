CREATE TABLE browser_commands(
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,actor_id uuid NOT NULL,request_key text NOT NULL CHECK(request_key ~ '^[A-Za-z0-9._:-]{1,128}$'),
 request_hash text NOT NULL CHECK(request_hash ~ '^[0-9a-f]{64}$'),session_id uuid NOT NULL,event_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,actor_id,request_key),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,session_id) REFERENCES browser_sessions(tenant_id,partner_id,session_id),
 FOREIGN KEY(tenant_id,partner_id,event_id) REFERENCES events(tenant_id,partner_id,event_id)
);
CREATE INDEX browser_command_session_bound ON browser_commands(tenant_id,partner_id,session_id);
ALTER TABLE browser_commands ENABLE ROW LEVEL SECURITY;ALTER TABLE browser_commands FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON browser_commands USING(tenant_id=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND partner_id=nullif(current_setting('freightctl.partner_id',true),'')::uuid AND actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND partner_id=nullif(current_setting('freightctl.partner_id',true),'')::uuid AND actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid);
GRANT SELECT,INSERT ON browser_commands TO freightctl_runtime;
CREATE FUNCTION freightctl_browser_command_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE p jsonb; n integer;
BEGIN
 PERFORM 1 FROM browser_sessions WHERE (tenant_id,partner_id,session_id,actor_id,state)=(NEW.tenant_id,NEW.partner_id,NEW.session_id,NEW.actor_id,'revoked') FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'logout command requires owned revoked session' USING ERRCODE='23514';END IF;
 SELECT count(*) INTO n FROM browser_commands WHERE (tenant_id,partner_id,session_id)=(NEW.tenant_id,NEW.partner_id,NEW.session_id);
 IF n>=16 THEN RAISE EXCEPTION 'browser command receipt budget exceeded' USING ERRCODE='23514';END IF;
 SELECT payload INTO p FROM events WHERE (tenant_id,partner_id,event_id,actor_id,resource_id,kind)=(NEW.tenant_id,NEW.partner_id,NEW.event_id,NEW.actor_id,NEW.session_id,'BrowserLogoutRecorded');
 IF p IS NULL OR p->>'session_id' IS DISTINCT FROM NEW.session_id::text OR p->>'request_key' IS DISTINCT FROM NEW.request_key OR p->>'request_hash' IS DISTINCT FROM NEW.request_hash THEN RAISE EXCEPTION 'logout command requires exact event proof' USING ERRCODE='23514';END IF;RETURN NEW;
END $$;
CREATE TRIGGER browser_command_guard BEFORE INSERT ON browser_commands FOR EACH ROW EXECUTE FUNCTION freightctl_browser_command_guard();
REVOKE ALL ON FUNCTION freightctl_browser_command_guard() FROM PUBLIC;
