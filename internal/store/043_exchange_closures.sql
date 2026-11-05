-- One immutable terminal decision, with a separate actor-private command
-- receipt. The other participant must not learn the original operation key.
CREATE TABLE artifact_exchange_closures(
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,exchange_id uuid NOT NULL,actor_id uuid NOT NULL,
 request_hash text NOT NULL CHECK(request_hash ~ '^[0-9a-f]{64}$'),
 operation text NOT NULL CHECK(operation IN ('cancel','decline')),
 command_hash text NOT NULL CHECK(command_hash ~ '^[0-9a-f]{64}$'),
 participant jsonb NOT NULL CHECK(jsonb_typeof(participant)='object'),event_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,exchange_id),
 FOREIGN KEY(tenant_id,partner_id,exchange_id) REFERENCES artifact_exchanges(tenant_id,partner_id,exchange_id),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,event_id) REFERENCES events(tenant_id,partner_id,event_id)
);
CREATE TABLE artifact_exchange_closure_commands(
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,actor_id uuid NOT NULL,
 request_key text NOT NULL CHECK(request_key ~ '^[A-Za-z0-9._:-]{1,128}$'),
 command_hash text NOT NULL CHECK(command_hash ~ '^[0-9a-f]{64}$'),exchange_id uuid NOT NULL,event_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,actor_id,request_key),UNIQUE(tenant_id,partner_id,exchange_id),
 FOREIGN KEY(tenant_id,partner_id,exchange_id) REFERENCES artifact_exchange_closures(tenant_id,partner_id,exchange_id),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,event_id) REFERENCES events(tenant_id,partner_id,event_id)
);
ALTER TABLE artifact_exchange_closures ENABLE ROW LEVEL SECURITY;
ALTER TABLE artifact_exchange_closures FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON artifact_exchange_closures
 USING(tenant_id=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND partner_id=nullif(current_setting('freightctl.partner_id',true),'')::uuid)
 WITH CHECK(tenant_id=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND partner_id=nullif(current_setting('freightctl.partner_id',true),'')::uuid);
CREATE POLICY exchange_actor ON artifact_exchange_closures AS RESTRICTIVE
 USING(EXISTS(SELECT 1 FROM artifact_exchanges x JOIN exchange_endpoint_versions v ON (v.tenant_id,v.partner_id,v.endpoint_id,v.revision)=(x.tenant_id,x.partner_id,x.endpoint_id,x.endpoint_revision)
 WHERE (x.tenant_id,x.partner_id,x.exchange_id)=(artifact_exchange_closures.tenant_id,artifact_exchange_closures.partner_id,artifact_exchange_closures.exchange_id)
 AND ((x.recipient_actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid AND freightctl_exchange_participant_current(x.tenant_id,x.partner_id,v.definition->'recipient',ARRAY['read','list']))
 OR (x.sender_actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid AND EXISTS(SELECT 1 FROM jsonb_array_elements(v.definition->'senders') s WHERE s->>'actor_id'=x.sender_actor_id::text AND freightctl_exchange_participant_current(x.tenant_id,x.partner_id,s,ARRAY['read','deliver']))))))
 WITH CHECK(actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid);
ALTER TABLE artifact_exchange_closure_commands ENABLE ROW LEVEL SECURITY;
ALTER TABLE artifact_exchange_closure_commands FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON artifact_exchange_closure_commands
 USING(tenant_id=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND partner_id=nullif(current_setting('freightctl.partner_id',true),'')::uuid AND actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid AND EXISTS(SELECT 1 FROM artifact_exchange_closures c WHERE (c.tenant_id,c.partner_id,c.exchange_id)=(artifact_exchange_closure_commands.tenant_id,artifact_exchange_closure_commands.partner_id,artifact_exchange_closure_commands.exchange_id)))
 WITH CHECK(tenant_id=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND partner_id=nullif(current_setting('freightctl.partner_id',true),'')::uuid AND actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid);
REVOKE ALL ON artifact_exchange_closures,artifact_exchange_closure_commands FROM PUBLIC;
GRANT SELECT,INSERT ON artifact_exchange_closures,artifact_exchange_closure_commands TO freightctl_runtime;

CREATE FUNCTION freightctl_artifact_exchange_closure_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE x artifact_exchanges;v exchange_endpoint_versions;e events;binding jsonb;command jsonb;wire text;permissions text[];
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'exchange closures are immutable' USING ERRCODE='23514';END IF;
 IF NEW.actor_id IS DISTINCT FROM nullif(current_setting('freightctl.actor_id',true),'')::uuid THEN RAISE EXCEPTION 'closure actor differs' USING ERRCODE='42501';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id::text||':'||NEW.partner_id::text||':'||NEW.actor_id::text||':exchange-closure-commands',0));
 PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id::text||':'||NEW.partner_id::text||':artifact-exchange:'||NEW.exchange_id::text,0));
 SELECT * INTO x FROM artifact_exchanges WHERE (tenant_id,partner_id,exchange_id,request_hash)=(NEW.tenant_id,NEW.partner_id,NEW.exchange_id,NEW.request_hash);
 IF x.exchange_id IS NULL THEN RAISE EXCEPTION 'closure requires exact exchange' USING ERRCODE='23514';END IF;
 SELECT * INTO v FROM exchange_endpoint_versions WHERE (tenant_id,partner_id,endpoint_id,revision,definition_hash)=(x.tenant_id,x.partner_id,x.endpoint_id,x.endpoint_revision,x.request->'endpoint'->>'hash');
 IF NEW.operation='cancel' AND NEW.actor_id=x.sender_actor_id THEN
  SELECT s INTO binding FROM jsonb_array_elements(v.definition->'senders') s WHERE s->>'actor_id'=NEW.actor_id::text;
  permissions:=ARRAY['read','deliver'];
 ELSIF NEW.operation='decline' AND NEW.actor_id=x.recipient_actor_id THEN
  binding:=v.definition->'recipient';permissions:=ARRAY['read','list'];
 ELSE RAISE EXCEPTION 'closure role is unauthorized' USING ERRCODE='42501';END IF;
 IF binding IS NULL OR NEW.participant IS DISTINCT FROM binding OR freightctl_exchange_participant_current(NEW.tenant_id,NEW.partner_id,binding,permissions) IS DISTINCT FROM true THEN RAISE EXCEPTION 'closure requires original live participant binding' USING ERRCODE='23514';END IF;
 command:=jsonb_build_object('schema_version',1,'exchange_id',NEW.exchange_id,'request_hash',NEW.request_hash,'operation',NEW.operation);
 wire:='{"schema_version":1,"exchange_id":'||to_json(NEW.exchange_id::text)::text||',"request_hash":'||to_json(NEW.request_hash)::text||',"operation":'||to_json(NEW.operation)::text||'}';
 IF NEW.command_hash IS DISTINCT FROM encode(sha256(convert_to(wire,'UTF8')),'hex') THEN RAISE EXCEPTION 'closure requires canonical command hash' USING ERRCODE='23514';END IF;
 SELECT * INTO e FROM events WHERE (tenant_id,partner_id,event_id,actor_id,resource_id,kind)=(NEW.tenant_id,NEW.partner_id,NEW.event_id,NEW.actor_id,NEW.exchange_id,'ArtifactExchangeClosed');
 IF coalesce(e.payload->>'request_key','') !~ '^[A-Za-z0-9._:-]{1,128}$' OR e.payload IS DISTINCT FROM jsonb_build_object('command',command,'command_hash',NEW.command_hash,'request_key',e.payload->>'request_key','participant',binding) THEN RAISE EXCEPTION 'closure requires exact journal event' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER artifact_exchange_closure_guard BEFORE INSERT OR UPDATE OR DELETE ON artifact_exchange_closures FOR EACH ROW EXECUTE FUNCTION freightctl_artifact_exchange_closure_guard();
CREATE FUNCTION freightctl_artifact_exchange_closure_command_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'closure command receipts are immutable' USING ERRCODE='23514';END IF;
 IF NOT EXISTS(SELECT 1 FROM artifact_exchange_closures c JOIN events e ON (e.tenant_id,e.partner_id,e.event_id)=(c.tenant_id,c.partner_id,c.event_id)
 WHERE (c.tenant_id,c.partner_id,c.exchange_id,c.actor_id,c.command_hash,c.event_id)=(NEW.tenant_id,NEW.partner_id,NEW.exchange_id,NEW.actor_id,NEW.command_hash,NEW.event_id)
 AND e.kind='ArtifactExchangeClosed' AND e.payload->>'request_key'=NEW.request_key) THEN RAISE EXCEPTION 'closure command requires exact terminal decision and event' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER artifact_exchange_closure_command_guard BEFORE INSERT OR UPDATE OR DELETE ON artifact_exchange_closure_commands FOR EACH ROW EXECUTE FUNCTION freightctl_artifact_exchange_closure_command_guard();
CREATE FUNCTION freightctl_artifact_exchange_closure_complete() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_TABLE_NAME='artifact_exchange_closures' THEN
  IF NOT EXISTS(SELECT 1 FROM artifact_exchange_closure_commands c WHERE (c.tenant_id,c.partner_id,c.exchange_id,c.event_id,c.actor_id,c.command_hash)=(NEW.tenant_id,NEW.partner_id,NEW.exchange_id,NEW.event_id,NEW.actor_id,NEW.command_hash)) THEN RAISE EXCEPTION 'closure requires transactional command receipt' USING ERRCODE='23514';END IF;
 ELSIF NOT EXISTS(SELECT 1 FROM artifact_exchange_closure_commands c WHERE (c.tenant_id,c.partner_id,c.exchange_id,c.event_id,c.actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.resource_id,NEW.event_id,NEW.actor_id)) THEN RAISE EXCEPTION 'closure event requires transactional decision and receipt' USING ERRCODE='23514';END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER artifact_exchange_closure_complete AFTER INSERT ON events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN(NEW.kind='ArtifactExchangeClosed') EXECUTE FUNCTION freightctl_artifact_exchange_closure_complete();
CREATE CONSTRAINT TRIGGER artifact_exchange_closure_receipt_complete AFTER INSERT ON artifact_exchange_closures DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION freightctl_artifact_exchange_closure_complete();

-- Existing publication/retrieval guards now include the terminal decision.
-- Keep every previous expiry, source, current endpoint and principal check.
CREATE OR REPLACE FUNCTION freightctl_artifact_exchange_principals_current(x artifact_exchanges) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT x.expires_at>clock_timestamp()
 AND NOT EXISTS(SELECT 1 FROM artifact_exchange_closures c WHERE (c.tenant_id,c.partner_id,c.exchange_id)=(x.tenant_id,x.partner_id,x.exchange_id))
 AND freightctl_exchange_actor_source_readable(x.tenant_id,x.partner_id,x.file_id,x.sender_actor_id) AND EXISTS(SELECT 1 FROM exchange_endpoint_heads h WHERE
 (h.tenant_id,h.partner_id,h.endpoint_id,h.revision,h.definition_hash,h.state)=(x.tenant_id,x.partner_id,x.endpoint_id,x.endpoint_revision,x.request->'endpoint'->>'hash','active')
 AND h.definition->'recipient'->>'actor_id'=x.recipient_actor_id::text
 AND freightctl_exchange_participant_current(x.tenant_id,x.partner_id,h.definition->'recipient',ARRAY['read','list'])
 AND EXISTS(SELECT 1 FROM jsonb_array_elements(h.definition->'senders') s WHERE s->>'actor_id'=x.sender_actor_id::text AND freightctl_exchange_participant_current(x.tenant_id,x.partner_id,s,ARRAY['read','deliver'])))
$$;
REVOKE ALL ON FUNCTION freightctl_artifact_exchange_closure_guard(),freightctl_artifact_exchange_closure_command_guard(),freightctl_artifact_exchange_closure_complete() FROM PUBLIC;
