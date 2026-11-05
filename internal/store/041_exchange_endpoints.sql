-- Append-only registered receive views. No retained database is upgraded by
-- adding this migration; application requires the normal authorized init path.
CREATE TABLE exchange_endpoint_versions(
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,endpoint_id uuid NOT NULL,
 revision bigint NOT NULL CHECK(revision>0),
 definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object'),
 definition_wire text NOT NULL CHECK(octet_length(definition_wire)<=16384 AND definition_wire::jsonb=definition),
 definition_hash text NOT NULL CHECK(definition_hash=encode(sha256(convert_to(definition_wire,'UTF8')),'hex')),
 state text NOT NULL CHECK(state IN ('active','revoked')),recorded_by uuid NOT NULL,event_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,endpoint_id,revision),
 FOREIGN KEY(tenant_id,partner_id,recorded_by) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,event_id) REFERENCES events(tenant_id,partner_id,event_id)
);
CREATE TABLE exchange_endpoint_commands(
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,actor_id uuid NOT NULL,
 request_key text NOT NULL CHECK(request_key ~ '^[A-Za-z0-9._:-]{1,128}$'),
 request_hash text NOT NULL CHECK(request_hash ~ '^[0-9a-f]{64}$'),
 endpoint_id uuid NOT NULL,revision bigint NOT NULL,result jsonb NOT NULL CHECK(octet_length(result::text)<=24576),event_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,actor_id,request_key),
 UNIQUE(tenant_id,partner_id,endpoint_id,revision),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,endpoint_id,revision) REFERENCES exchange_endpoint_versions(tenant_id,partner_id,endpoint_id,revision),
 FOREIGN KEY(tenant_id,partner_id,event_id) REFERENCES events(tenant_id,partner_id,event_id)
);
-- A separate head prevents an old participant's visible historical version
-- from masquerading as the current endpoint after a recipient/sender change.
CREATE TABLE exchange_endpoint_heads(
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,endpoint_id uuid NOT NULL,revision bigint NOT NULL,
 definition jsonb NOT NULL,definition_hash text NOT NULL,state text NOT NULL,recorded_by uuid NOT NULL,event_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,endpoint_id),
 FOREIGN KEY(tenant_id,partner_id,endpoint_id,revision) REFERENCES exchange_endpoint_versions(tenant_id,partner_id,endpoint_id,revision)
);

CREATE FUNCTION freightctl_exchange_participant_shape(p jsonb) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
 SELECT coalesce(CASE WHEN jsonb_typeof(p)='object' THEN
 ARRAY(SELECT jsonb_object_keys(p) ORDER BY 1)=ARRAY['actor_id','authority_revision','partner_id','root_policy_digest','tenant_id']::text[]
 AND jsonb_typeof(p->'authority_revision')='number' AND p->>'authority_revision' ~ '^[1-9][0-9]{0,18}$'
 AND (p->>'authority_revision')::numeric<=9223372036854775807
 AND jsonb_typeof(p->'root_policy_digest')='string' AND p->>'root_policy_digest' ~ '^[0-9a-f]{64}$'
 AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['tenant_id','partner_id','actor_id']) k
 WHERE jsonb_typeof(p->k) IS DISTINCT FROM 'string' OR p->>k !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
 ELSE false END,false)
$$;
CREATE FUNCTION freightctl_exchange_participant_wire(p jsonb) RETURNS text LANGUAGE sql IMMUTABLE AS $$
 SELECT '{"tenant_id":'||to_json(p->>'tenant_id')::text||',"partner_id":'||to_json(p->>'partner_id')::text||',"actor_id":'||to_json(p->>'actor_id')::text||',"authority_revision":'||(p->>'authority_revision')||',"root_policy_digest":'||to_json(p->>'root_policy_digest')::text||'}'
$$;
CREATE FUNCTION freightctl_exchange_participant_current(t uuid,p uuid,b jsonb,needed text[]) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT coalesce(freightctl_exchange_participant_shape(b) AND b->>'tenant_id'=t::text AND b->>'partner_id'=p::text AND EXISTS(
 SELECT 1 FROM credentials c WHERE (c.tenant_id,c.partner_id,c.actor_id::text)=(t,p,b->>'actor_id')
 AND c.authority_revision::text=b->>'authority_revision'
 AND encode(sha256(convert_to(c.namespace_root,'UTF8')),'hex')=b->>'root_policy_digest'
 AND c.permissions @> needed AND c.revoked_at IS NULL AND (c.expires_at IS NULL OR c.expires_at>clock_timestamp())),false)
$$;
CREATE FUNCTION freightctl_exchange_endpoint_wire(d jsonb) RETURNS text LANGUAGE sql IMMUTABLE AS $$
 SELECT '{"schema_version":1,"profile":"custody-https-poll-v1","recipient":'||freightctl_exchange_participant_wire(d->'recipient')||',"senders":['||
 (SELECT string_agg(freightctl_exchange_participant_wire(s),',' ORDER BY (s->>'actor_id') COLLATE "C") FROM jsonb_array_elements(d->'senders') s)||']}'
$$;

ALTER TABLE exchange_endpoint_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE exchange_endpoint_versions FORCE ROW LEVEL SECURITY;
ALTER TABLE exchange_endpoint_commands ENABLE ROW LEVEL SECURITY;
ALTER TABLE exchange_endpoint_commands FORCE ROW LEVEL SECURITY;
ALTER TABLE exchange_endpoint_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE exchange_endpoint_heads FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON exchange_endpoint_versions
 USING(tenant_id=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND partner_id=nullif(current_setting('freightctl.partner_id',true),'')::uuid)
 WITH CHECK(tenant_id=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND partner_id=nullif(current_setting('freightctl.partner_id',true),'')::uuid);
CREATE POLICY endpoint_actor ON exchange_endpoint_versions AS RESTRICTIVE
 USING(freightctl_account_manager(tenant_id,partner_id) OR
 (definition->'recipient'->>'actor_id'=current_setting('freightctl.actor_id',true) AND freightctl_exchange_participant_current(tenant_id,partner_id,definition->'recipient',ARRAY['read','list'])) OR
 EXISTS(SELECT 1 FROM jsonb_array_elements(definition->'senders') s WHERE s->>'actor_id'=current_setting('freightctl.actor_id',true) AND freightctl_exchange_participant_current(tenant_id,partner_id,s,ARRAY['read','deliver'])))
 WITH CHECK(freightctl_account_manager(tenant_id,partner_id) AND recorded_by=nullif(current_setting('freightctl.actor_id',true),'')::uuid);
CREATE POLICY scope ON exchange_endpoint_heads
 USING(tenant_id=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND partner_id=nullif(current_setting('freightctl.partner_id',true),'')::uuid)
 WITH CHECK(tenant_id=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND partner_id=nullif(current_setting('freightctl.partner_id',true),'')::uuid);
CREATE POLICY endpoint_actor ON exchange_endpoint_heads AS RESTRICTIVE
 USING(freightctl_account_manager(tenant_id,partner_id) OR
 (definition->'recipient'->>'actor_id'=current_setting('freightctl.actor_id',true) AND freightctl_exchange_participant_current(tenant_id,partner_id,definition->'recipient',ARRAY['read','list'])) OR
 EXISTS(SELECT 1 FROM jsonb_array_elements(definition->'senders') s WHERE s->>'actor_id'=current_setting('freightctl.actor_id',true) AND freightctl_exchange_participant_current(tenant_id,partner_id,s,ARRAY['read','deliver'])))
 WITH CHECK(freightctl_account_manager(tenant_id,partner_id) AND recorded_by=nullif(current_setting('freightctl.actor_id',true),'')::uuid);
CREATE POLICY scope ON exchange_endpoint_commands
 USING(tenant_id=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND partner_id=nullif(current_setting('freightctl.partner_id',true),'')::uuid AND actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid AND freightctl_account_manager(tenant_id,partner_id))
 WITH CHECK(tenant_id=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND partner_id=nullif(current_setting('freightctl.partner_id',true),'')::uuid AND actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid AND freightctl_account_manager(tenant_id,partner_id));
REVOKE ALL ON exchange_endpoint_versions,exchange_endpoint_commands,exchange_endpoint_heads FROM PUBLIC;
GRANT SELECT,INSERT ON exchange_endpoint_versions,exchange_endpoint_commands TO freightctl_runtime;
GRANT SELECT,INSERT,UPDATE ON exchange_endpoint_heads TO freightctl_runtime;

CREATE FUNCTION freightctl_exchange_endpoint_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE e events;d jsonb;prior exchange_endpoint_versions;maximum bigint;actors bigint;unique_actors bigint;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'exchange endpoint versions are immutable' USING ERRCODE='23514';END IF;
 IF NOT freightctl_account_manager(NEW.tenant_id,NEW.partner_id) OR NEW.recorded_by IS DISTINCT FROM nullif(current_setting('freightctl.actor_id',true),'')::uuid THEN RAISE EXCEPTION 'exchange endpoint requires account authority' USING ERRCODE='42501';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id::text||':'||NEW.partner_id::text||':exchange-endpoint:'||NEW.endpoint_id::text,0));
 SELECT * INTO e FROM events WHERE (tenant_id,partner_id,event_id,actor_id,resource_id,kind)=(NEW.tenant_id,NEW.partner_id,NEW.event_id,NEW.recorded_by,NEW.endpoint_id,'ExchangeEndpointRecorded');
 IF e.payload IS DISTINCT FROM jsonb_build_object('id',NEW.endpoint_id,'revision',NEW.revision,'definition',NEW.definition,'definition_hash',NEW.definition_hash,'state',NEW.state,'recorded_by',NEW.recorded_by) THEN RAISE EXCEPTION 'exchange endpoint requires its exact event' USING ERRCODE='23514';END IF;
 SELECT * INTO prior FROM exchange_endpoint_versions WHERE (tenant_id,partner_id,endpoint_id)=(NEW.tenant_id,NEW.partner_id,NEW.endpoint_id) ORDER BY revision DESC LIMIT 1;
 maximum:=coalesce(prior.revision,0);
 IF NEW.revision<>maximum+1 OR maximum=0 AND NEW.state<>'active' OR maximum>0 AND prior.state<>'active' OR NEW.state='revoked' AND (NEW.definition,NEW.definition_wire,NEW.definition_hash) IS DISTINCT FROM (prior.definition,prior.definition_wire,prior.definition_hash) THEN RAISE EXCEPTION 'invalid exchange endpoint revision' USING ERRCODE='23514';END IF;
 d:=NEW.definition;
 IF ARRAY(SELECT jsonb_object_keys(d) ORDER BY 1)<>ARRAY['profile','recipient','schema_version','senders']::text[] OR d->'schema_version'<>'1'::jsonb OR d->>'profile'<>'custody-https-poll-v1' OR jsonb_typeof(d->'senders') IS DISTINCT FROM 'array' OR NOT freightctl_exchange_participant_shape(d->'recipient') THEN RAISE EXCEPTION 'invalid exchange endpoint contract' USING ERRCODE='23514';END IF;
 SELECT count(*),count(DISTINCT s->>'actor_id') INTO actors,unique_actors FROM jsonb_array_elements(d->'senders') s;
 IF actors<1 OR actors>128 OR actors<>unique_actors OR EXISTS(SELECT 1 FROM jsonb_array_elements(d->'senders') s WHERE NOT freightctl_exchange_participant_shape(s) OR (s->>'tenant_id',s->>'partner_id') IS DISTINCT FROM (NEW.tenant_id::text,NEW.partner_id::text)) OR (d->'recipient'->>'tenant_id',d->'recipient'->>'partner_id') IS DISTINCT FROM (NEW.tenant_id::text,NEW.partner_id::text) OR NEW.definition_wire IS DISTINCT FROM freightctl_exchange_endpoint_wire(d) THEN RAISE EXCEPTION 'invalid exchange endpoint bindings' USING ERRCODE='23514';END IF;
 IF NEW.state='active' AND (NOT freightctl_exchange_participant_current(NEW.tenant_id,NEW.partner_id,d->'recipient',ARRAY['read','list']) OR EXISTS(SELECT 1 FROM jsonb_array_elements(d->'senders') s WHERE NOT freightctl_exchange_participant_current(NEW.tenant_id,NEW.partner_id,s,ARRAY['read','deliver']))) THEN RAISE EXCEPTION 'stale exchange participant authority' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER exchange_endpoint_guard BEFORE INSERT OR UPDATE OR DELETE ON exchange_endpoint_versions FOR EACH ROW EXECUTE FUNCTION freightctl_exchange_endpoint_guard();

CREATE FUNCTION freightctl_exchange_endpoint_head_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE v exchange_endpoint_versions;
BEGIN
 IF TG_OP='DELETE' OR NOT freightctl_account_manager(NEW.tenant_id,NEW.partner_id) THEN RAISE EXCEPTION 'exchange endpoint head requires account authority' USING ERRCODE='42501';END IF;
 SELECT * INTO v FROM exchange_endpoint_versions WHERE (tenant_id,partner_id,endpoint_id)=(NEW.tenant_id,NEW.partner_id,NEW.endpoint_id) ORDER BY revision DESC LIMIT 1;
 IF (NEW.revision,NEW.definition,NEW.definition_hash,NEW.state,NEW.recorded_by,NEW.event_id) IS DISTINCT FROM (v.revision,v.definition,v.definition_hash,v.state,v.recorded_by,v.event_id) OR TG_OP='INSERT' AND NEW.revision<>1 OR TG_OP='UPDATE' AND ((NEW.tenant_id,NEW.partner_id,NEW.endpoint_id) IS DISTINCT FROM (OLD.tenant_id,OLD.partner_id,OLD.endpoint_id) OR NEW.revision<>OLD.revision+1) THEN RAISE EXCEPTION 'exchange endpoint head requires exact next journal projection' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER exchange_endpoint_head_guard BEFORE INSERT OR UPDATE OR DELETE ON exchange_endpoint_heads FOR EACH ROW EXECUTE FUNCTION freightctl_exchange_endpoint_head_guard();
CREATE FUNCTION freightctl_exchange_endpoint_project() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 UPDATE exchange_endpoint_heads SET revision=NEW.revision,definition=NEW.definition,definition_hash=NEW.definition_hash,state=NEW.state,recorded_by=NEW.recorded_by,event_id=NEW.event_id
 WHERE (tenant_id,partner_id,endpoint_id)=(NEW.tenant_id,NEW.partner_id,NEW.endpoint_id);
 IF NOT FOUND THEN
  INSERT INTO exchange_endpoint_heads(tenant_id,partner_id,endpoint_id,revision,definition,definition_hash,state,recorded_by,event_id)
  VALUES(NEW.tenant_id,NEW.partner_id,NEW.endpoint_id,NEW.revision,NEW.definition,NEW.definition_hash,NEW.state,NEW.recorded_by,NEW.event_id);
 END IF;
 RETURN NULL;
END $$;
CREATE TRIGGER exchange_endpoint_project AFTER INSERT ON exchange_endpoint_versions FOR EACH ROW EXECUTE FUNCTION freightctl_exchange_endpoint_project();

CREATE FUNCTION freightctl_exchange_endpoint_command_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE e events;v exchange_endpoint_versions;c jsonb;wire text;expected jsonb;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'exchange endpoint receipts are immutable' USING ERRCODE='23514';END IF;
 SELECT * INTO e FROM events WHERE (tenant_id,partner_id,event_id,actor_id,resource_id,kind)=(NEW.tenant_id,NEW.partner_id,NEW.event_id,NEW.actor_id,NEW.endpoint_id,'ExchangeEndpointCommandCompleted');
 SELECT * INTO v FROM exchange_endpoint_versions WHERE (tenant_id,partner_id,endpoint_id,revision)=(NEW.tenant_id,NEW.partner_id,NEW.endpoint_id,NEW.revision);
 c:=e.payload->'command';
 IF c IS DISTINCT FROM jsonb_build_object('operation',c->>'operation','endpoint_id',NEW.endpoint_id,'expected_revision',NEW.revision-1) OR e.payload IS DISTINCT FROM jsonb_build_object('request_key',NEW.request_key,'request_hash',NEW.request_hash,'command',c,'result',NEW.result) THEN RAISE EXCEPTION 'invalid exchange endpoint command shape' USING ERRCODE='23514';END IF;
 IF v.event_id IS NULL OR v.recorded_by<>NEW.actor_id OR e.payload->>'request_key' IS DISTINCT FROM NEW.request_key OR e.payload->>'request_hash' IS DISTINCT FROM NEW.request_hash OR e.payload->'result' IS DISTINCT FROM NEW.result OR c->>'endpoint_id' IS DISTINCT FROM NEW.endpoint_id::text OR c->>'expected_revision' IS DISTINCT FROM (NEW.revision-1)::text OR c->>'operation' NOT IN ('create','replace','revoke') OR ((c->>'operation'='create') IS DISTINCT FROM (NEW.revision=1)) OR ((c->>'operation'='revoke') IS DISTINCT FROM (v.state='revoked')) THEN RAISE EXCEPTION 'exchange endpoint receipt requires exact command' USING ERRCODE='23514';END IF;
 wire:='{"operation":'||to_json(c->>'operation')::text||',"endpoint_id":'||to_json(NEW.endpoint_id::text)::text||',"expected_revision":'||(NEW.revision-1)::text||CASE WHEN c->>'operation'='revoke' THEN '' ELSE ',"definition":'||v.definition_wire END||'}';
 expected:=jsonb_build_object('endpoint',jsonb_build_object('id',v.endpoint_id,'revision',v.revision,'definition',v.definition,'definition_hash',v.definition_hash,'state',v.state,'recorded_by',v.recorded_by,'event_id',v.event_id),'replayed',false);
 IF NEW.request_hash IS DISTINCT FROM encode(sha256(convert_to(wire,'UTF8')),'hex') OR NEW.result IS DISTINCT FROM expected THEN RAISE EXCEPTION 'exchange endpoint receipt meaning or result differs' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER exchange_endpoint_command_guard BEFORE INSERT OR UPDATE OR DELETE ON exchange_endpoint_commands FOR EACH ROW EXECUTE FUNCTION freightctl_exchange_endpoint_command_guard();

CREATE FUNCTION freightctl_exchange_endpoint_complete() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_TABLE_NAME='exchange_endpoint_versions' THEN
  IF NOT EXISTS(SELECT 1 FROM exchange_endpoint_commands c WHERE (c.tenant_id,c.partner_id,c.endpoint_id,c.revision)=(NEW.tenant_id,NEW.partner_id,NEW.endpoint_id,NEW.revision)) THEN RAISE EXCEPTION 'exchange endpoint requires transactional command receipt' USING ERRCODE='23514';END IF;
  IF NOT EXISTS(SELECT 1 FROM exchange_endpoint_heads h WHERE (h.tenant_id,h.partner_id,h.endpoint_id,h.revision)=(NEW.tenant_id,NEW.partner_id,NEW.endpoint_id,NEW.revision)) THEN RAISE EXCEPTION 'exchange endpoint requires current head projection' USING ERRCODE='23514';END IF;
 ELSIF NEW.kind='ExchangeEndpointRecorded' THEN
  IF NOT EXISTS(SELECT 1 FROM exchange_endpoint_versions v WHERE (v.tenant_id,v.partner_id,v.event_id)=(NEW.tenant_id,NEW.partner_id,NEW.event_id)) THEN RAISE EXCEPTION 'exchange endpoint event requires exact projection' USING ERRCODE='23514';END IF;
 ELSIF NEW.kind='ExchangeEndpointCommandCompleted' THEN
  IF NOT EXISTS(SELECT 1 FROM exchange_endpoint_commands c WHERE (c.tenant_id,c.partner_id,c.event_id)=(NEW.tenant_id,NEW.partner_id,NEW.event_id)) THEN RAISE EXCEPTION 'exchange endpoint command event requires exact receipt' USING ERRCODE='23514';END IF;
 END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER exchange_endpoint_complete AFTER INSERT ON exchange_endpoint_versions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION freightctl_exchange_endpoint_complete();
CREATE CONSTRAINT TRIGGER exchange_endpoint_events_complete AFTER INSERT ON events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN(NEW.kind IN ('ExchangeEndpointRecorded','ExchangeEndpointCommandCompleted')) EXECUTE FUNCTION freightctl_exchange_endpoint_complete();
REVOKE ALL ON FUNCTION freightctl_exchange_participant_shape(jsonb),freightctl_exchange_participant_wire(jsonb),freightctl_exchange_participant_current(uuid,uuid,jsonb,text[]),freightctl_exchange_endpoint_wire(jsonb),freightctl_exchange_endpoint_guard(),freightctl_exchange_endpoint_command_guard(),freightctl_exchange_endpoint_complete() FROM PUBLIC;
REVOKE ALL ON FUNCTION freightctl_exchange_endpoint_head_guard(),freightctl_exchange_endpoint_project() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION freightctl_exchange_participant_shape(jsonb),freightctl_exchange_participant_wire(jsonb),freightctl_exchange_participant_current(uuid,uuid,jsonb,text[]),freightctl_exchange_endpoint_wire(jsonb) TO freightctl_runtime;
