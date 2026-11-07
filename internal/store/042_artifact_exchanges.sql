CREATE TABLE artifact_exchanges(
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,exchange_id uuid NOT NULL,
 sender_actor_id uuid NOT NULL,recipient_actor_id uuid NOT NULL,file_id uuid NOT NULL,
 endpoint_id uuid NOT NULL,endpoint_revision bigint NOT NULL,
 request jsonb NOT NULL CHECK(jsonb_typeof(request)='object'),
 request_wire text NOT NULL CHECK(octet_length(request_wire)<=16384 AND request_wire::jsonb=request),
 request_hash text NOT NULL CHECK(request_hash=encode(sha256(convert_to(request_wire,'UTF8')),'hex')),
 storage_id uuid NOT NULL,expires_at timestamptz NOT NULL CHECK(isfinite(expires_at)),event_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,exchange_id),
 FOREIGN KEY(tenant_id,partner_id,sender_actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,recipient_actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,file_id) REFERENCES files(tenant_id,partner_id,file_id),
 FOREIGN KEY(tenant_id,partner_id,endpoint_id,endpoint_revision) REFERENCES exchange_endpoint_versions(tenant_id,partner_id,endpoint_id,revision),
 FOREIGN KEY(tenant_id,partner_id,event_id) REFERENCES events(tenant_id,partner_id,event_id)
);
CREATE INDEX artifact_exchange_sender_open ON artifact_exchanges(tenant_id,partner_id,sender_actor_id,expires_at);
CREATE INDEX artifact_exchange_incoming ON artifact_exchanges(tenant_id,partner_id,recipient_actor_id,endpoint_id,endpoint_revision,exchange_id);
CREATE TABLE artifact_exchange_commands(
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,actor_id uuid NOT NULL,
 request_key text NOT NULL CHECK(request_key ~ '^[A-Za-z0-9._:-]{1,128}$'),
 request_hash text NOT NULL CHECK(request_hash ~ '^[0-9a-f]{64}$'),exchange_id uuid NOT NULL,
 result jsonb NOT NULL CHECK(octet_length(result::text)<=24576),event_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,actor_id,request_key),UNIQUE(tenant_id,partner_id,exchange_id),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,exchange_id) REFERENCES artifact_exchanges(tenant_id,partner_id,exchange_id),
 FOREIGN KEY(tenant_id,partner_id,event_id) REFERENCES events(tenant_id,partner_id,event_id)
);
ALTER TABLE artifact_exchanges ENABLE ROW LEVEL SECURITY;
ALTER TABLE artifact_exchanges FORCE ROW LEVEL SECURITY;
ALTER TABLE artifact_exchange_commands ENABLE ROW LEVEL SECURITY;
ALTER TABLE artifact_exchange_commands FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON artifact_exchanges
 USING(tenant_id=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND partner_id=nullif(current_setting('freightctl.partner_id',true),'')::uuid)
 WITH CHECK(tenant_id=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND partner_id=nullif(current_setting('freightctl.partner_id',true),'')::uuid);
CREATE POLICY exchange_actor ON artifact_exchanges AS RESTRICTIVE
 USING(nullif(current_setting('freightctl.actor_id',true),'')::uuid IN (sender_actor_id,recipient_actor_id))
 WITH CHECK(sender_actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid);
CREATE POLICY scope ON artifact_exchange_commands
 USING(tenant_id=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND partner_id=nullif(current_setting('freightctl.partner_id',true),'')::uuid AND actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid)
 WITH CHECK(tenant_id=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND partner_id=nullif(current_setting('freightctl.partner_id',true),'')::uuid AND actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid);
REVOKE ALL ON artifact_exchanges,artifact_exchange_commands FROM PUBLIC;
GRANT SELECT,INSERT ON artifact_exchanges,artifact_exchange_commands TO freightctl_runtime;

-- Independent SQL source check mirrors existing file access: own unpublished
-- raw revision, root administrator, or a readable live namespace history with
-- traversable ancestors. No incoming view is a source permission by itself.
CREATE FUNCTION freightctl_exchange_actor_source_readable(t uuid,p uuid,f uuid,a uuid) RETURNS boolean LANGUAGE plpgsql STABLE AS $$
DECLARE c credentials;n namespace_entries;d namespace_entries;parent text;candidate_count integer;bits integer;depth integer;valid boolean;
BEGIN
 IF NOT EXISTS(SELECT 1 FROM files WHERE (tenant_id,partner_id,file_id)=(t,p,f)) THEN RETURN false;END IF;
 SELECT * INTO c FROM credentials WHERE (tenant_id,partner_id,actor_id)=(t,p,a);
 IF c.actor_id IS NULL OR c.revoked_at IS NOT NULL OR c.expires_at<=clock_timestamp() OR NOT c.permissions @> ARRAY['read','deliver']::text[] THEN RETURN false;END IF;
 IF c.namespace_root='/' AND 'admin'=ANY(c.permissions) THEN RETURN true;END IF;
 IF c.namespace_root='/' AND EXISTS(SELECT 1 FROM files v JOIN events e ON (e.tenant_id,e.partner_id,e.event_id)=(v.tenant_id,v.partner_id,v.accepted_event_id)
 WHERE (v.tenant_id,v.partner_id,v.file_id,e.actor_id)=(t,p,f,c.actor_id) AND NOT EXISTS(SELECT 1 FROM namespace_revisions r WHERE (r.tenant_id,r.partner_id,r.file_id)=(t,p,f))) THEN RETURN true;END IF;
 SELECT count(*) INTO candidate_count FROM (SELECT 1 FROM namespace_entries v WHERE (v.tenant_id,v.partner_id)=(t,p) AND NOT v.deleted
 AND EXISTS(SELECT 1 FROM namespace_revisions r WHERE (r.tenant_id,r.partner_id,r.entry_id,r.file_id)=(t,p,v.entry_id,f)) LIMIT 1001) candidates;
 IF candidate_count>1000 THEN RETURN false;END IF;
 FOR n IN SELECT * FROM namespace_entries v WHERE (v.tenant_id,v.partner_id)=(t,p) AND NOT v.deleted AND EXISTS(SELECT 1 FROM namespace_revisions r WHERE (r.tenant_id,r.partner_id,r.entry_id,r.file_id)=(t,p,v.entry_id,f)) ORDER BY v.path COLLATE "C" LIMIT 1000 LOOP
  IF c.namespace_root<>'/' AND n.path<>c.namespace_root AND left(n.path,length(c.namespace_root)+1)<>c.namespace_root||'/' THEN CONTINUE;END IF;
  bits:=CASE WHEN n.owner_actor_id=c.actor_id THEN (n.mode>>6)&7 ELSE (n.mode>>3)&7 END;
  IF NOT 'admin'=ANY(c.permissions) AND (bits&4)<>4 THEN CONTINUE;END IF;
  parent:=CASE WHEN n.path=c.namespace_root THEN c.namespace_root ELSE coalesce(nullif(regexp_replace(n.path,'/[^/]+$',''),''),'/') END;
  IF c.namespace_root<>'/' AND parent<>c.namespace_root AND left(parent,length(c.namespace_root)+1)<>c.namespace_root||'/' THEN parent:=c.namespace_root;END IF;
  depth:=0;valid:=true;
  LOOP
   depth:=depth+1;IF depth>512 THEN valid:=false;EXIT;END IF;
   IF parent='/' THEN EXIT;END IF;
   SELECT * INTO d FROM namespace_entries WHERE (tenant_id,partner_id,path)=(t,p,parent) AND NOT deleted;
   IF d.entry_id IS NULL OR d.kind<>'dir' THEN valid:=false;EXIT;END IF;
   bits:=CASE WHEN d.owner_actor_id=c.actor_id THEN (d.mode>>6)&7 ELSE (d.mode>>3)&7 END;
   IF NOT 'admin'=ANY(c.permissions) AND (bits&1)<>1 THEN valid:=false;EXIT;END IF;
   IF parent=c.namespace_root THEN EXIT;END IF;
   parent:=coalesce(nullif(regexp_replace(parent,'/[^/]+$',''),''),'/');
  END LOOP;
  IF valid THEN RETURN true;END IF;
 END LOOP;
 RETURN false;
END $$;
CREATE FUNCTION freightctl_exchange_source_readable(t uuid,p uuid,f uuid) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT freightctl_exchange_actor_source_readable(t,p,f,nullif(current_setting('freightctl.actor_id',true),'')::uuid)
$$;

CREATE FUNCTION freightctl_artifact_exchange_principals_current(x artifact_exchanges) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT x.expires_at>clock_timestamp() AND freightctl_exchange_actor_source_readable(x.tenant_id,x.partner_id,x.file_id,x.sender_actor_id) AND EXISTS(SELECT 1 FROM exchange_endpoint_heads h WHERE
 (h.tenant_id,h.partner_id,h.endpoint_id,h.revision,h.definition_hash,h.state)=(x.tenant_id,x.partner_id,x.endpoint_id,x.endpoint_revision,x.request->'endpoint'->>'hash','active')
 AND h.definition->'recipient'->>'actor_id'=x.recipient_actor_id::text
 AND freightctl_exchange_participant_current(x.tenant_id,x.partner_id,h.definition->'recipient',ARRAY['read','list'])
 AND EXISTS(SELECT 1 FROM jsonb_array_elements(h.definition->'senders') s WHERE s->>'actor_id'=x.sender_actor_id::text AND freightctl_exchange_participant_current(x.tenant_id,x.partner_id,s,ARRAY['read','deliver'])))
$$;
CREATE FUNCTION freightctl_artifact_exchange_result(x artifact_exchanges) RETURNS jsonb LANGUAGE sql IMMUTABLE AS $$
 SELECT jsonb_build_object('id',x.exchange_id,'sender_actor_id',x.sender_actor_id,'recipient_actor_id',x.recipient_actor_id,'request',x.request,'request_hash',x.request_hash,'event_id',x.event_id)
$$;
CREATE FUNCTION freightctl_artifact_exchange_policy_current(t uuid,p uuid,f uuid) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT EXISTS(SELECT 1 FROM files v LEFT JOIN LATERAL (SELECT state,definition_hash FROM intake_policies WHERE (tenant_id,partner_id)=(t,p) ORDER BY version DESC LIMIT 1) i ON true
 WHERE (v.tenant_id,v.partner_id,v.file_id)=(t,p,f) AND ((i.definition_hash IS NULL AND v.policy='integrity-only-v1') OR (i.state='active' AND v.policy='intake-csv-v1:'||i.definition_hash)))
 AND freightctl_file_available(t,p,f)
$$;
CREATE FUNCTION freightctl_artifact_exchange_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE e events;f files;h exchange_endpoint_heads;r jsonb;wire text;expiry text;pending bigint;prior artifact_exchanges;expected jsonb;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'artifact exchange requests are immutable' USING ERRCODE='23514';END IF;
 IF NEW.sender_actor_id IS DISTINCT FROM nullif(current_setting('freightctl.actor_id',true),'')::uuid THEN RAISE EXCEPTION 'exchange sender differs from actor' USING ERRCODE='42501';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id::text||':'||NEW.partner_id::text||':'||NEW.sender_actor_id::text||':artifact-exchanges',0));
 PERFORM pg_advisory_xact_lock_shared(hashtextextended(NEW.tenant_id::text||':'||NEW.partner_id::text||':exchange-endpoint:'||NEW.endpoint_id::text,0));
 PERFORM pg_advisory_xact_lock_shared(hashtextextended(NEW.tenant_id::text||':'||NEW.partner_id::text||':namespace-v1',0));
 PERFORM pg_advisory_xact_lock_shared(hashtextextended(NEW.tenant_id::text||':'||NEW.partner_id::text||':intake-policy',0));
 SELECT count(*) INTO pending FROM artifact_exchanges WHERE (tenant_id,partner_id,sender_actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.sender_actor_id) AND expires_at>clock_timestamp();
 IF pending>=10000 THEN RAISE EXCEPTION 'exchange view admission full' USING ERRCODE='23514';END IF;
 SELECT * INTO h FROM exchange_endpoint_heads WHERE (tenant_id,partner_id,endpoint_id)=(NEW.tenant_id,NEW.partner_id,NEW.endpoint_id);
 IF h.endpoint_id IS NULL OR h.revision<>NEW.endpoint_revision OR NOT freightctl_artifact_exchange_principals_current(NEW) THEN RAISE EXCEPTION 'exchange requires current endpoint and participant bindings' USING ERRCODE='23514';END IF;
 SELECT * INTO f FROM files WHERE (tenant_id,partner_id,file_id)=(NEW.tenant_id,NEW.partner_id,NEW.file_id);
 IF f.file_id IS NULL OR NOT freightctl_exchange_source_readable(NEW.tenant_id,NEW.partner_id,NEW.file_id) OR NOT freightctl_artifact_exchange_policy_current(NEW.tenant_id,NEW.partner_id,NEW.file_id) THEN RAISE EXCEPTION 'exchange source is unavailable or unauthorized' USING ERRCODE='23514';END IF;
 r:=NEW.request;
 IF ARRAY(SELECT jsonb_object_keys(r) ORDER BY 1) IS DISTINCT FROM (CASE WHEN r ? 'reply_to' THEN ARRAY['artifact','endpoint','expires_at','receipt','reply_to','schema_version']::text[] ELSE ARRAY['artifact','endpoint','expires_at','receipt','schema_version']::text[] END) OR r->'schema_version' IS DISTINCT FROM '1'::jsonb OR r->>'receipt' IS DISTINCT FROM 'availability-only-v1' OR r->'artifact' IS DISTINCT FROM jsonb_build_object('file_revision_id',f.file_id,'size_bytes',f.size_bytes,'sha256',f.sha256,'acceptance_policy',f.policy) OR r->'endpoint' IS DISTINCT FROM jsonb_build_object('id',h.endpoint_id,'revision',h.revision,'hash',h.definition_hash) THEN RAISE EXCEPTION 'exchange requires exact artifact and endpoint request' USING ERRCODE='23514';END IF;
 expiry:=rtrim(rtrim(to_char(NEW.expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US'),'0'),'.')||'Z';
 IF r->'expires_at' IS DISTINCT FROM to_jsonb(expiry) THEN RAISE EXCEPTION 'exchange expiry must have exact UTC microsecond meaning' USING ERRCODE='23514';END IF;
 IF r ? 'reply_to' THEN
  SELECT * INTO prior FROM artifact_exchanges WHERE (tenant_id,partner_id,exchange_id::text,recipient_actor_id,sender_actor_id)=(NEW.tenant_id,NEW.partner_id,r->>'reply_to',NEW.sender_actor_id,NEW.recipient_actor_id);
  IF prior.exchange_id IS NULL OR jsonb_typeof(r->'reply_to') IS DISTINCT FROM 'string' THEN RAISE EXCEPTION 'reply lineage grants no exchange authority' USING ERRCODE='23514';END IF;
 END IF;
 wire:='{"schema_version":1,"artifact":{"file_revision_id":'||to_json(f.file_id::text)::text||',"size_bytes":'||f.size_bytes::text||',"sha256":'||to_json(f.sha256)::text||',"acceptance_policy":'||to_json(f.policy)::text||'},"endpoint":{"id":'||to_json(h.endpoint_id::text)::text||',"revision":'||h.revision::text||',"hash":'||to_json(h.definition_hash)::text||'},"expires_at":'||to_json(expiry)::text||',"receipt":"availability-only-v1"'||CASE WHEN r ? 'reply_to' THEN ',"reply_to":'||to_json(prior.exchange_id::text)::text ELSE '' END||'}';
 IF NEW.request_wire IS DISTINCT FROM wire THEN RAISE EXCEPTION 'exchange request must have canonical meaning' USING ERRCODE='23514';END IF;
 SELECT * INTO e FROM events WHERE (tenant_id,partner_id,event_id,actor_id,resource_id,kind)=(NEW.tenant_id,NEW.partner_id,NEW.event_id,NEW.sender_actor_id,NEW.exchange_id,'ArtifactExchangeOffered');
 expected:=jsonb_build_object('exchange',freightctl_artifact_exchange_result(NEW)-'event_id','storage_id',NEW.storage_id);
 IF e.payload IS DISTINCT FROM expected THEN RAISE EXCEPTION 'exchange requires exact offered event' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER artifact_exchange_guard BEFORE INSERT OR UPDATE OR DELETE ON artifact_exchanges FOR EACH ROW EXECUTE FUNCTION freightctl_artifact_exchange_guard();
CREATE FUNCTION freightctl_artifact_exchange_command_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE e events;x artifact_exchanges;expected jsonb;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'artifact exchange receipts are immutable' USING ERRCODE='23514';END IF;
 SELECT * INTO x FROM artifact_exchanges WHERE (tenant_id,partner_id,exchange_id,sender_actor_id,request_hash)=(NEW.tenant_id,NEW.partner_id,NEW.exchange_id,NEW.actor_id,NEW.request_hash);
 expected:=jsonb_build_object('exchange',freightctl_artifact_exchange_result(x),'replayed',false);
 SELECT * INTO e FROM events WHERE (tenant_id,partner_id,event_id,actor_id,resource_id,kind)=(NEW.tenant_id,NEW.partner_id,NEW.event_id,NEW.actor_id,NEW.exchange_id,'ArtifactExchangeCommandCompleted');
 IF x.exchange_id IS NULL OR NEW.result IS DISTINCT FROM expected OR e.payload IS DISTINCT FROM jsonb_build_object('request_key',NEW.request_key,'request_hash',NEW.request_hash,'result',expected) THEN RAISE EXCEPTION 'exchange receipt requires exact request and result event' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER artifact_exchange_command_guard BEFORE INSERT OR UPDATE OR DELETE ON artifact_exchange_commands FOR EACH ROW EXECUTE FUNCTION freightctl_artifact_exchange_command_guard();
CREATE FUNCTION freightctl_artifact_exchange_complete() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_TABLE_NAME='artifact_exchanges' THEN
  IF NOT EXISTS(SELECT 1 FROM artifact_exchange_commands c WHERE (c.tenant_id,c.partner_id,c.exchange_id)=(NEW.tenant_id,NEW.partner_id,NEW.exchange_id)) THEN RAISE EXCEPTION 'exchange requires transactional receipt' USING ERRCODE='23514';END IF;
 ELSIF NEW.kind='ArtifactExchangeOffered' THEN
  IF NOT EXISTS(SELECT 1 FROM artifact_exchanges x WHERE (x.tenant_id,x.partner_id,x.event_id)=(NEW.tenant_id,NEW.partner_id,NEW.event_id)) THEN RAISE EXCEPTION 'offered event requires exact exchange' USING ERRCODE='23514';END IF;
 ELSIF NEW.kind='ArtifactExchangeCommandCompleted' THEN
  IF NOT EXISTS(SELECT 1 FROM artifact_exchange_commands c WHERE (c.tenant_id,c.partner_id,c.event_id)=(NEW.tenant_id,NEW.partner_id,NEW.event_id)) THEN RAISE EXCEPTION 'exchange command event requires exact receipt' USING ERRCODE='23514';END IF;
 ELSIF NEW.kind='ArtifactExchangeRetrievalAuthorized' THEN
  IF NOT EXISTS(SELECT 1 FROM artifact_exchanges x WHERE (x.tenant_id,x.partner_id,x.exchange_id,x.recipient_actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.resource_id,NEW.actor_id) AND freightctl_artifact_exchange_principals_current(x) AND freightctl_artifact_exchange_policy_current(x.tenant_id,x.partner_id,x.file_id)
   AND NEW.payload=jsonb_build_object('file_revision_id',x.file_id,'sha256',x.request->'artifact'->>'sha256','evidence','read-authorized-only')) THEN RAISE EXCEPTION 'retrieval event requires current recipient and exact available revision' USING ERRCODE='23514';END IF;
 END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER artifact_exchange_complete AFTER INSERT ON artifact_exchanges DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION freightctl_artifact_exchange_complete();
CREATE CONSTRAINT TRIGGER artifact_exchange_events_complete AFTER INSERT ON events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN(NEW.kind IN ('ArtifactExchangeOffered','ArtifactExchangeCommandCompleted','ArtifactExchangeRetrievalAuthorized')) EXECUTE FUNCTION freightctl_artifact_exchange_complete();
REVOKE ALL ON FUNCTION freightctl_exchange_source_readable(uuid,uuid,uuid),freightctl_artifact_exchange_principals_current(artifact_exchanges),freightctl_artifact_exchange_result(artifact_exchanges),freightctl_artifact_exchange_guard(),freightctl_artifact_exchange_command_guard(),freightctl_artifact_exchange_complete() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION freightctl_exchange_source_readable(uuid,uuid,uuid),freightctl_artifact_exchange_principals_current(artifact_exchanges),freightctl_artifact_exchange_result(artifact_exchanges) TO freightctl_runtime;
REVOKE ALL ON FUNCTION freightctl_artifact_exchange_policy_current(uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION freightctl_artifact_exchange_policy_current(uuid,uuid,uuid) TO freightctl_runtime;
REVOKE ALL ON FUNCTION freightctl_exchange_actor_source_readable(uuid,uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION freightctl_exchange_actor_source_readable(uuid,uuid,uuid,uuid) TO freightctl_runtime;
