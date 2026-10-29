-- New permissions apply to newly provisioned identities only. Existing grants stay unchanged.
ALTER TABLE credentials DROP CONSTRAINT credential_permissions_valid;
ALTER TABLE credentials ADD CONSTRAINT credential_permissions_valid CHECK(cardinality(permissions)<=9 AND permissions <@ ARRAY['read','write','list','manage_paths','inspect','audit_read','admin','connections_manage','deliver']::text[]);
ALTER TABLE credentials ALTER COLUMN permissions SET DEFAULT ARRAY['read','write','list','manage_paths','inspect','audit_read','admin','connections_manage','deliver']::text[];
CREATE TABLE delivery_intents (
 tenant_id uuid NOT NULL, partner_id uuid NOT NULL, delivery_id uuid NOT NULL, actor_id uuid NOT NULL,
 file_id uuid NOT NULL,
 definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object' AND octet_length(definition::text)<=8192),
 definition_hash text NOT NULL CHECK(definition_hash ~ '^[0-9a-f]{64}$'),
 state text NOT NULL CHECK(state IN ('draft','queued','staging','publishing','retry','succeeded','ambiguous','blocked','cancelled')),
 revision bigint NOT NULL CHECK(revision>0), fence bigint NOT NULL CHECK(fence>=0),
 attempts integer NOT NULL CHECK(attempts BETWEEN 0 AND 8),
 lease_owner uuid, lease_until timestamptz, next_at timestamptz NOT NULL,
 observation jsonb NOT NULL CHECK(jsonb_typeof(observation)='object' AND octet_length(observation::text)<=2048),
 changed_event_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,delivery_id),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,file_id) REFERENCES files(tenant_id,partner_id,file_id),
 FOREIGN KEY(tenant_id,partner_id,changed_event_id) REFERENCES events(tenant_id,partner_id,event_id),
 CHECK((state IN ('staging','publishing'))=(lease_owner IS NOT NULL)),
 CHECK((lease_owner IS NULL)=(lease_until IS NULL))
);
CREATE INDEX delivery_actor_state ON delivery_intents(tenant_id,partner_id,actor_id,state,next_at);
CREATE TABLE delivery_receipts (
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,actor_id uuid NOT NULL,
 request_key text NOT NULL CHECK(request_key ~ '^[A-Za-z0-9._:-]{1,128}$'),
 request_hash text NOT NULL CHECK(request_hash ~ '^[0-9a-f]{64}$'),
 delivery_id uuid NOT NULL,result jsonb NOT NULL CHECK(octet_length(result::text)<=16384),completed_event_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,actor_id,request_key),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,delivery_id) REFERENCES delivery_intents(tenant_id,partner_id,delivery_id),
 FOREIGN KEY(tenant_id,partner_id,completed_event_id) REFERENCES events(tenant_id,partner_id,event_id)
);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['delivery_intents','delivery_receipts'] LOOP
  EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('CREATE POLICY scope ON %I USING(tenant_id=nullif(current_setting(''freightctl.tenant_id'',true),'''')::uuid AND partner_id=nullif(current_setting(''freightctl.partner_id'',true),'''')::uuid) WITH CHECK(tenant_id=nullif(current_setting(''freightctl.tenant_id'',true),'''')::uuid AND partner_id=nullif(current_setting(''freightctl.partner_id'',true),'''')::uuid)',t);
  EXECUTE format('CREATE POLICY identity_scope ON %I AS RESTRICTIVE USING(actor_id=nullif(current_setting(''freightctl.actor_id'',true),'''')::uuid) WITH CHECK(actor_id=nullif(current_setting(''freightctl.actor_id'',true),'''')::uuid)',t);
 END LOOP;
END $$;
GRANT SELECT,INSERT,UPDATE ON delivery_intents TO freightctl_runtime;
GRANT SELECT,INSERT ON delivery_receipts TO freightctl_runtime;
CREATE FUNCTION freightctl_delivery_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE k text; p jsonb; valid boolean:=false;
BEGIN
 SELECT kind,payload INTO k,p FROM events WHERE (tenant_id,partner_id,event_id)=(NEW.tenant_id,NEW.partner_id,NEW.changed_event_id) AND actor_id=NEW.actor_id AND resource_id=NEW.delivery_id;
 IF k IS DISTINCT FROM 'DeliveryTransitioned' OR p->>'file_id' IS DISTINCT FROM NEW.file_id::text OR
  p->'definition' IS DISTINCT FROM NEW.definition OR p->>'definition_hash' IS DISTINCT FROM NEW.definition_hash OR
  p->>'state' IS DISTINCT FROM NEW.state OR p->>'revision' IS DISTINCT FROM NEW.revision::text OR
  p->>'fence' IS DISTINCT FROM NEW.fence::text OR p->>'attempts' IS DISTINCT FROM NEW.attempts::text OR
  p->>'lease_owner' IS DISTINCT FROM coalesce(NEW.lease_owner::text,'') OR
  (p->>'lease_until')::timestamptz IS DISTINCT FROM NEW.lease_until OR
  (p->>'next_at')::timestamptz IS DISTINCT FROM NEW.next_at OR p->'observation' IS DISTINCT FROM NEW.observation THEN
  RAISE EXCEPTION 'delivery requires its exact event' USING ERRCODE='23514';
 END IF;
 IF TG_OP='INSERT' THEN
  valid:=NEW.state='draft' AND NEW.revision=1 AND NEW.fence=0 AND NEW.attempts=0;
 ELSE
  IF (NEW.tenant_id,NEW.partner_id,NEW.delivery_id,NEW.actor_id,NEW.file_id,NEW.definition,NEW.definition_hash) IS DISTINCT FROM (OLD.tenant_id,OLD.partner_id,OLD.delivery_id,OLD.actor_id,OLD.file_id,OLD.definition,OLD.definition_hash) OR NEW.revision<>OLD.revision+1 THEN
   RAISE EXCEPTION 'delivery definition is immutable' USING ERRCODE='23514';
  END IF;
  IF NEW.state='staging' AND (OLD.state IN ('queued','retry') OR (OLD.state='staging' AND OLD.lease_until<=clock_timestamp())) THEN
   valid:=NEW.fence=OLD.fence+1 AND NEW.attempts=OLD.attempts+1 AND OLD.attempts<8 AND OLD.next_at<=clock_timestamp() AND NEW.lease_until>clock_timestamp() AND NEW.lease_until<=clock_timestamp()+interval '31 seconds';
  ELSIF OLD.state IN ('staging','publishing') AND NEW.state IN ('staging','publishing') THEN
   valid:=OLD.lease_until>clock_timestamp() AND NEW.lease_owner=OLD.lease_owner AND NEW.lease_until>=OLD.lease_until AND NEW.lease_until<=clock_timestamp()+interval '31 seconds' AND NEW.fence=OLD.fence AND NEW.attempts=OLD.attempts AND (NEW.state=OLD.state OR (OLD.state='staging' AND NEW.state='publishing'));
  ELSE
   valid:=NEW.fence=OLD.fence AND NEW.attempts=OLD.attempts AND (
    (OLD.state='draft' AND NEW.state='queued') OR
    (OLD.state IN ('draft','queued','retry','ambiguous') AND NEW.state='cancelled') OR
    (OLD.state='staging' AND NEW.state IN ('retry','blocked') AND OLD.lease_until>clock_timestamp()) OR
    (OLD.state='publishing' AND NEW.state='succeeded' AND OLD.lease_until>clock_timestamp()) OR
    (OLD.state='publishing' AND NEW.state='ambiguous') OR
    (OLD.state='ambiguous' AND NEW.state='succeeded') OR
    (OLD.state IN ('queued','retry','staging') AND NEW.state='blocked'));
  END IF;
 END IF;
 IF NOT coalesce(valid,false) THEN RAISE EXCEPTION 'invalid delivery state or fence' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER delivery_guard BEFORE INSERT OR UPDATE ON delivery_intents FOR EACH ROW EXECUTE FUNCTION freightctl_delivery_guard();
CREATE FUNCTION freightctl_delivery_receipt_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM events e WHERE (e.tenant_id,e.partner_id,e.event_id)=(NEW.tenant_id,NEW.partner_id,NEW.completed_event_id) AND e.actor_id=NEW.actor_id AND e.resource_id=NEW.delivery_id AND e.kind='DeliveryCommandCompleted' AND e.payload->>'request_key'=NEW.request_key AND e.payload->>'request_hash'=NEW.request_hash AND e.payload->'result'=NEW.result) THEN
  RAISE EXCEPTION 'delivery receipt requires its exact event' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER delivery_receipt_guard BEFORE INSERT ON delivery_receipts FOR EACH ROW EXECUTE FUNCTION freightctl_delivery_receipt_guard();
REVOKE ALL ON FUNCTION freightctl_delivery_guard(),freightctl_delivery_receipt_guard() FROM PUBLIC;
