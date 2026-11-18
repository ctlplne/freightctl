CREATE TABLE artifact_exchange_integrity_reports (
 tenant_id uuid NOT NULL, partner_id uuid NOT NULL, exchange_id uuid NOT NULL, actor_id uuid NOT NULL,
 request_key text NOT NULL CHECK(request_key~'^[A-Za-z0-9._:-]{1,128}$'),
 command_wire text NOT NULL CHECK(octet_length(command_wire) BETWEEN 1 AND 4096 AND jsonb_typeof(command_wire::jsonb)='object'),
 command_hash text NOT NULL CHECK(command_hash=encode(sha256(convert_to(command_wire,'UTF8')),'hex')),
 read_event_id uuid NOT NULL, event_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,exchange_id),
 UNIQUE(tenant_id,partner_id,actor_id,request_key),
 FOREIGN KEY(tenant_id,partner_id,exchange_id) REFERENCES artifact_exchanges(tenant_id,partner_id,exchange_id),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,read_event_id) REFERENCES events(tenant_id,partner_id,event_id),
 FOREIGN KEY(tenant_id,partner_id,event_id) REFERENCES events(tenant_id,partner_id,event_id)
);
ALTER TABLE artifact_exchange_integrity_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE artifact_exchange_integrity_reports FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON artifact_exchange_integrity_reports
 USING(tenant_id=nullif(current_setting('freightctl.tenant_id',true),'')::uuid
   AND partner_id=nullif(current_setting('freightctl.partner_id',true),'')::uuid
   AND EXISTS(SELECT 1 FROM artifact_exchanges x WHERE (x.tenant_id,x.partner_id,x.exchange_id)=
     (artifact_exchange_integrity_reports.tenant_id,artifact_exchange_integrity_reports.partner_id,artifact_exchange_integrity_reports.exchange_id)))
 WITH CHECK(tenant_id=nullif(current_setting('freightctl.tenant_id',true),'')::uuid
   AND partner_id=nullif(current_setting('freightctl.partner_id',true),'')::uuid
   AND actor_id=nullif(current_setting('freightctl.actor_id',true),'')::uuid);
REVOKE ALL ON artifact_exchange_integrity_reports FROM PUBLIC;
GRANT SELECT,INSERT ON artifact_exchange_integrity_reports TO freightctl_runtime;

-- Preserve the exact ordinary admission event and authorize one additional
-- full-GET shape with the same live principal, policy and revision checks.
CREATE OR REPLACE FUNCTION freightctl_artifact_exchange_complete() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_TABLE_NAME='artifact_exchanges' THEN
  IF NOT EXISTS(SELECT 1 FROM artifact_exchange_commands c WHERE (c.tenant_id,c.partner_id,c.exchange_id)=(NEW.tenant_id,NEW.partner_id,NEW.exchange_id)) THEN RAISE EXCEPTION 'exchange requires transactional receipt' USING ERRCODE='23514';END IF;
 ELSIF NEW.kind='ArtifactExchangeOffered' THEN
  IF NOT EXISTS(SELECT 1 FROM artifact_exchanges x WHERE (x.tenant_id,x.partner_id,x.event_id)=(NEW.tenant_id,NEW.partner_id,NEW.event_id)) THEN RAISE EXCEPTION 'offered event requires exact exchange' USING ERRCODE='23514';END IF;
 ELSIF NEW.kind='ArtifactExchangeCommandCompleted' THEN
  IF NOT EXISTS(SELECT 1 FROM artifact_exchange_commands c WHERE (c.tenant_id,c.partner_id,c.event_id)=(NEW.tenant_id,NEW.partner_id,NEW.event_id)) THEN RAISE EXCEPTION 'exchange command event requires exact receipt' USING ERRCODE='23514';END IF;
 ELSIF NEW.kind='ArtifactExchangeRetrievalAuthorized' THEN
  IF NOT EXISTS(SELECT 1 FROM artifact_exchanges x
   CROSS JOIN LATERAL (SELECT jsonb_build_object('file_revision_id',x.file_id,'sha256',x.request#>>'{artifact,sha256}','evidence','read-authorized-only') AS payload) base
   WHERE (x.tenant_id,x.partner_id,x.exchange_id,x.recipient_actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.resource_id,NEW.actor_id)
   AND freightctl_artifact_exchange_principals_current(x) AND freightctl_artifact_exchange_policy_current(x.tenant_id,x.partner_id,x.file_id)
   AND NEW.payload IN (base.payload,base.payload||jsonb_build_object('report_profile','recipient-sha256-report-v1'))) THEN
   RAISE EXCEPTION 'retrieval event requires current recipient and exact available revision' USING ERRCODE='23514';
  END IF;
 END IF;
 RETURN NULL;
END $$;

CREATE FUNCTION freightctl_exchange_integrity_report_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE x artifact_exchanges;expected jsonb;read_payload jsonb;report_payload jsonb;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'recipient integrity reports are immutable' USING ERRCODE='23514';END IF;
 PERFORM freightctl_authority_read_lock(NEW.tenant_id,NEW.partner_id);
 PERFORM pg_advisory_xact_lock_shared(hashtextextended(NEW.tenant_id::text||':'||NEW.partner_id::text||':artifact-exchange:'||NEW.exchange_id::text,0));
 SELECT * INTO x FROM artifact_exchanges WHERE (tenant_id,partner_id,exchange_id)=(NEW.tenant_id,NEW.partner_id,NEW.exchange_id);
 IF x.exchange_id IS NULL OR NEW.actor_id IS DISTINCT FROM x.recipient_actor_id
   OR NEW.actor_id IS DISTINCT FROM nullif(current_setting('freightctl.actor_id',true),'')::uuid THEN
  RAISE EXCEPTION 'integrity report requires the recipient' USING ERRCODE='42501';
 END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended(NEW.tenant_id::text||':'||NEW.partner_id::text||':exchange-endpoint:'||x.endpoint_id::text,0));
 PERFORM pg_advisory_xact_lock_shared(hashtextextended(NEW.tenant_id::text||':'||NEW.partner_id::text||':namespace-v1',0));
 IF freightctl_artifact_exchange_principals_current(x) IS DISTINCT FROM true
   OR freightctl_artifact_exchange_policy_current(x.tenant_id,x.partner_id,x.file_id) IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'integrity report requires a currently readable exchange' USING ERRCODE='55000';
 END IF;
 expected:=jsonb_build_object('schema_version',1,'exchange_id',x.exchange_id,'request_hash',x.request_hash,
   'read_authorization_event_id',NEW.read_event_id,'file_revision_id',x.file_id,
   'size_bytes',x.request#>'{artifact,size_bytes}','sha256',x.request#>>'{artifact,sha256}');
 SELECT payload INTO read_payload FROM events WHERE (tenant_id,partner_id,event_id,actor_id,resource_id,kind)=
   (NEW.tenant_id,NEW.partner_id,NEW.read_event_id,NEW.actor_id,NEW.exchange_id,'ArtifactExchangeRetrievalAuthorized');
 SELECT payload INTO report_payload FROM events WHERE (tenant_id,partner_id,event_id,actor_id,resource_id,kind)=
   (NEW.tenant_id,NEW.partner_id,NEW.event_id,NEW.actor_id,NEW.exchange_id,'ArtifactExchangeIntegrityReported');
 IF NEW.command_wire::jsonb IS DISTINCT FROM expected
   OR read_payload IS DISTINCT FROM jsonb_build_object('file_revision_id',x.file_id,'sha256',x.request#>>'{artifact,sha256}',
     'evidence','read-authorized-only','report_profile','recipient-sha256-report-v1')
   OR report_payload IS DISTINCT FROM jsonb_build_object('command',expected,'command_hash',NEW.command_hash,'request_key',NEW.request_key) THEN
  RAISE EXCEPTION 'integrity report requires the exact read and original journal event' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER exchange_integrity_report_guard BEFORE INSERT OR UPDATE OR DELETE ON artifact_exchange_integrity_reports
 FOR EACH ROW EXECUTE FUNCTION freightctl_exchange_integrity_report_guard();

CREATE FUNCTION freightctl_exchange_integrity_report_complete() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM artifact_exchange_integrity_reports r WHERE (r.tenant_id,r.partner_id,r.exchange_id,r.actor_id,r.event_id)=
   (NEW.tenant_id,NEW.partner_id,NEW.resource_id,NEW.actor_id,NEW.event_id)) THEN
  RAISE EXCEPTION 'integrity event requires its transactional receipt' USING ERRCODE='23514';
 END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER exchange_integrity_report_complete AFTER INSERT ON events DEFERRABLE INITIALLY DEFERRED
 FOR EACH ROW WHEN(NEW.kind='ArtifactExchangeIntegrityReported') EXECUTE FUNCTION freightctl_exchange_integrity_report_complete();
REVOKE ALL ON FUNCTION freightctl_exchange_integrity_report_guard(),freightctl_exchange_integrity_report_complete() FROM PUBLIC;
