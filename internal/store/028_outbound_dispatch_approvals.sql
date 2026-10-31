-- This policy controls every outbound SFTP delivery intent. Definition-level
-- workflow/onboarding approval remains a separate, cumulative control.
CREATE TABLE outbound_dispatch_policies(
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,revision bigint NOT NULL CHECK(revision>0),mode text NOT NULL CHECK(mode IN ('author','independent')),actor_id uuid NOT NULL,event_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,partner_id,revision),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,event_id) REFERENCES events(tenant_id,partner_id,event_id)
);
CREATE TABLE outbound_dispatch_reviews(
 tenant_id uuid NOT NULL,partner_id uuid NOT NULL,actor_id uuid NOT NULL,review_id uuid NOT NULL,reviewer_id uuid NOT NULL,delivery_id uuid NOT NULL,
 definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object' AND octet_length(definition::text)<=32768),definition_hash text NOT NULL CHECK(definition_hash ~ '^[0-9a-f]{64}$'),
 state text NOT NULL CHECK(state IN ('pending','approved','rejected','withdrawn')),revision bigint NOT NULL CHECK(revision>0),created_at timestamptz NOT NULL,changed_event_id uuid NOT NULL,policy_revision bigint NOT NULL CHECK(policy_revision>0),
 PRIMARY KEY(tenant_id,partner_id,review_id),CHECK(actor_id<>reviewer_id),
 FOREIGN KEY(tenant_id,partner_id,actor_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,reviewer_id) REFERENCES credentials(tenant_id,partner_id,actor_id),
 FOREIGN KEY(tenant_id,partner_id,delivery_id) REFERENCES delivery_intents(tenant_id,partner_id,delivery_id),
 FOREIGN KEY(tenant_id,partner_id,policy_revision) REFERENCES outbound_dispatch_policies(tenant_id,partner_id,revision),
 FOREIGN KEY(tenant_id,partner_id,changed_event_id) REFERENCES events(tenant_id,partner_id,event_id)
);
CREATE UNIQUE INDEX outbound_dispatch_one_open_review ON outbound_dispatch_reviews(tenant_id,partner_id,delivery_id) WHERE state IN ('pending','approved');
CREATE INDEX outbound_dispatch_author_history ON outbound_dispatch_reviews(tenant_id,partner_id,actor_id,review_id);
CREATE INDEX outbound_dispatch_reviewer_history ON outbound_dispatch_reviews(tenant_id,partner_id,reviewer_id,review_id);
ALTER TABLE outbound_dispatch_policies ENABLE ROW LEVEL SECURITY;ALTER TABLE outbound_dispatch_policies FORCE ROW LEVEL SECURITY;
ALTER TABLE outbound_dispatch_reviews ENABLE ROW LEVEL SECURITY;ALTER TABLE outbound_dispatch_reviews FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON outbound_dispatch_policies USING(tenant_id=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND partner_id=nullif(current_setting('freightctl.partner_id',true),'')::uuid)
 WITH CHECK(tenant_id=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND partner_id=nullif(current_setting('freightctl.partner_id',true),'')::uuid AND freightctl_onboarding_manager(tenant_id,partner_id));
CREATE FUNCTION freightctl_outbound_dispatch_reader(t uuid,p uuid,a uuid,r uuid) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT t=nullif(current_setting('freightctl.tenant_id',true),'')::uuid AND p=nullif(current_setting('freightctl.partner_id',true),'')::uuid AND EXISTS(SELECT 1 FROM credentials c WHERE (c.tenant_id,c.partner_id,c.actor_id)=(t,p,nullif(current_setting('freightctl.actor_id',true),'')::uuid)
 AND c.namespace_root='/' AND c.revoked_at IS NULL AND (c.expires_at IS NULL OR c.expires_at>clock_timestamp())
 AND ((c.actor_id=a AND c.permissions @> ARRAY['read','deliver']::text[]) OR (c.actor_id=r AND c.permissions @> ARRAY['inspect','workflow_approve']::text[])))
$$;
CREATE POLICY scope ON outbound_dispatch_reviews USING(freightctl_outbound_dispatch_reader(tenant_id,partner_id,actor_id,reviewer_id)) WITH CHECK(freightctl_outbound_dispatch_reader(tenant_id,partner_id,actor_id,reviewer_id));
REVOKE ALL ON outbound_dispatch_policies,outbound_dispatch_reviews FROM PUBLIC;
GRANT SELECT,INSERT ON outbound_dispatch_policies TO freightctl_runtime;
GRANT SELECT,INSERT,UPDATE ON outbound_dispatch_reviews TO freightctl_runtime;
CREATE FUNCTION freightctl_outbound_dispatch_policy_binding(t uuid,p uuid) RETURNS jsonb LANGUAGE sql STABLE AS $$
 SELECT coalesce((SELECT jsonb_build_object('revision',revision,'mode',mode) FROM outbound_dispatch_policies WHERE tenant_id=t AND partner_id=p ORDER BY revision DESC LIMIT 1),'{"revision":0,"mode":"author"}'::jsonb)
$$;
CREATE FUNCTION freightctl_outbound_dispatch_policy_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE e jsonb;n bigint;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'outbound dispatch policy history is immutable' USING ERRCODE='23514';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id::text||':'||NEW.partner_id::text||':accounts',0));
 PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id::text||':'||NEW.partner_id::text||':outbound-dispatch-policy',0));
 SELECT coalesce(max(revision),0)+1 INTO n FROM outbound_dispatch_policies WHERE tenant_id=NEW.tenant_id AND partner_id=NEW.partner_id;
 SELECT payload INTO e FROM events WHERE (tenant_id,partner_id,event_id,actor_id,resource_id,kind)=(NEW.tenant_id,NEW.partner_id,NEW.event_id,NEW.actor_id,NEW.partner_id,'OutboundDispatchPolicyChanged');
 IF NOT freightctl_onboarding_manager(NEW.tenant_id,NEW.partner_id) OR NEW.actor_id IS DISTINCT FROM nullif(current_setting('freightctl.actor_id',true),'')::uuid THEN RAISE EXCEPTION 'outbound dispatch policy requires current administrator' USING ERRCODE='42501';END IF;
 IF NEW.revision<>n OR e IS NULL OR e->>'revision' IS DISTINCT FROM NEW.revision::text OR e->>'mode' IS DISTINCT FROM NEW.mode OR e->>'author_id' IS DISTINCT FROM NEW.actor_id::text THEN RAISE EXCEPTION 'outbound policy requires exact journal revision' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER outbound_dispatch_policy_guard BEFORE INSERT OR UPDATE OR DELETE ON outbound_dispatch_policies FOR EACH ROW EXECUTE FUNCTION freightctl_outbound_dispatch_policy_guard();
CREATE FUNCTION freightctl_outbound_dispatch_current(t uuid,p uuid,a uuid,id uuid) RETURNS boolean LANGUAGE plpgsql VOLATILE AS $$
DECLARE policy jsonb;d jsonb;h text;
BEGIN
 PERFORM pg_advisory_xact_lock_shared(hashtextextended(t::text||':'||p::text||':outbound-dispatch-policy',0));
 policy:=freightctl_outbound_dispatch_policy_binding(t,p);
 SELECT definition,definition_hash INTO d,h FROM delivery_intents WHERE (tenant_id,partner_id,actor_id,delivery_id)=(t,p,a,id);
 IF d IS NULL OR coalesce(d->'dispatch_approval_policy','{"revision":0,"mode":"author"}'::jsonb) IS DISTINCT FROM policy THEN RETURN false;END IF;
 IF policy->>'mode'='author' THEN RETURN true;END IF;
 RETURN EXISTS(SELECT 1 FROM outbound_dispatch_reviews r JOIN credentials reviewer ON (reviewer.tenant_id,reviewer.partner_id,reviewer.actor_id)=(r.tenant_id,r.partner_id,r.reviewer_id) JOIN credentials author ON (author.tenant_id,author.partner_id,author.actor_id)=(r.tenant_id,r.partner_id,r.actor_id)
 WHERE (r.tenant_id,r.partner_id,r.actor_id,r.delivery_id)=(t,p,a,id) AND r.state='approved' AND r.definition->'policy'=policy AND r.definition->>'delivery_hash'=h
 AND r.definition->'source'=d->'source' AND r.definition->>'authority_revision'=d->>'authority_revision'
 AND author.authority_revision::text=d->>'authority_revision' AND author.namespace_root=d->>'namespace_root' AND author.permissions @> ARRAY['read','deliver']::text[] AND author.revoked_at IS NULL AND (author.expires_at IS NULL OR author.expires_at>clock_timestamp())
 AND reviewer.authority_revision::text=r.definition->>'reviewer_authority_revision' AND reviewer.namespace_root='/' AND reviewer.permissions @> ARRAY['inspect','workflow_approve']::text[] AND reviewer.revoked_at IS NULL AND (reviewer.expires_at IS NULL OR reviewer.expires_at>clock_timestamp()));
END $$;
CREATE FUNCTION freightctl_outbound_dispatch_effect_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE policy jsonb;
BEGIN
 IF TG_OP='INSERT' THEN
  PERFORM pg_advisory_xact_lock_shared(hashtextextended(NEW.tenant_id::text||':'||NEW.partner_id::text||':outbound-dispatch-policy',0));policy:=freightctl_outbound_dispatch_policy_binding(NEW.tenant_id,NEW.partner_id);
  IF coalesce(NEW.definition->'dispatch_approval_policy','{"revision":0,"mode":"author"}'::jsonb) IS DISTINCT FROM policy THEN RAISE EXCEPTION 'delivery must bind current dispatch policy' USING ERRCODE='23514';END IF;
 ELSIF NEW.state IN ('staging','publishing','succeeded') THEN
  -- Read-only reconciliation preserves an existing uncertain publication's
  -- integrity receipt. It cannot stage/send bytes or authorize another send.
  IF OLD.state='ambiguous' AND NEW.state='succeeded' AND NEW.observation->>'code'='remote_file_integrity_observed' AND NEW.observation->>'reconciled'='true' THEN RETURN NEW;END IF;
  IF NOT freightctl_outbound_dispatch_current(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.delivery_id) THEN RAISE EXCEPTION 'current outbound dispatch approval required' USING ERRCODE='23514';END IF;
 END IF;RETURN NEW;
END $$;
CREATE TRIGGER outbound_dispatch_effect_guard BEFORE INSERT OR UPDATE ON delivery_intents FOR EACH ROW EXECUTE FUNCTION freightctl_outbound_dispatch_effect_guard();
CREATE FUNCTION freightctl_outbound_dispatch_authority_lock() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id::text||':'||NEW.partner_id::text||':outbound-dispatch-policy',0));RETURN NEW;
END $$;
CREATE TRIGGER outbound_dispatch_authority_lock BEFORE UPDATE ON credentials FOR EACH ROW EXECUTE FUNCTION freightctl_outbound_dispatch_authority_lock();
CREATE FUNCTION freightctl_outbound_dispatch_review_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE e jsonb;d jsonb;a uuid;original delivery_intents%ROWTYPE;expected jsonb;recipient text;pending integer;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'outbound dispatch reviews cannot be deleted' USING ERRCODE='23514';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id::text||':'||NEW.partner_id::text||':accounts',0));
 IF TG_OP='UPDATE' THEN PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id::text||':'||NEW.partner_id::text||':outbound-dispatch-policy',0));END IF;
 a:=nullif(current_setting('freightctl.actor_id',true),'')::uuid;d:=NEW.definition;
 SELECT payload INTO e FROM events WHERE (tenant_id,partner_id,event_id,actor_id,resource_id,kind)=(NEW.tenant_id,NEW.partner_id,NEW.changed_event_id,a,NEW.review_id,'OutboundDispatchReviewChanged');
 IF e IS NULL OR e->>'id' IS DISTINCT FROM NEW.review_id::text OR e->>'author_id' IS DISTINCT FROM NEW.actor_id::text OR e->>'reviewer_id' IS DISTINCT FROM NEW.reviewer_id::text OR e->>'delivery_id' IS DISTINCT FROM NEW.delivery_id::text OR e->'definition' IS DISTINCT FROM d OR e->>'definition_hash' IS DISTINCT FROM NEW.definition_hash OR e->>'state' IS DISTINCT FROM NEW.state OR e->>'revision' IS DISTINCT FROM NEW.revision::text OR (e->>'created_at')::timestamptz IS DISTINCT FROM NEW.created_at THEN RAISE EXCEPTION 'outbound review requires exact immutable journal record' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN
  SELECT count(*) INTO pending FROM outbound_dispatch_reviews WHERE tenant_id=NEW.tenant_id AND partner_id=NEW.partner_id AND actor_id=NEW.actor_id AND state='pending';IF pending>=128 THEN RAISE EXCEPTION 'outbound review admission full' USING ERRCODE='23514';END IF;
  IF a<>NEW.actor_id OR NEW.state<>'pending' OR NEW.revision<>1 OR NOT EXISTS(SELECT 1 FROM credentials c WHERE (c.tenant_id,c.partner_id,c.actor_id)=(NEW.tenant_id,NEW.partner_id,a) AND c.namespace_root='/' AND c.permissions @> ARRAY['read','deliver']::text[] AND c.authority_revision::text=d->>'authority_revision' AND c.revoked_at IS NULL AND (c.expires_at IS NULL OR c.expires_at>clock_timestamp())) THEN RAISE EXCEPTION 'dispatch review starts with authorized owner proposal' USING ERRCODE='42501';END IF;
  IF ARRAY(SELECT jsonb_object_keys(d) ORDER BY 1) IS DISTINCT FROM ARRAY['attempt_limit','author_id','authority_revision','delivery_hash','delivery_id','delivery_revision','effect','namespace_root','policy','reviewer_authority_revision','reviewer_id','schema_version','source','storage_id']::text[] OR d->>'schema_version' IS DISTINCT FROM '1' OR d->>'attempt_limit' IS DISTINCT FROM '8' OR d->>'namespace_root' IS DISTINCT FROM '/' OR d->>'author_id' IS DISTINCT FROM NEW.actor_id::text OR d->>'reviewer_id' IS DISTINCT FROM NEW.reviewer_id::text OR d->>'delivery_id' IS DISTINCT FROM NEW.delivery_id::text OR d->'policy' IS DISTINCT FROM freightctl_outbound_dispatch_policy_binding(NEW.tenant_id,NEW.partner_id) OR d->'policy'->>'mode' IS DISTINCT FROM 'independent' OR d->'policy'->>'revision' IS DISTINCT FROM NEW.policy_revision::text THEN RAISE EXCEPTION 'invalid exact dispatch review binding' USING ERRCODE='23514';END IF;
  IF NOT EXISTS(SELECT 1 FROM credentials c WHERE (c.tenant_id,c.partner_id,c.actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.reviewer_id) AND c.namespace_root='/' AND c.permissions @> ARRAY['inspect','workflow_approve']::text[] AND c.authority_revision::text=d->>'reviewer_authority_revision' AND c.revoked_at IS NULL AND (c.expires_at IS NULL OR c.expires_at>clock_timestamp())) THEN RAISE EXCEPTION 'dispatch reviewer lacks current authority' USING ERRCODE='42501';END IF;
  SELECT * INTO original FROM delivery_intents WHERE (tenant_id,partner_id,actor_id,delivery_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.delivery_id);
  IF original.delivery_id IS NULL OR original.state NOT IN ('draft','queued') OR original.attempts<>0 OR original.fence<>0 OR original.lease_owner IS NOT NULL OR original.revision::text IS DISTINCT FROM d->>'delivery_revision' OR original.definition_hash IS DISTINCT FROM d->>'delivery_hash' OR original.definition->'source' IS DISTINCT FROM d->'source' OR original.definition->>'storage_id' IS DISTINCT FROM d->>'storage_id' OR original.definition->>'authority_revision' IS DISTINCT FROM d->>'authority_revision' OR original.definition->>'namespace_root' IS DISTINCT FROM d->>'namespace_root' OR original.definition->'dispatch_approval_policy' IS DISTINCT FROM d->'policy' OR EXISTS(SELECT 1 FROM delivery_ciphertexts WHERE (tenant_id,partner_id,actor_id,delivery_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.delivery_id)) OR NOT freightctl_file_available(NEW.tenant_id,NEW.partner_id,original.file_id) THEN RAISE EXCEPTION 'review requires exact untouched authorized delivery' USING ERRCODE='23514';END IF;
  IF NOT EXISTS(SELECT 1 FROM files f WHERE (f.tenant_id,f.partner_id,f.file_id)=(NEW.tenant_id,NEW.partner_id,original.file_id) AND d->'source'=jsonb_build_object('id',f.file_id::text,'size_bytes',f.size_bytes,'sha256',f.sha256,'policy',f.policy,'accepted_event_id',f.accepted_event_id::text)) THEN RAISE EXCEPTION 'dispatch source must equal accepted file' USING ERRCODE='23514';END IF;
  recipient:='';IF original.definition ? 'encryption' THEN SELECT definition->>'fingerprint' INTO recipient FROM pgp_keys WHERE (tenant_id,partner_id,key_id,version)=(NEW.tenant_id,NEW.partner_id,(original.definition->'encryption'->'key'->>'id')::uuid,(original.definition->'encryption'->'key'->>'version')::integer) AND state='active' AND definition_hash=original.definition->'encryption'->'key'->>'hash' AND (valid_until IS NULL OR valid_until>clock_timestamp());IF recipient IS NULL THEN RAISE EXCEPTION 'dispatch recipient changed' USING ERRCODE='23514';END IF;END IF;
  expected:=jsonb_build_object('protocol','sftp','address',original.definition->'destination'->>'address','user',original.definition->'destination'->>'user','directory',original.definition->>'directory','filename',original.definition->>'filename','final_path',rtrim(original.definition->>'directory','/')||'/'||original.delivery_id::text||'-'||(original.definition->>'filename'),'host_fingerprint',original.definition->'destination'->'host'->>'Fingerprint','key_fingerprint',original.definition->'destination'->>'key_fingerprint','key_reference_sha256',encode(sha256(convert_to(original.definition->'destination'->>'key_reference','UTF8')),'hex'),'recipient_fingerprint',recipient);
  IF original.definition ? 'encryption' THEN expected:=expected||jsonb_build_object('encryption',original.definition->'encryption');END IF;
  IF original.definition ? 'workflow_binding' THEN expected:=expected||jsonb_build_object('workflow_binding',original.definition->'workflow_binding');END IF;
  IF d->'effect' IS DISTINCT FROM expected THEN RAISE EXCEPTION 'dispatch effects must equal exact intent' USING ERRCODE='23514';END IF;
 ELSE
  IF (NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.review_id,NEW.reviewer_id,NEW.delivery_id,NEW.definition,NEW.definition_hash,NEW.created_at,NEW.policy_revision) IS DISTINCT FROM (OLD.tenant_id,OLD.partner_id,OLD.actor_id,OLD.review_id,OLD.reviewer_id,OLD.delivery_id,OLD.definition,OLD.definition_hash,OLD.created_at,OLD.policy_revision) OR NEW.revision<>OLD.revision+1 THEN RAISE EXCEPTION 'dispatch review identity is immutable' USING ERRCODE='23514';END IF;
  IF NEW.state='withdrawn' AND OLD.state IN ('pending','approved') THEN IF a<>NEW.actor_id AND a<>NEW.reviewer_id THEN RAISE EXCEPTION 'only owner or named reviewer can withdraw' USING ERRCODE='42501';END IF;
  ELSIF NEW.state IN ('approved','rejected') AND OLD.state='pending' THEN
   IF a<>NEW.reviewer_id OR a=NEW.actor_id OR d->'policy' IS DISTINCT FROM freightctl_outbound_dispatch_policy_binding(NEW.tenant_id,NEW.partner_id) OR NOT EXISTS(SELECT 1 FROM credentials c WHERE (c.tenant_id,c.partner_id,c.actor_id)=(NEW.tenant_id,NEW.partner_id,a) AND c.authority_revision::text=d->>'reviewer_authority_revision' AND c.permissions @> ARRAY['inspect','workflow_approve']::text[] AND c.namespace_root='/' AND c.revoked_at IS NULL AND (c.expires_at IS NULL OR c.expires_at>clock_timestamp())) THEN RAISE EXCEPTION 'approval requires exact current independent dispatch reviewer' USING ERRCODE='42501';END IF;
   IF NOT EXISTS(SELECT 1 FROM credentials c WHERE (c.tenant_id,c.partner_id,c.actor_id)=(NEW.tenant_id,NEW.partner_id,NEW.actor_id) AND c.authority_revision::text=d->>'authority_revision' AND c.revoked_at IS NULL AND (c.expires_at IS NULL OR c.expires_at>clock_timestamp())) THEN RAISE EXCEPTION 'dispatch author authority changed' USING ERRCODE='42501';END IF;
  ELSE RAISE EXCEPTION 'invalid dispatch review transition' USING ERRCODE='23514';END IF;
 END IF;RETURN NEW;
END $$;
CREATE TRIGGER outbound_dispatch_review_guard BEFORE INSERT OR UPDATE OR DELETE ON outbound_dispatch_reviews FOR EACH ROW EXECUTE FUNCTION freightctl_outbound_dispatch_review_guard();
CREATE FUNCTION freightctl_outbound_dispatch_event_complete() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (NEW.kind='OutboundDispatchPolicyChanged' AND NOT EXISTS(SELECT 1 FROM outbound_dispatch_policies WHERE (tenant_id,partner_id,event_id)=(NEW.tenant_id,NEW.partner_id,NEW.event_id))) OR (NEW.kind='OutboundDispatchReviewChanged' AND NOT EXISTS(SELECT 1 FROM outbound_dispatch_reviews WHERE (tenant_id,partner_id,changed_event_id)=(NEW.tenant_id,NEW.partner_id,NEW.event_id))) THEN RAISE EXCEPTION 'outbound dispatch event requires complete projection' USING ERRCODE='23514';END IF;RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER outbound_dispatch_event_complete AFTER INSERT ON events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN(NEW.kind IN ('OutboundDispatchPolicyChanged','OutboundDispatchReviewChanged')) EXECUTE FUNCTION freightctl_outbound_dispatch_event_complete();
REVOKE ALL ON FUNCTION freightctl_outbound_dispatch_policy_guard(),freightctl_outbound_dispatch_effect_guard(),freightctl_outbound_dispatch_authority_lock(),freightctl_outbound_dispatch_review_guard(),freightctl_outbound_dispatch_event_complete() FROM PUBLIC;

CREATE FUNCTION freightctl_outbound_dispatch_ciphertext_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT freightctl_outbound_dispatch_current(NEW.tenant_id,NEW.partner_id,NEW.actor_id,NEW.delivery_id) THEN RAISE EXCEPTION 'ciphertext binding requires current dispatch approval' USING ERRCODE='23514';END IF;RETURN NEW;
END $$;
CREATE TRIGGER outbound_dispatch_ciphertext_guard BEFORE INSERT ON delivery_ciphertexts FOR EACH ROW EXECUTE FUNCTION freightctl_outbound_dispatch_ciphertext_guard();
REVOKE ALL ON FUNCTION freightctl_outbound_dispatch_ciphertext_guard() FROM PUBLIC;
