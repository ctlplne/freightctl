-- Retain the original namespace transition guard and RLS policies unchanged.
-- Property values are inert content,not authority or executable instructions.
ALTER TABLE namespace_entries ADD COLUMN namespace_properties jsonb NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE namespace_entries ADD CONSTRAINT namespace_properties_bounded CHECK (
    jsonb_typeof(namespace_properties)='object'
    AND octet_length(convert_to(namespace_properties::text,'UTF8')) <= 32768
);

CREATE FUNCTION freightctl_namespace_properties_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE event_kind text; event_properties jsonb; property_count integer;
BEGIN
    IF jsonb_typeof(NEW.namespace_properties)<>'object' THEN
        RAISE EXCEPTION 'namespace properties require an object' USING ERRCODE='23514';
    END IF;
    SELECT count(*) INTO property_count FROM jsonb_each(NEW.namespace_properties);
    IF property_count>32 OR EXISTS (
        SELECT 1 FROM jsonb_each(NEW.namespace_properties) p
        WHERE jsonb_typeof(p.value)<>'string' OR p.key LIKE '{DAV:}%'
          OR p.key LIKE '{urn:freightctl}%' OR p.key LIKE '{urn:freightctl:%'
          OR length(p.key)>643 OR length(p.value #>> '{}')=0
    ) THEN
        RAISE EXCEPTION 'invalid namespace property snapshot' USING ERRCODE='23514';
    END IF;
    SELECT kind,payload->'namespace_properties' INTO event_kind,event_properties FROM events
      WHERE (tenant_id,partner_id,event_id)=(NEW.tenant_id,NEW.partner_id,NEW.changed_event_id);
    IF (TG_OP='INSERT' AND NEW.namespace_properties<>'{}'::jsonb)
       OR (TG_OP='UPDATE' AND NEW.namespace_properties IS DISTINCT FROM OLD.namespace_properties) THEN
        IF event_properties IS DISTINCT FROM NEW.namespace_properties
           OR (TG_OP='INSERT' AND event_kind<>'PathPublished')
           OR (TG_OP='UPDATE' AND (event_kind<>'PathAttrsChanged' OR NEW.mode<>OLD.mode OR NEW.modified_at<>OLD.modified_at)) THEN
            RAISE EXCEPTION 'properties require their exact namespace event' USING ERRCODE='23514';
        END IF;
    END IF;
    IF event_properties IS NOT NULL AND event_properties IS DISTINCT FROM NEW.namespace_properties THEN
        RAISE EXCEPTION 'property event differs from namespace snapshot' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER namespace_properties_guard BEFORE INSERT OR UPDATE ON namespace_entries
 FOR EACH ROW EXECUTE FUNCTION freightctl_namespace_properties_guard();
