ALTER TABLE events ADD CONSTRAINT events_kind_bounded
    CHECK (kind ~ '^[A-Za-z][A-Za-z0-9]{0,127}$');
ALTER TABLE events ADD CONSTRAINT events_payload_bounded
    CHECK (octet_length(convert_to(payload::text,'UTF8')) <= 65536);
