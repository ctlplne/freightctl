-- Seek a sender's historical UUID page without sorting all of its receipts.
-- Authorization remains in forced RLS and the live source/participant filters.
CREATE INDEX artifact_exchange_sender_history ON artifact_exchanges(tenant_id,partner_id,sender_actor_id,exchange_id);
