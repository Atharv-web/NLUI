ALTER TABLE outbox ADD COLUMN delivery_transport TEXT;
ALTER TABLE outbox ADD COLUMN published_reference TEXT;

CREATE INDEX outbox_delivery_idx
ON outbox(delivery_transport, published_reference);

CREATE TABLE resource_fences (
    resource TEXT PRIMARY KEY,
    last_token INTEGER NOT NULL CHECK(last_token >= 1),
    updated_at TEXT NOT NULL
) STRICT;
