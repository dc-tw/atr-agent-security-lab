ALTER TABLE atr_delivery_outbox
    ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now();

CREATE INDEX IF NOT EXISTS idx_atr_delivery_outbox_ready
    ON atr_delivery_outbox (status, next_attempt_at, updated_at);
