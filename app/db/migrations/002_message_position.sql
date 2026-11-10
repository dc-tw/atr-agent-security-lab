ALTER TABLE conversation_messages
    ADD COLUMN IF NOT EXISTS position smallint NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_conversation_messages_order
    ON conversation_messages (tenant_id, conversation_id, created_at DESC, position DESC);
