ALTER TABLE atr_policy_versions
    DROP CONSTRAINT IF EXISTS atr_policy_versions_mode_check;

ALTER TABLE atr_policy_versions
    ADD CONSTRAINT atr_policy_versions_mode_check
    CHECK (mode IN ('detection_only', 'shadow', 'blocking'));
