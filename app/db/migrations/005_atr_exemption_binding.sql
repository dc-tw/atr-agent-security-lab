ALTER TABLE atr_exemptions
    ADD COLUMN IF NOT EXISTS bundle_checksum text,
    ADD COLUMN IF NOT EXISTS policy_version integer;
