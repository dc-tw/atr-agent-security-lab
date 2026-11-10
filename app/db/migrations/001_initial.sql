CREATE TABLE IF NOT EXISTS gateway_events (
    event_id uuid PRIMARY KEY,
    tenant_id text NOT NULL,
    event_type text NOT NULL,
    actor_type text NOT NULL,
    actor_id text NOT NULL,
    correlation_id text NOT NULL,
    causation_id text,
    conversation_id text,
    run_id text,
    goal_id text,
    payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_gateway_events_tenant_created
    ON gateway_events (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_gateway_events_correlation
    ON gateway_events (tenant_id, correlation_id, created_at);

CREATE TABLE IF NOT EXISTS conversations (
    tenant_id text NOT NULL,
    conversation_id text NOT NULL,
    summary text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, conversation_id)
);

CREATE TABLE IF NOT EXISTS conversation_messages (
    message_id uuid PRIMARY KEY,
    tenant_id text NOT NULL,
    conversation_id text NOT NULL,
    role text NOT NULL,
    content text NOT NULL,
    model text,
    request_id text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, conversation_id)
        REFERENCES conversations (tenant_id, conversation_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_conversation_messages_context
    ON conversation_messages (tenant_id, conversation_id, created_at DESC);

CREATE TABLE IF NOT EXISTS agent_runs (
    tenant_id text NOT NULL,
    request_id text NOT NULL,
    conversation_id text,
    model text NOT NULL,
    status text NOT NULL,
    state jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, request_id)
);

CREATE TABLE IF NOT EXISTS goals (
    tenant_id text NOT NULL,
    goal_id text NOT NULL,
    status text NOT NULL,
    objective text NOT NULL,
    model text NOT NULL,
    state jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, goal_id)
);
CREATE TABLE IF NOT EXISTS goal_steps (
    tenant_id text NOT NULL,
    goal_id text NOT NULL,
    step_id text NOT NULL,
    position integer NOT NULL,
    status text NOT NULL,
    query text NOT NULL,
    state jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, goal_id, step_id),
    FOREIGN KEY (tenant_id, goal_id)
        REFERENCES goals (tenant_id, goal_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS audit_entries (
    tenant_id text NOT NULL,
    sequence bigint NOT NULL,
    event_id uuid NOT NULL,
    actor_id text NOT NULL,
    action text NOT NULL,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    prev_hash text NOT NULL,
    entry_hash text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, sequence),
    UNIQUE (event_id),
    UNIQUE (tenant_id, entry_hash)
);

CREATE TABLE IF NOT EXISTS atr_policy_versions (
    policy_id uuid PRIMARY KEY,
    tenant_id text NOT NULL,
    version integer NOT NULL,
    mode text NOT NULL CHECK (mode IN ('detection_only', 'blocking')),
    minimum_severity text NOT NULL,
    block_severity text NOT NULL,
    action_map jsonb NOT NULL,
    enabled_rule_ids text[] NOT NULL DEFAULT '{}',
    excluded_rule_ids text[] NOT NULL DEFAULT '{}',
    active boolean NOT NULL DEFAULT false,
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, version)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_atr_policy_one_active
    ON atr_policy_versions (tenant_id) WHERE active;

CREATE TABLE IF NOT EXISTS atr_rule_bundles (
    bundle_id uuid PRIMARY KEY,
    version text NOT NULL,
    checksum text NOT NULL UNIQUE,
    source_path text NOT NULL,
    rule_count integer NOT NULL,
    validation_report jsonb NOT NULL DEFAULT '{}'::jsonb,
    status text NOT NULL,
    active boolean NOT NULL DEFAULT false,
    activated_by text,
    created_at timestamptz NOT NULL DEFAULT now(),
    activated_at timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_atr_bundle_one_active
    ON atr_rule_bundles ((active)) WHERE active;

CREATE TABLE IF NOT EXISTS atr_rules (
    bundle_id uuid NOT NULL REFERENCES atr_rule_bundles(bundle_id) ON DELETE CASCADE,
    rule_id text NOT NULL,
    title text NOT NULL,
    severity text NOT NULL,
    status text NOT NULL,
    tags jsonb NOT NULL DEFAULT '{}'::jsonb,
    condition_count integer NOT NULL DEFAULT 0,
    PRIMARY KEY (bundle_id, rule_id)
);

CREATE TABLE IF NOT EXISTS atr_findings (
    finding_id uuid PRIMARY KEY,
    tenant_id text NOT NULL,
    context_id text NOT NULL,
    request_id text,
    goal_id text,
    model text NOT NULL,
    rule_id text NOT NULL,
    rule_title text NOT NULL,
    severity text NOT NULL,
    confidence text NOT NULL,
    boundary text NOT NULL,
    location text NOT NULL,
    bundle_checksum text,
    policy_version integer,
    content_fingerprint text,
    content_length integer,
    truncated boolean NOT NULL DEFAULT false,
    decision text NOT NULL,
    action text NOT NULL,
    review_status text NOT NULL DEFAULT 'unreviewed',
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_atr_findings_tenant_created
    ON atr_findings (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_atr_findings_rule
    ON atr_findings (tenant_id, rule_id, created_at DESC);

CREATE TABLE IF NOT EXISTS atr_reviews (
    review_id uuid PRIMARY KEY,
    finding_id uuid NOT NULL REFERENCES atr_findings(finding_id) ON DELETE CASCADE,
    tenant_id text NOT NULL,
    verdict text NOT NULL,
    reason text NOT NULL,
    reviewer text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS atr_exemptions (
    exemption_id uuid PRIMARY KEY,
    tenant_id text NOT NULL,
    finding_id uuid REFERENCES atr_findings(finding_id),
    rule_id text NOT NULL,
    boundary text NOT NULL,
    content_fingerprint text NOT NULL,
    remaining_uses integer NOT NULL DEFAULT 1 CHECK (remaining_uses >= 0),
    expires_at timestamptz NOT NULL,
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS atr_enforcement_receipts (
    receipt_id uuid PRIMARY KEY,
    tenant_id text NOT NULL,
    sequence bigint NOT NULL,
    finding_id uuid NOT NULL REFERENCES atr_findings(finding_id),
    rule_id text NOT NULL,
    bundle_checksum text,
    policy_version integer,
    boundary text NOT NULL,
    decision text NOT NULL,
    action text NOT NULL,
    correlation_id text NOT NULL,
    content_stored boolean NOT NULL DEFAULT false,
    prev_hash text NOT NULL,
    receipt_hash text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, sequence),
    UNIQUE (tenant_id, receipt_hash)
);

CREATE TABLE IF NOT EXISTS atr_export_sinks (
    sink_id uuid PRIMARY KEY,
    tenant_id text NOT NULL,
    sink_type text NOT NULL,
    url text NOT NULL,
    encrypted_secret text NOT NULL,
    enabled boolean NOT NULL DEFAULT true,
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS atr_delivery_outbox (
    delivery_id uuid PRIMARY KEY,
    tenant_id text NOT NULL,
    sink_id uuid NOT NULL REFERENCES atr_export_sinks(sink_id) ON DELETE CASCADE,
    receipt_id uuid NOT NULL REFERENCES atr_enforcement_receipts(receipt_id) ON DELETE CASCADE,
    payload jsonb NOT NULL,
    status text NOT NULL DEFAULT 'pending',
    attempts integer NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    last_error text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    delivered_at timestamptz,
    UNIQUE (sink_id, receipt_id)
);
