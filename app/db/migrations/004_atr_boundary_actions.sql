ALTER TABLE atr_policy_versions
    ADD COLUMN IF NOT EXISTS boundary_action_map jsonb NOT NULL DEFAULT '{}'::jsonb;

UPDATE atr_policy_versions
SET boundary_action_map = jsonb_build_object(
    'request_input', action_map,
    'planner_output', action_map,
    'tool_call', action_map,
    'tool_response', action_map,
    'model_output', action_map
)
WHERE boundary_action_map = '{}'::jsonb;
