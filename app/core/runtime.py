from __future__ import annotations

from typing import Any

from app.core.postgres_runtime import PostgresRuntime
from app.core.redis_runtime import RedisRuntime


class GatewayRuntime:
    """Routes durable operations to PostgreSQL and ephemeral operations to Redis."""

    _DURABLE_METHODS = frozenset(
        {
            "append_audit",
            "activate_atr_rule_bundle",
            "append_conversation_turn",
            "claim_export_deliveries",
            "complete_export_delivery",
            "create_export_sink",
            "delete_conversation",
            "delete_export_sink",
            "get_conversation",
            "get_conversation_context",
            "get_active_atr_policy",
            "get_atr_rule_bundle",
            "get_active_atr_rule_bundle",
            "get_goal",
            "get_run_state",
            "get_threat_finding",
            "list_goal_ids",
            "list_goal_tenants",
            "list_atr_policy_versions",
            "list_atr_rule_bundles",
            "list_atr_rules",
            "list_enforcement_receipts",
            "list_export_sinks",
            "list_threat_findings",
            "review_threat_finding",
            "retry_export_delivery",
            "create_atr_policy",
            "create_atr_exemption",
            "rollback_atr_policy",
            "verify_enforcement_receipts",
            "consume_atr_exemption",
            "save_goal",
            "save_run_state",
            "save_threat_findings",
        }
    )

    def __init__(self, postgres: PostgresRuntime, redis: RedisRuntime) -> None:
        self.postgres = postgres
        self.redis = redis

    def __getattr__(self, name: str) -> Any:
        target = self.postgres if name in self._DURABLE_METHODS else self.redis
        return getattr(target, name)

    async def append_event(
        self, request_id: str, event: dict[str, Any], tenant_id: str = "default"
    ) -> str:
        durable_event_id = await self.postgres.append_event(
            tenant_id,
            str(event.get("type", "agent_event")),
            event,
            actor_type="agent",
            actor_id="gateway",
            correlation_id=request_id,
            run_id=request_id,
        )
        replay_event = {**event, "durable_event_id": durable_event_id}
        return await self.redis.append_event(request_id, replay_event, tenant_id)

    async def append_goal_event(
        self, goal_id: str, event: dict[str, Any], tenant_id: str = "default"
    ) -> str:
        durable_event_id = await self.postgres.append_event(
            tenant_id,
            str(event.get("type", "goal_event")),
            event,
            actor_type="goal_worker",
            actor_id="worker",
            correlation_id=goal_id,
            goal_id=goal_id,
        )
        replay_event = {**event, "durable_event_id": durable_event_id}
        return await self.redis.append_goal_event(goal_id, replay_event, tenant_id)

    async def ping(self) -> bool:
        postgres, redis = await self.postgres.ping(), await self.redis.ping()
        return postgres and redis

    async def close(self) -> None:
        await self.postgres.close()
        await self.redis.close()
