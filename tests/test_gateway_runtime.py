import pytest

from app.core.runtime import GatewayRuntime


class DurableStore:
    def __init__(self):
        self.events = []

    async def append_event(self, *args, **kwargs):
        self.events.append((args, kwargs))
        return f"durable-{len(self.events)}"


class EphemeralStore:
    def __init__(self):
        self.agent_events = []
        self.goal_events = []

    async def append_event(self, request_id, event, tenant_id):
        self.agent_events.append((request_id, event, tenant_id))
        return "redis-agent-id"

    async def append_goal_event(self, goal_id, event, tenant_id):
        self.goal_events.append((goal_id, event, tenant_id))
        return "redis-goal-id"


@pytest.mark.asyncio
async def test_runtime_dual_writes_agent_and_goal_events() -> None:
    postgres = DurableStore()
    redis = EphemeralStore()
    runtime = GatewayRuntime(postgres, redis)  # type: ignore[arg-type]

    agent_id = await runtime.append_event("run-1", {"type": "token", "content": "safe"}, "tenant-1")
    goal_id = await runtime.append_goal_event(
        "goal-1", {"type": "goal_status", "status": "paused"}, "tenant-1"
    )

    assert agent_id == "redis-agent-id"
    assert goal_id == "redis-goal-id"
    assert len(postgres.events) == 2
    assert redis.agent_events[0][1]["durable_event_id"] == "durable-1"
    assert redis.goal_events[0][1]["durable_event_id"] == "durable-2"
