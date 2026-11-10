from __future__ import annotations

import asyncio
from uuid import uuid4

from app.core.config import get_settings
from app.core.postgres_runtime import PostgresRuntime


async def smoke(database_url: str) -> dict[str, object]:
    tenant_id = f"smoke-{uuid4().hex}"
    request_id = str(uuid4())
    conversation_id = str(uuid4())
    goal_id = str(uuid4())
    finding_id = str(uuid4())
    runtime = PostgresRuntime(database_url)
    await runtime.connect()
    try:
        await runtime.save_run_state(
            request_id,
            {
                "conversation_id": conversation_id,
                "model": "smoke-model",
                "status": "running",
            },
            tenant_id,
        )
        assert (await runtime.get_run_state(request_id, tenant_id))["status"] == "running"

        await runtime.append_conversation_turn(
            conversation_id,
            query="smoke question",
            answer="smoke answer",
            model="smoke-model",
            request_id=request_id,
            tenant_id=tenant_id,
        )
        messages = await runtime.get_conversation(conversation_id, tenant_id=tenant_id)
        assert [message["role"] for message in messages] == ["user", "assistant"]

        goal = {
            "goal_id": goal_id,
            "objective": "database smoke test",
            "model": "smoke-model",
            "status": "paused",
            "steps": [],
        }
        await runtime.save_goal(goal_id, goal, tenant_id)
        assert (await runtime.get_goal(goal_id, tenant_id))["status"] == "paused"

        policy = await runtime.create_atr_policy(
            tenant_id,
            {
                "mode": "blocking",
                "minimum_severity": "medium",
                "block_severity": "high",
                "action_map": {
                    "informational": "detect",
                    "low": "detect",
                    "medium": "require_approval",
                    "high": "block",
                    "critical": "quarantine",
                },
                "enabled_rule_ids": [],
                "excluded_rule_ids": [],
            },
            created_by="smoke",
        )
        assert policy["version"] == 1
        rolled_back = await runtime.rollback_atr_policy(tenant_id, 1, created_by="smoke")
        assert rolled_back and rolled_back["version"] == 2

        await runtime.append_event(
            tenant_id,
            "smoke_event",
            {"status": "durable"},
            correlation_id=request_id,
            run_id=request_id,
        )
        assert (
            await runtime.pool.fetchval(
                "SELECT count(*) FROM gateway_events WHERE tenant_id=$1", tenant_id
            )
            == 1
        )

        await runtime.create_export_sink(
            tenant_id,
            sink_type="jsonl",
            url="/tmp/smoke.jsonl",
            encrypted_secret="unused",
            created_by="smoke",
        )

        await runtime.save_threat_findings(
            tenant_id,
            {
                "event_type": "llm_input",
                "location": "smoke",
                "findings": [
                    {
                        "finding_id": finding_id,
                        "rule_id": "ATR-SMOKE-1",
                        "title": "Smoke finding",
                        "severity": "critical",
                        "confidence": "high",
                        "block_candidate": True,
                        "action": "quarantine",
                        "enforcement_action": "quarantined",
                        "content_fingerprint": "a" * 64,
                        "content_length": 42,
                        "policy_version": 2,
                    }
                ],
            },
            context_id=request_id,
            model="smoke-model",
            ttl_seconds=60,
            max_records=10,
        )
        reviewed = await runtime.review_threat_finding(
            tenant_id,
            finding_id,
            review_status="true_positive",
            reason="smoke",
            reviewer="smoke",
            ttl_seconds=60,
        )
        assert reviewed and reviewed["review_status"] == "true_positive"
        deliveries = await runtime.claim_export_deliveries(limit=10)
        assert len(deliveries) == 1
        await runtime.complete_export_delivery(deliveries[0]["delivery_id"])
        receipt_verification = await runtime.verify_enforcement_receipts(tenant_id)
        assert receipt_verification == {
            "valid": True,
            "count": 1,
            "invalid_sequence": None,
        }

        await runtime.append_audit(tenant_id, {"action": "smoke.first", "subject": "smoke"})
        await runtime.append_audit(tenant_id, {"action": "smoke.second", "subject": "smoke"})
        audit_rows = await runtime.pool.fetch(
            """
            SELECT sequence, prev_hash, entry_hash FROM audit_entries
            WHERE tenant_id=$1 ORDER BY sequence
            """,
            tenant_id,
        )
        assert len(audit_rows) == 2
        assert audit_rows[0]["prev_hash"] == "GENESIS"
        assert audit_rows[1]["prev_hash"] == audit_rows[0]["entry_hash"]
        return {
            "status": "ok",
            "tenant_id": tenant_id,
            "policy_versions": 2,
            "audit_chain_entries": 2,
            "enforcement_receipts": receipt_verification["count"],
            "outbox_deliveries": len(deliveries),
            "conversation_messages": len(messages),
        }
    finally:
        async with runtime.pool.acquire() as connection, connection.transaction():
            for table in (
                "atr_delivery_outbox",
                "atr_export_sinks",
                "atr_exemptions",
                "atr_reviews",
                "atr_enforcement_receipts",
                "atr_findings",
                "atr_policy_versions",
                "audit_entries",
                "goal_steps",
                "goals",
                "agent_runs",
                "conversation_messages",
                "conversations",
                "gateway_events",
            ):
                await connection.execute(f"DELETE FROM {table} WHERE tenant_id=$1", tenant_id)
        await runtime.close()


async def main() -> None:
    database_url = get_settings().database_url
    if not database_url:
        raise RuntimeError("DATABASE_URL is required")
    print(await smoke(database_url))


if __name__ == "__main__":
    asyncio.run(main())
