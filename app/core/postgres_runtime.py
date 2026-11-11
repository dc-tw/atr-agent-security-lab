from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import asyncpg


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _record(value: asyncpg.Record | None) -> dict[str, Any] | None:
    if value is None:
        return None
    result = dict(value)
    for key, item in tuple(result.items()):
        if isinstance(item, UUID):
            result[key] = str(item)
        elif isinstance(item, datetime):
            result[key] = item.isoformat()
    return result


def _object(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        decoded = json.loads(value)
        return dict(decoded) if isinstance(decoded, dict) else {}
    return dict(value) if value is not None else {}


class PostgresRuntime:
    """Durable tenant-scoped state and append-only security records."""

    def __init__(
        self,
        database_url: str,
        *,
        min_size: int = 1,
        max_size: int = 10,
        command_timeout: float = 30.0,
    ) -> None:
        self._database_url = database_url
        self._min_size = min_size
        self._max_size = max_size
        self._command_timeout = command_timeout
        self._pool: asyncpg.Pool | None = None

    async def connect(self) -> None:
        if self._pool is None:
            self._pool = await asyncpg.create_pool(
                self._database_url,
                min_size=self._min_size,
                max_size=self._max_size,
                command_timeout=self._command_timeout,
            )

    @property
    def pool(self) -> asyncpg.Pool:
        if self._pool is None:
            raise RuntimeError("PostgreSQL runtime is not connected")
        return self._pool

    async def ping(self) -> bool:
        return bool(await self.pool.fetchval("SELECT true"))

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None

    async def append_event(
        self,
        tenant_id: str,
        event_type: str,
        payload: dict[str, Any],
        *,
        actor_type: str = "system",
        actor_id: str = "gateway",
        correlation_id: str,
        causation_id: str | None = None,
        conversation_id: str | None = None,
        run_id: str | None = None,
        goal_id: str | None = None,
    ) -> str:
        event_id = uuid4()
        await self.pool.execute(
            """
            INSERT INTO gateway_events(
                event_id, tenant_id, event_type, actor_type, actor_id,
                correlation_id, causation_id, conversation_id, run_id, goal_id, payload
            ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb)
            """,
            event_id,
            tenant_id,
            event_type,
            actor_type,
            actor_id,
            correlation_id,
            causation_id,
            conversation_id,
            run_id,
            goal_id,
            _json(payload),
        )
        return str(event_id)

    async def save_run_state(
        self, request_id: str, state: dict[str, Any], tenant_id: str = "default"
    ) -> None:
        await self.pool.execute(
            """
            INSERT INTO agent_runs(
                tenant_id, request_id, conversation_id, model, status, state
            ) VALUES($1,$2,$3,$4,$5,$6::jsonb)
            ON CONFLICT (tenant_id, request_id) DO UPDATE SET
                conversation_id=EXCLUDED.conversation_id,
                model=EXCLUDED.model,
                status=EXCLUDED.status,
                state=EXCLUDED.state,
                updated_at=now()
            """,
            tenant_id,
            request_id,
            state.get("conversation_id"),
            str(state.get("model", "unknown")),
            str(state.get("status", "unknown")),
            _json(state),
        )

    async def get_run_state(
        self, request_id: str, tenant_id: str = "default"
    ) -> dict[str, Any] | None:
        value = await self.pool.fetchval(
            "SELECT state FROM agent_runs WHERE tenant_id=$1 AND request_id=$2",
            tenant_id,
            request_id,
        )
        return _object(value) if value is not None else None

    async def list_pending_agent_approvals(
        self, tenant_id: str = "default", limit: int = 100
    ) -> list[dict[str, Any]]:
        rows = await self.pool.fetch(
            """
            SELECT request_id, model, updated_at, state->'pending_approval' AS approval
            FROM agent_runs
            WHERE tenant_id=$1 AND status='waiting_approval'
            ORDER BY updated_at DESC LIMIT $2
            """,
            tenant_id,
            limit,
        )
        return [
            {
                "request_id": str(row["request_id"]),
                "model": str(row["model"]),
                "updated_at": row["updated_at"].isoformat(),
                **(_object(row["approval"]) or {}),
            }
            for row in rows
        ]

    async def get_conversation(
        self, conversation_id: str, limit: int = 40, tenant_id: str = "default"
    ) -> list[dict[str, str]]:
        rows = await self.pool.fetch(
            """
            SELECT role, content, model, request_id, created_at
            FROM conversation_messages
            WHERE tenant_id=$1 AND conversation_id=$2
            ORDER BY created_at DESC, position DESC, message_id DESC
            LIMIT $3
            """,
            tenant_id,
            conversation_id,
            limit,
        )
        return [
            {
                "role": row["role"],
                "content": row["content"],
                "request_id": row["request_id"],
                "created_at": row["created_at"].isoformat(),
                **({"model": row["model"]} if row["model"] else {}),
            }
            for row in reversed(rows)
        ]

    async def get_conversation_context(
        self,
        conversation_id: str,
        *,
        query: str,
        limit: int = 40,
        tenant_id: str = "default",
    ) -> list[dict[str, str]]:
        del query
        summary = await self.pool.fetchval(
            "SELECT summary FROM conversations WHERE tenant_id=$1 AND conversation_id=$2",
            tenant_id,
            conversation_id,
        )
        context: list[dict[str, str]] = []
        if summary:
            context.append({"role": "memory_summary", "content": str(summary)})
        context.extend(await self.get_conversation(conversation_id, limit, tenant_id))
        return context

    async def append_conversation_turn(
        self,
        conversation_id: str,
        *,
        query: str,
        answer: str,
        model: str,
        request_id: str,
        max_turns: int = 40,
        ttl_seconds: int = 604_800,
        tenant_id: str = "default",
    ) -> None:
        del ttl_seconds
        async with self.pool.acquire() as connection, connection.transaction():
            await connection.execute(
                """
                INSERT INTO conversations(tenant_id, conversation_id)
                VALUES($1,$2)
                ON CONFLICT (tenant_id, conversation_id)
                DO UPDATE SET updated_at=now()
                """,
                tenant_id,
                conversation_id,
            )
            await connection.executemany(
                """
                INSERT INTO conversation_messages(
                    message_id, tenant_id, conversation_id, role, content, model,
                    request_id, position
                ) VALUES($1,$2,$3,$4,$5,$6,$7,$8)
                """,
                [
                    (
                        uuid4(),
                        tenant_id,
                        conversation_id,
                        "user",
                        query,
                        None,
                        request_id,
                        0,
                    ),
                    (
                        uuid4(),
                        tenant_id,
                        conversation_id,
                        "assistant",
                        answer,
                        model,
                        request_id,
                        1,
                    ),
                ],
            )
            overflow = await connection.fetch(
                """
                SELECT message_id, role, content FROM conversation_messages
                WHERE tenant_id=$1 AND conversation_id=$2
                ORDER BY created_at DESC, position DESC, message_id DESC
                OFFSET $3
                """,
                tenant_id,
                conversation_id,
                max_turns * 2,
            )
            if overflow:
                old_summary = await connection.fetchval(
                    """
                    SELECT summary FROM conversations
                    WHERE tenant_id=$1 AND conversation_id=$2
                    """,
                    tenant_id,
                    conversation_id,
                )
                fragments = [f"{row['role']}: {row['content']}" for row in reversed(overflow)]
                summary = ((old_summary or "") + "\n" + "\n".join(fragments)).strip()[-8_000:]
                await connection.execute(
                    """
                    UPDATE conversations SET summary=$3, updated_at=now()
                    WHERE tenant_id=$1 AND conversation_id=$2
                    """,
                    tenant_id,
                    conversation_id,
                    summary,
                )
                await connection.execute(
                    "DELETE FROM conversation_messages WHERE message_id = ANY($1::uuid[])",
                    [row["message_id"] for row in overflow],
                )

    async def delete_conversation(self, conversation_id: str, tenant_id: str = "default") -> bool:
        result = await self.pool.execute(
            "DELETE FROM conversations WHERE tenant_id=$1 AND conversation_id=$2",
            tenant_id,
            conversation_id,
        )
        return result != "DELETE 0"

    async def save_goal(
        self, goal_id: str, goal: dict[str, Any], tenant_id: str = "default"
    ) -> None:
        await self.pool.execute(
            """
            INSERT INTO goals(tenant_id, goal_id, status, objective, model, state)
            VALUES($1,$2,$3,$4,$5,$6::jsonb)
            ON CONFLICT (tenant_id, goal_id) DO UPDATE SET
                status=EXCLUDED.status,
                objective=EXCLUDED.objective,
                model=EXCLUDED.model,
                state=EXCLUDED.state,
                updated_at=now()
            """,
            tenant_id,
            goal_id,
            str(goal.get("status", "unknown")),
            str(goal.get("objective", "")),
            str(goal.get("model", "unknown")),
            _json(goal),
        )

    async def get_goal(self, goal_id: str, tenant_id: str = "default") -> dict[str, Any] | None:
        value = await self.pool.fetchval(
            "SELECT state FROM goals WHERE tenant_id=$1 AND goal_id=$2",
            tenant_id,
            goal_id,
        )
        return _object(value) if value is not None else None

    async def list_goal_ids(self, tenant_id: str = "default") -> list[str]:
        rows = await self.pool.fetch(
            "SELECT goal_id FROM goals WHERE tenant_id=$1 ORDER BY created_at", tenant_id
        )
        return [row["goal_id"] for row in rows]

    async def list_goal_tenants(self) -> list[str]:
        rows = await self.pool.fetch("SELECT DISTINCT tenant_id FROM goals ORDER BY tenant_id")
        return [row["tenant_id"] for row in rows]

    async def append_audit(self, tenant_id: str, event: dict[str, Any]) -> str:
        event_id = uuid4()
        async with self.pool.acquire() as connection, connection.transaction():
            await connection.execute("SELECT pg_advisory_xact_lock(hashtext($1))", tenant_id)
            previous = await connection.fetchrow(
                """
                SELECT sequence, entry_hash FROM audit_entries
                WHERE tenant_id=$1 ORDER BY sequence DESC LIMIT 1
                """,
                tenant_id,
            )
            sequence = int(previous["sequence"]) + 1 if previous else 1
            prev_hash = str(previous["entry_hash"]) if previous else "GENESIS"
            actor_id = str(event.get("subject", "system"))
            action = str(event.get("action", "unknown"))
            canonical = _json(
                {
                    "tenant_id": tenant_id,
                    "sequence": sequence,
                    "event_id": str(event_id),
                    "actor_id": actor_id,
                    "action": action,
                    "metadata": event,
                    "prev_hash": prev_hash,
                }
            )
            entry_hash = hashlib.sha256(canonical.encode()).hexdigest()
            await connection.execute(
                """
                INSERT INTO audit_entries(
                    tenant_id, sequence, event_id, actor_id, action, metadata,
                    prev_hash, entry_hash
                ) VALUES($1,$2,$3,$4,$5,$6::jsonb,$7,$8)
                """,
                tenant_id,
                sequence,
                event_id,
                actor_id,
                action,
                _json(event),
                prev_hash,
                entry_hash,
            )
        return str(event_id)

    async def save_threat_findings(
        self,
        tenant_id: str,
        event: dict[str, Any],
        *,
        context_id: str,
        model: str,
        ttl_seconds: int,
        max_records: int,
    ) -> list[dict[str, Any]]:
        del ttl_seconds, max_records
        records: list[dict[str, Any]] = []
        for finding in event.get("findings", []):
            if not isinstance(finding, dict) or not finding.get("finding_id"):
                continue
            finding_id = UUID(str(finding["finding_id"]))
            enforcement_status = str(finding.get("enforcement_action", "detected"))
            action = str(
                finding.get(
                    "action",
                    {
                        "blocked": "block",
                        "quarantined": "quarantine",
                        "approval_required": "require_approval",
                    }.get(enforcement_status, "detect"),
                )
            )
            record = {
                "finding_id": str(finding_id),
                "context_id": context_id,
                "model": model,
                "rule_id": str(finding.get("rule_id", "")),
                "title": str(finding.get("title", "")),
                "severity": str(finding.get("severity", "unknown")),
                "confidence": str(finding.get("confidence", "unknown")),
                "event_type": str(event.get("event_type", "unknown")),
                "location": str(event.get("location", "unknown")),
                "block_candidate": bool(finding.get("block_candidate", False)),
                "action": action,
                "enforcement_status": enforcement_status,
                "review_status": "unreviewed",
                "review_reason": "",
                "reviewed_by": "",
                "reviewed_at": "",
                "created_at": datetime.now(UTC).isoformat(),
            }
            async with self.pool.acquire() as connection, connection.transaction():
                inserted = await connection.execute(
                    """
                    INSERT INTO atr_findings(
                        finding_id, tenant_id, context_id, request_id, goal_id, model,
                        rule_id, rule_title, severity, confidence, boundary, location,
                        bundle_checksum, policy_version, content_fingerprint,
                        content_length, truncated, decision, action
                    ) VALUES(
                        $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19
                    )
                    ON CONFLICT (finding_id) DO NOTHING
                    """,
                    finding_id,
                    tenant_id,
                    context_id,
                    context_id if event.get("event_type") != "goal" else None,
                    context_id if event.get("event_type") == "goal" else None,
                    model,
                    record["rule_id"],
                    record["title"],
                    record["severity"],
                    record["confidence"],
                    record["event_type"],
                    record["location"],
                    finding.get("bundle_checksum"),
                    int(finding.get("policy_version", 0)),
                    finding.get("content_fingerprint"),
                    int(finding.get("content_length", 0)),
                    bool(event.get("truncated", False)),
                    enforcement_status,
                    action,
                )
                if inserted == "INSERT 0 1":
                    receipt = await self._create_enforcement_receipt(
                        connection,
                        tenant_id,
                        finding_id=str(finding_id),
                        rule_id=record["rule_id"],
                        bundle_checksum=finding.get("bundle_checksum"),
                        policy_version=int(finding.get("policy_version", 0)),
                        boundary=record["event_type"],
                        decision=enforcement_status,
                        action=action,
                        correlation_id=context_id,
                    )
                    record["receipt_id"] = receipt["receipt_id"]
            records.append(record)
        return records

    async def create_enforcement_receipt(
        self,
        tenant_id: str,
        *,
        finding_id: str,
        rule_id: str,
        bundle_checksum: str | None,
        policy_version: int,
        boundary: str,
        decision: str,
        action: str,
        correlation_id: str,
    ) -> dict[str, Any]:
        async with self.pool.acquire() as connection, connection.transaction():
            return await self._create_enforcement_receipt(
                connection,
                tenant_id,
                finding_id=finding_id,
                rule_id=rule_id,
                bundle_checksum=bundle_checksum,
                policy_version=policy_version,
                boundary=boundary,
                decision=decision,
                action=action,
                correlation_id=correlation_id,
            )

    async def _create_enforcement_receipt(
        self,
        connection: asyncpg.Connection,
        tenant_id: str,
        *,
        finding_id: str,
        rule_id: str,
        bundle_checksum: str | None,
        policy_version: int,
        boundary: str,
        decision: str,
        action: str,
        correlation_id: str,
    ) -> dict[str, Any]:
        receipt_id = uuid4()
        await connection.execute(
            "SELECT pg_advisory_xact_lock(hashtext($1))", f"receipt:{tenant_id}"
        )
        existing = await connection.fetchrow(
            """
            SELECT * FROM atr_enforcement_receipts
            WHERE tenant_id=$1 AND finding_id=$2::uuid AND decision=$3
              AND correlation_id=$4
            ORDER BY sequence DESC LIMIT 1
            """,
            tenant_id,
            finding_id,
            decision,
            correlation_id,
        )
        if existing is not None:
            return _record(existing) or {}
        previous = await connection.fetchrow(
            """
            SELECT sequence, receipt_hash FROM atr_enforcement_receipts
            WHERE tenant_id=$1 ORDER BY sequence DESC LIMIT 1
            """,
            tenant_id,
        )
        sequence = int(previous["sequence"]) + 1 if previous else 1
        prev_hash = str(previous["receipt_hash"]) if previous else "GENESIS"
        values = {
            "receipt_id": str(receipt_id),
            "tenant_id": tenant_id,
            "sequence": sequence,
            "finding_id": finding_id,
            "rule_id": rule_id,
            "bundle_checksum": bundle_checksum,
            "policy_version": policy_version,
            "boundary": boundary,
            "decision": decision,
            "action": action,
            "correlation_id": correlation_id,
            "content_stored": False,
            "prev_hash": prev_hash,
        }
        receipt_hash = hashlib.sha256(_json(values).encode()).hexdigest()
        row = await connection.fetchrow(
            """
                INSERT INTO atr_enforcement_receipts(
                    receipt_id, tenant_id, sequence, finding_id, rule_id,
                    bundle_checksum, policy_version, boundary, decision, action,
                    correlation_id, content_stored, prev_hash, receipt_hash
                ) VALUES($1,$2,$3,$4::uuid,$5,$6,$7,$8,$9,$10,$11,false,$12,$13)
                RETURNING *
                """,
            receipt_id,
            tenant_id,
            sequence,
            finding_id,
            rule_id,
            bundle_checksum,
            policy_version,
            boundary,
            decision,
            action,
            correlation_id,
            prev_hash,
            receipt_hash,
        )
        sinks = await connection.fetch(
            """
                SELECT sink_id FROM atr_export_sinks
                WHERE tenant_id=$1 AND enabled=true
                """,
            tenant_id,
        )
        receipt_payload = _record(row) or {}
        if sinks:
            await connection.executemany(
                """
                    INSERT INTO atr_delivery_outbox(
                        delivery_id, tenant_id, sink_id, receipt_id, payload
                    ) VALUES($1,$2,$3,$4,$5::jsonb)
                    ON CONFLICT (sink_id, receipt_id) DO NOTHING
                    """,
                [
                    (
                        uuid4(),
                        tenant_id,
                        sink["sink_id"],
                        receipt_id,
                        _json(receipt_payload),
                    )
                    for sink in sinks
                ],
            )
        result = _record(row)
        if result is None:
            raise RuntimeError("Failed to create ATR enforcement receipt")
        return result

    async def list_enforcement_receipts(
        self, tenant_id: str, *, limit: int = 100
    ) -> list[dict[str, Any]]:
        rows = await self.pool.fetch(
            """
            SELECT * FROM atr_enforcement_receipts
            WHERE tenant_id=$1 ORDER BY sequence DESC LIMIT $2
            """,
            tenant_id,
            limit,
        )
        return [record for row in rows if (record := _record(row))]

    async def verify_enforcement_receipts(self, tenant_id: str) -> dict[str, Any]:
        rows = await self.pool.fetch(
            """
            SELECT * FROM atr_enforcement_receipts
            WHERE tenant_id=$1 ORDER BY sequence
            """,
            tenant_id,
        )
        previous = "GENESIS"
        for row in rows:
            values = {
                "receipt_id": str(row["receipt_id"]),
                "tenant_id": row["tenant_id"],
                "sequence": row["sequence"],
                "finding_id": str(row["finding_id"]),
                "rule_id": row["rule_id"],
                "bundle_checksum": row["bundle_checksum"],
                "policy_version": row["policy_version"],
                "boundary": row["boundary"],
                "decision": row["decision"],
                "action": row["action"],
                "correlation_id": row["correlation_id"],
                "content_stored": row["content_stored"],
                "prev_hash": row["prev_hash"],
            }
            expected = hashlib.sha256(_json(values).encode()).hexdigest()
            if row["prev_hash"] != previous or row["receipt_hash"] != expected:
                return {
                    "valid": False,
                    "count": len(rows),
                    "invalid_sequence": row["sequence"],
                }
            previous = row["receipt_hash"]
        return {"valid": True, "count": len(rows), "invalid_sequence": None}

    async def create_export_sink(
        self,
        tenant_id: str,
        *,
        sink_type: str,
        url: str,
        encrypted_secret: str,
        created_by: str,
    ) -> dict[str, Any]:
        row = await self.pool.fetchrow(
            """
            INSERT INTO atr_export_sinks(
                sink_id, tenant_id, sink_type, url, encrypted_secret, created_by
            ) VALUES($1,$2,$3,$4,$5,$6) RETURNING *
            """,
            uuid4(),
            tenant_id,
            sink_type,
            url,
            encrypted_secret,
            created_by,
        )
        result = _record(row) or {}
        result.pop("encrypted_secret", None)
        return result

    async def list_export_sinks(self, tenant_id: str) -> list[dict[str, Any]]:
        rows = await self.pool.fetch(
            """
            SELECT sink_id, tenant_id, sink_type, url, enabled, created_by, created_at
            FROM atr_export_sinks WHERE tenant_id=$1 ORDER BY created_at DESC
            """,
            tenant_id,
        )
        return [record for row in rows if (record := _record(row))]

    async def delete_export_sink(self, tenant_id: str, sink_id: str) -> bool:
        result = await self.pool.execute(
            "DELETE FROM atr_export_sinks WHERE tenant_id=$1 AND sink_id=$2::uuid",
            tenant_id,
            sink_id,
        )
        return result != "DELETE 0"

    async def claim_export_deliveries(self, *, limit: int = 20) -> list[dict[str, Any]]:
        async with self.pool.acquire() as connection, connection.transaction():
            rows = await connection.fetch(
                """
                SELECT o.delivery_id, o.tenant_id, o.payload, o.attempts,
                       s.sink_type, s.url, s.encrypted_secret
                FROM atr_delivery_outbox o
                JOIN atr_export_sinks s ON s.sink_id=o.sink_id
                WHERE (
                    o.status IN ('pending', 'retry') AND o.next_attempt_at <= now()
                  OR o.status='delivering' AND o.updated_at < now() - interval '5 minutes'
                )
                  AND s.enabled=true
                ORDER BY o.next_attempt_at, o.created_at
                LIMIT $1 FOR UPDATE OF o SKIP LOCKED
                """,
                limit,
            )
            if rows:
                await connection.execute(
                    """
                    UPDATE atr_delivery_outbox
                    SET status='delivering', attempts=attempts+1, updated_at=now()
                    WHERE delivery_id = ANY($1::uuid[])
                    """,
                    [row["delivery_id"] for row in rows],
                )
        records = []
        for row in rows:
            record = _record(row) or {}
            record["payload"] = _object(record["payload"])
            record["attempts"] = int(record["attempts"]) + 1
            records.append(record)
        return records

    async def complete_export_delivery(self, delivery_id: str) -> None:
        await self.pool.execute(
            """
            UPDATE atr_delivery_outbox SET status='delivered', delivered_at=now(),
                last_error='', updated_at=now()
            WHERE delivery_id=$1::uuid
            """,
            delivery_id,
        )

    async def retry_export_delivery(
        self,
        delivery_id: str,
        *,
        error: str,
        retry_seconds: int,
        terminal: bool,
    ) -> None:
        await self.pool.execute(
            """
            UPDATE atr_delivery_outbox SET status=$2, last_error=$3,
                next_attempt_at=now() + make_interval(secs => $4), updated_at=now()
            WHERE delivery_id=$1::uuid
            """,
            delivery_id,
            "dead" if terminal else "retry",
            error[:2_000],
            retry_seconds,
        )

    async def get_threat_finding(self, tenant_id: str, finding_id: str) -> dict[str, Any] | None:
        row = await self.pool.fetchrow(
            """
            SELECT f.*,
              r.verdict AS latest_verdict, r.reason AS latest_reason,
              r.reviewer AS latest_reviewer, r.created_at AS reviewed_at
            FROM atr_findings f
            LEFT JOIN LATERAL (
                SELECT verdict, reason, reviewer, created_at FROM atr_reviews
                WHERE finding_id=f.finding_id ORDER BY created_at DESC LIMIT 1
            ) r ON true
            WHERE f.tenant_id=$1 AND f.finding_id=$2::uuid
            """,
            tenant_id,
            finding_id,
        )
        return self._finding_record(row)

    @staticmethod
    def _finding_record(row: asyncpg.Record | None) -> dict[str, Any] | None:
        base = _record(row)
        if base is None:
            return None
        verdict = base.pop("latest_verdict", None)
        reason = base.pop("latest_reason", None)
        reviewer = base.pop("latest_reviewer", None)
        reviewed_at = base.get("reviewed_at")
        base.update(
            {
                "title": base.pop("rule_title"),
                "event_type": base.pop("boundary"),
                "action": base.get("action"),
                "enforcement_status": base.get("decision"),
                "block_candidate": base.get("action") in {"block", "quarantine"},
                "review_status": verdict or base.get("review_status", "unreviewed"),
                "review_reason": reason or "",
                "reviewed_by": reviewer or "",
                "reviewed_at": reviewed_at or "",
            }
        )
        return base

    async def list_threat_findings(
        self,
        tenant_id: str,
        *,
        limit: int = 100,
        review_status: str = "",
        rule_id: str = "",
    ) -> list[dict[str, Any]]:
        rows = await self.pool.fetch(
            """
            SELECT f.*,
              r.verdict AS latest_verdict, r.reason AS latest_reason,
              r.reviewer AS latest_reviewer, r.created_at AS reviewed_at
            FROM atr_findings f
            LEFT JOIN LATERAL (
                SELECT verdict, reason, reviewer, created_at FROM atr_reviews
                WHERE finding_id=f.finding_id ORDER BY created_at DESC LIMIT 1
            ) r ON true
            WHERE f.tenant_id=$1
              AND ($2='' OR COALESCE(r.verdict, f.review_status)=$2)
              AND ($3='' OR f.rule_id=$3)
            ORDER BY f.created_at DESC LIMIT $4
            """,
            tenant_id,
            review_status,
            rule_id,
            limit,
        )
        return [record for row in rows if (record := self._finding_record(row))]

    async def review_threat_finding(
        self,
        tenant_id: str,
        finding_id: str,
        *,
        review_status: str,
        reason: str,
        reviewer: str,
        ttl_seconds: int,
    ) -> dict[str, Any] | None:
        del ttl_seconds
        exists = await self.pool.fetchval(
            "SELECT true FROM atr_findings WHERE tenant_id=$1 AND finding_id=$2::uuid",
            tenant_id,
            finding_id,
        )
        if not exists:
            return None
        await self.pool.execute(
            """
            INSERT INTO atr_reviews(
                review_id, finding_id, tenant_id, verdict, reason, reviewer
            ) VALUES($1,$2::uuid,$3,$4,$5,$6)
            """,
            uuid4(),
            finding_id,
            tenant_id,
            review_status,
            reason,
            reviewer,
        )
        return await self.get_threat_finding(tenant_id, finding_id)

    @staticmethod
    def _policy_record(row: asyncpg.Record | None) -> dict[str, Any] | None:
        base = _record(row)
        if base is None:
            return None
        base["action_map"] = _object(base.get("action_map"))
        base["boundary_action_map"] = _object(base.get("boundary_action_map"))
        base["mode"] = str(base["mode"])
        base["enabled_rule_ids"] = list(base.get("enabled_rule_ids") or [])
        base["excluded_rule_ids"] = list(base.get("excluded_rule_ids") or [])
        return base

    async def get_active_atr_policy(self, tenant_id: str) -> dict[str, Any] | None:
        row = await self.pool.fetchrow(
            """
            SELECT * FROM atr_policy_versions
            WHERE tenant_id=$1 AND active=true
            """,
            tenant_id,
        )
        return self._policy_record(row)

    async def list_atr_policy_versions(
        self, tenant_id: str, *, limit: int = 100
    ) -> list[dict[str, Any]]:
        rows = await self.pool.fetch(
            """
            SELECT * FROM atr_policy_versions WHERE tenant_id=$1
            ORDER BY version DESC LIMIT $2
            """,
            tenant_id,
            limit,
        )
        return [policy for row in rows if (policy := self._policy_record(row))]

    async def create_atr_policy(
        self,
        tenant_id: str,
        policy: dict[str, Any],
        *,
        created_by: str,
    ) -> dict[str, Any]:
        policy_id = uuid4()
        async with self.pool.acquire() as connection, connection.transaction():
            await connection.execute("SELECT pg_advisory_xact_lock(hashtext($1))", tenant_id)
            version = int(
                await connection.fetchval(
                    """
                    SELECT COALESCE(MAX(version), 0) + 1
                    FROM atr_policy_versions WHERE tenant_id=$1
                    """,
                    tenant_id,
                )
            )
            await connection.execute(
                "UPDATE atr_policy_versions SET active=false WHERE tenant_id=$1 AND active",
                tenant_id,
            )
            row = await connection.fetchrow(
                """
                INSERT INTO atr_policy_versions(
                    policy_id, tenant_id, version, mode, minimum_severity,
                    block_severity, action_map, boundary_action_map, enabled_rule_ids,
                    excluded_rule_ids, active, created_by
                ) VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb,$9,$10,true,$11)
                RETURNING *
                """,
                policy_id,
                tenant_id,
                version,
                policy["mode"],
                policy["minimum_severity"],
                policy["block_severity"],
                _json(policy["action_map"]),
                _json(policy["boundary_action_map"]),
                policy.get("enabled_rule_ids", []),
                policy.get("excluded_rule_ids", []),
                created_by,
            )
        result = self._policy_record(row)
        if result is None:
            raise RuntimeError("Failed to create ATR policy")
        return result

    async def rollback_atr_policy(
        self, tenant_id: str, version: int, *, created_by: str
    ) -> dict[str, Any] | None:
        source = await self.pool.fetchrow(
            """
            SELECT * FROM atr_policy_versions
            WHERE tenant_id=$1 AND version=$2
            """,
            tenant_id,
            version,
        )
        policy = self._policy_record(source)
        if policy is None:
            return None
        return await self.create_atr_policy(
            tenant_id,
            {
                "mode": policy["mode"],
                "minimum_severity": policy["minimum_severity"],
                "block_severity": policy["block_severity"],
                "action_map": policy["action_map"],
                "boundary_action_map": policy["boundary_action_map"],
                "enabled_rule_ids": policy["enabled_rule_ids"],
                "excluded_rule_ids": policy["excluded_rule_ids"],
            },
            created_by=created_by,
        )

    @staticmethod
    def _bundle_record(row: asyncpg.Record | None) -> dict[str, Any] | None:
        base = _record(row)
        if base is None:
            return None
        base["validation_report"] = _object(base.get("validation_report"))
        return base

    async def activate_atr_rule_bundle(
        self, manifest: dict[str, Any], *, activated_by: str
    ) -> dict[str, Any]:
        bundle_id = uuid4()
        async with self.pool.acquire() as connection, connection.transaction():
            await connection.execute("SELECT pg_advisory_xact_lock($1)", 8_428_602)
            existing = await connection.fetchrow(
                "SELECT * FROM atr_rule_bundles WHERE checksum=$1",
                manifest["checksum"],
            )
            await connection.execute("UPDATE atr_rule_bundles SET active=false WHERE active")
            if existing:
                bundle_id = existing["bundle_id"]
                row = await connection.fetchrow(
                    """
                    UPDATE atr_rule_bundles SET
                        active=true, status='active', activated_by=$2, activated_at=now()
                    WHERE bundle_id=$1 RETURNING *
                    """,
                    bundle_id,
                    activated_by,
                )
            else:
                row = await connection.fetchrow(
                    """
                    INSERT INTO atr_rule_bundles(
                        bundle_id, version, checksum, source_path, rule_count,
                        validation_report, status, active, activated_by, activated_at
                    ) VALUES($1,$2,$3,$4,$5,$6::jsonb,'active',true,$7,now())
                    RETURNING *
                    """,
                    bundle_id,
                    manifest["version"],
                    manifest["checksum"],
                    manifest["source_path"],
                    manifest["rule_count"],
                    _json(manifest["validation_report"]),
                    activated_by,
                )
                await connection.executemany(
                    """
                    INSERT INTO atr_rules(
                        bundle_id, rule_id, title, severity, status, tags, condition_count
                    ) VALUES($1,$2,$3,$4,$5,$6::jsonb,$7)
                    """,
                    [
                        (
                            bundle_id,
                            rule["rule_id"],
                            rule["title"],
                            rule["severity"],
                            rule["status"],
                            _json(rule["tags"]),
                            rule["condition_count"],
                        )
                        for rule in manifest["rules"]
                    ],
                )
        result = self._bundle_record(row)
        if result is None:
            raise RuntimeError("Failed to activate ATR rule bundle")
        return result

    async def list_atr_rule_bundles(self, *, limit: int = 100) -> list[dict[str, Any]]:
        rows = await self.pool.fetch(
            "SELECT * FROM atr_rule_bundles ORDER BY created_at DESC LIMIT $1", limit
        )
        return [bundle for row in rows if (bundle := self._bundle_record(row))]

    async def get_atr_rule_bundle(self, bundle_id: str) -> dict[str, Any] | None:
        row = await self.pool.fetchrow(
            "SELECT * FROM atr_rule_bundles WHERE bundle_id=$1::uuid", bundle_id
        )
        return self._bundle_record(row)

    async def get_active_atr_rule_bundle(self) -> dict[str, Any] | None:
        row = await self.pool.fetchrow("SELECT * FROM atr_rule_bundles WHERE active=true")
        return self._bundle_record(row)

    async def list_atr_rules(self, bundle_id: str, *, limit: int = 2_000) -> list[dict[str, Any]]:
        rows = await self.pool.fetch(
            """
            SELECT rule_id, title, severity, status, tags, condition_count
            FROM atr_rules WHERE bundle_id=$1::uuid ORDER BY rule_id LIMIT $2
            """,
            bundle_id,
            limit,
        )
        records = []
        for row in rows:
            record = dict(row)
            record["tags"] = _object(record["tags"])
            records.append(record)
        return records

    async def create_atr_exemption(
        self,
        tenant_id: str,
        finding_id: str,
        *,
        created_by: str,
        expires_at: datetime,
    ) -> dict[str, Any] | None:
        finding = await self.pool.fetchrow(
            """
            SELECT rule_id, boundary, content_fingerprint, bundle_checksum, policy_version
            FROM atr_findings WHERE tenant_id=$1 AND finding_id=$2::uuid
            """,
            tenant_id,
            finding_id,
        )
        if finding is None or not finding["content_fingerprint"]:
            return None
        row = await self.pool.fetchrow(
            """
            INSERT INTO atr_exemptions(
                exemption_id, tenant_id, finding_id, rule_id, boundary,
                content_fingerprint, bundle_checksum, policy_version,
                remaining_uses, expires_at, created_by
            ) VALUES($1,$2,$3::uuid,$4,$5,$6,$7,$8,1,$9,$10)
            RETURNING *
            """,
            uuid4(),
            tenant_id,
            finding_id,
            finding["rule_id"],
            finding["boundary"],
            finding["content_fingerprint"],
            finding["bundle_checksum"],
            finding["policy_version"],
            expires_at,
            created_by,
        )
        result = _record(row)
        return result

    async def consume_atr_exemption(
        self,
        tenant_id: str,
        *,
        rule_id: str,
        boundary: str,
        content_fingerprint: str,
        bundle_checksum: str | None,
        policy_version: int,
    ) -> bool:
        async with self.pool.acquire() as connection, connection.transaction():
            row = await connection.fetchrow(
                """
                SELECT exemption_id FROM atr_exemptions
                WHERE tenant_id=$1 AND rule_id=$2 AND boundary=$3
                  AND content_fingerprint=$4 AND remaining_uses > 0
                  AND bundle_checksum IS NOT DISTINCT FROM $5
                  AND policy_version IS NOT DISTINCT FROM $6
                  AND expires_at > now()
                ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED
                """,
                tenant_id,
                rule_id,
                boundary,
                content_fingerprint,
                bundle_checksum,
                policy_version,
            )
            if row is None:
                return False
            await connection.execute(
                """
                UPDATE atr_exemptions SET remaining_uses=remaining_uses-1
                WHERE exemption_id=$1
                """,
                row["exemption_id"],
            )
            return True
